package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

type AWGConfig struct {
	PrivateKey string
	PublicKey  string
	Addresses  []string
	DNS        []string
	MTU        int
	AllowedIPs []string
	Params     map[string]string
}

type VerifyResult struct {
	Endpoint     string  `json:"endpoint"`
	LatencyMS    float64 `json:"latency_ms"`
	LossPercent  float64 `json:"loss_percent"`
	SuccessCount int     `json:"success_count"`
	Retries      int     `json:"retries"`
	Error        string  `json:"error,omitempty"`
}

func main() {
	configPath := flag.String("config", "config.conf", "AmneziaWG config path")
	endpointsArg := flag.String("endpoints", "", "comma-separated endpoints to verify")
	retries := flag.Int("retries", 3, "test retries per endpoint")
	timeout := flag.Duration("timeout", 3*time.Second, "timeout per HTTP test")
	testURL := flag.String("url", "http://www.gstatic.com/generate_204", "HTTP test URL")
	flag.Parse()

	if *endpointsArg == "" {
		writeError("missing endpoints")
		os.Exit(2)
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		writeError(err.Error())
		os.Exit(2)
	}

	endpoints := splitCSV(*endpointsArg)
	results := make([]VerifyResult, 0, len(endpoints))
	for _, endpoint := range endpoints {
		results = append(results, verifyEndpoint(cfg, endpoint, *retries, *timeout, *testURL))
	}

	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		writeError(err.Error())
		os.Exit(1)
	}
}

func writeError(message string) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"error": message})
}

func loadConfig(path string) (AWGConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return AWGConfig{}, err
	}
	defer file.Close()

	sections := map[string]map[string]string{}
	current := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if _, ok := sections[current]; !ok {
				sections[current] = map[string]string{}
			}
			continue
		}
		if current == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		sections[current][strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return AWGConfig{}, err
	}

	iface := sections["interface"]
	peer := sections["peer"]
	if iface == nil || peer == nil {
		return AWGConfig{}, fmt.Errorf("config must contain Interface and Peer sections")
	}

	mtu := 1420
	if value := iface["mtu"]; value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			mtu = parsed
		}
	}

	cfg := AWGConfig{
		PrivateKey: iface["privatekey"],
		PublicKey:  peer["publickey"],
		Addresses:  splitCSV(iface["address"]),
		DNS:        splitCSV(iface["dns"]),
		MTU:        mtu,
		AllowedIPs: splitCSV(peer["allowedips"]),
		Params:     map[string]string{},
	}
	if cfg.PrivateKey == "" {
		return AWGConfig{}, fmt.Errorf("missing Interface PrivateKey")
	}
	if cfg.PublicKey == "" {
		return AWGConfig{}, fmt.Errorf("missing Peer PublicKey")
	}
	if len(cfg.Addresses) == 0 {
		cfg.Addresses = []string{"172.16.0.2/32"}
	}
	if len(cfg.DNS) == 0 {
		cfg.DNS = []string{"1.1.1.1"}
	}
	if len(cfg.AllowedIPs) == 0 {
		cfg.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
	}

	for _, key := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"} {
		if value := iface[key]; value != "" {
			cfg.Params[key] = value
		}
	}

	return cfg, nil
}

func verifyEndpoint(cfg AWGConfig, endpoint string, retries int, timeout time.Duration, testURL string) VerifyResult {
	result := VerifyResult{Endpoint: endpoint, Retries: retries}
	if retries <= 0 {
		result.Error = "retries must be positive"
		return result
	}

	localAddrs, err := parseAddrList(cfg.Addresses)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	dnsAddrs, err := parseAddrList(cfg.DNS)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	tdev, tnet, err := netstack.CreateNetTUN(localAddrs, dnsAddrs, cfg.MTU)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()

	uapi, err := buildUAPI(cfg, endpoint)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if err := dev.IpcSet(uapi); err != nil {
		result.Error = err.Error()
		return result
	}
	if err := dev.Up(); err != nil {
		result.Error = err.Error()
		return result
	}

	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
	}

	var total time.Duration
	for i := 0; i < retries; i++ {
		start := time.Now()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodHead, testURL, nil)
		if err != nil {
			result.Error = err.Error()
			break
		}
		resp, err := client.Do(req)
		if err == nil && resp != nil {
			if resp.Body != nil {
				resp.Body.Close()
			}
			if resp.StatusCode == http.StatusNoContent {
				result.SuccessCount++
				total += time.Since(start)
			}
		}
	}

	result.LossPercent = float64(retries-result.SuccessCount) / float64(retries) * 100
	if result.SuccessCount > 0 {
		result.LatencyMS = float64(total.Microseconds()) / 1000.0 / float64(result.SuccessCount)
		result.Error = ""
	} else if result.Error == "" {
		result.Error = "all attempts failed"
	}

	return result
}

func buildUAPI(cfg AWGConfig, endpoint string) (string, error) {
	privateKey, err := base64KeyToHex(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}
	publicKey, err := base64KeyToHex(cfg.PublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid public key: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privateKey)
	for _, key := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"} {
		if value := cfg.Params[key]; value != "" {
			fmt.Fprintf(&b, "%s=%s\n", key, value)
		}
	}
	fmt.Fprintf(&b, "public_key=%s\n", publicKey)
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	fmt.Fprintf(&b, "persistent_keepalive_interval=5\n")
	fmt.Fprintf(&b, "replace_allowed_ips=true\n")
	for _, allowed := range cfg.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", allowed)
	}
	b.WriteByte('\n')

	return b.String(), nil
}

func base64KeyToHex(value string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("expected 32 bytes, got %d", len(decoded))
	}
	return hex.EncodeToString(decoded), nil
}

func parseAddrList(values []string) ([]netip.Addr, error) {
	addrs := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(value); err == nil {
			addrs = append(addrs, prefix.Addr())
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", value, err)
		}
		addrs = append(addrs, addr)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no valid addresses")
	}
	return addrs, nil
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
