#!/usr/bin/env python3
"""
Warp Endpoint Scanner with Advanced Features
- Real-time logging with scrollback buffer
- Dynamic range expansion
- Configurable concurrency
- Auto-save working endpoints
- Latency filtering
"""

import socket
import random
import time
import csv
import sys
import os
import json
import subprocess
import tempfile
import shutil
import urllib.error
import urllib.request
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Set
from enum import Enum
from datetime import datetime
from collections import deque
import threading

try:
    from rich.console import Console, Group
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm, IntPrompt
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.live import Live
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Installing rich for better UI...")
    os.system(f"{sys.executable} -m pip install rich")
    print("Please restart the script.")
    sys.exit(0)

console = Console()

@dataclass
class ScanResult:
    endpoint: str
    latency: float
    timestamp: float

@dataclass
class WarpConfig:
    private_key: str
    public_key: str
    addresses: List[str]
    dns: List[str]
    mtu: int
    reserved: List[int]

@dataclass
class VerificationResult:
    endpoint: str
    latency: float
    loss: float
    success_count: int
    retries: int

class ScanMode(Enum):
    QUICK = 100
    NORMAL = 1000
    DEEP = 5000
    CUSTOM = 0

class IPVersion(Enum):
    IPV4_ONLY = "IPv4"
    IPV6_ONLY = "IPv6"
    BOTH = "Both"

class RealtimeLogger:
    """Maintains a rolling log of last N entries"""
    def __init__(self, max_entries=50):
        self.max_entries = max_entries
        self.entries = deque(maxlen=max_entries)
        self.lock = threading.Lock()
        self.last_update = time.time()
        self.update_interval = 0.5  # Update every 0.5 seconds
    
    def add(self, endpoint: str, status: str, latency: float = None):
        with self.lock:
            timestamp = datetime.now().strftime("%H:%M:%S")
            if status == "WORKING":
                entry = f"[{timestamp}] ✅ {endpoint} - {latency:.1f}ms"
            else:
                entry = f"[{timestamp}] ❌ {endpoint}"
            self.entries.append(entry)
            self.last_update = time.time()

    def clear(self):
        with self.lock:
            self.entries.clear()
            self.last_update = time.time()
    
    def display(self):
        with self.lock:
            if not self.entries:
                return "[dim]No scans yet...[/dim]"
            return "\n".join(list(self.entries)[-self.max_entries:])
    
    def should_update(self):
        return time.time() - self.last_update >= self.update_interval

class WarpConfigParser:
    """Parses the user's local WireGuard/AmneziaWG config without logging secrets."""

    @staticmethod
    def load(path: str) -> WarpConfig:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Config file not found: {path}")

        sections = {}
        current_section = None

        with open(path, 'r', encoding='utf-8-sig') as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith(('#', ';')):
                    continue
                if line.startswith('[') and line.endswith(']'):
                    current_section = line[1:-1].strip().lower()
                    sections.setdefault(current_section, {})
                    continue
                if '=' in line and current_section:
                    key, value = line.split('=', 1)
                    sections[current_section][key.strip().lower()] = value.strip()

        interface = sections.get('interface', {})
        peer = sections.get('peer', {})

        private_key = interface.get('privatekey')
        public_key = peer.get('publickey')
        if not private_key:
            raise ValueError("Missing Interface PrivateKey in config.conf")
        if not public_key:
            raise ValueError("Missing Peer PublicKey in config.conf")

        addresses = WarpConfigParser._split_csv(interface.get('address', '172.16.0.2/32'))
        dns = WarpConfigParser._split_csv(interface.get('dns', '1.1.1.1'))
        mtu = WarpConfigParser._parse_int(interface.get('mtu'), default=1280)
        reserved = WarpConfigParser._parse_reserved(interface)

        return WarpConfig(
            private_key=private_key,
            public_key=public_key,
            addresses=addresses,
            dns=dns,
            mtu=mtu,
            reserved=reserved
        )

    @staticmethod
    def _split_csv(value: str) -> List[str]:
        return [part.strip() for part in value.split(',') if part.strip()]

    @staticmethod
    def _parse_int(value: str, default: int) -> int:
        try:
            return int(value) if value else default
        except ValueError:
            return default

    @staticmethod
    def _parse_reserved(interface: dict) -> List[int]:
        value = interface.get('reserved') or interface.get('clientid') or interface.get('client_id')
        if not value:
            return []

        value = value.strip().strip('[]')
        if ',' in value:
            reserved = []
            for part in value.split(','):
                part = part.strip()
                if part:
                    reserved.append(int(part))
            return reserved

        try:
            import base64
            return list(base64.b64decode(value))
        except Exception:
            return []

class XrayWarpVerifier:
    """Verifies endpoints through Xray userspace WireGuard, without installing a tunnel."""

    TEST_URL = "http://www.gstatic.com/generate_204"

    def __init__(self, config_path="config.conf", xray_path=None, retries=3, timeout=3.0):
        self.config_path = config_path
        self.xray_path = xray_path or self.find_xray()
        self.retries = retries
        self.timeout = timeout
        self.base_port = 18080

    @staticmethod
    def find_xray() -> str:
        candidates = [
            os.path.join("core", "xray.exe"),
            os.path.join("core", "xray"),
            "xray.exe",
            "xray",
            os.path.join("BPB-Warp-Scanner-main", "core", "xray.exe"),
            os.path.join("BPB-Warp-Scanner-main", "core", "xray"),
        ]
        for candidate in candidates:
            if os.path.exists(candidate):
                return candidate
        path_candidate = shutil.which("xray.exe") or shutil.which("xray")
        if path_candidate:
            return path_candidate
        return ""

    def available(self) -> Tuple[bool, str]:
        if not os.path.exists(self.config_path):
            return False, f"{self.config_path} was not found"
        if not self.xray_path or not os.path.exists(self.xray_path):
            return False, "Xray core was not found. Put xray.exe in .\\core\\xray.exe"
        return True, ""

    def verify(self, endpoints: List[str], logger: RealtimeLogger = None) -> List[VerificationResult]:
        if not endpoints:
            return []

        warp_config = WarpConfigParser.load(self.config_path)
        endpoints = list(dict.fromkeys(endpoints))

        with tempfile.TemporaryDirectory(prefix="warp_verify_") as temp_dir:
            config_path = os.path.join(temp_dir, "xray_config.json")
            self._write_xray_config(config_path, endpoints, warp_config, temp_dir)
            proc = self._start_xray(config_path)

            try:
                time.sleep(1.2)
                if proc.poll() is not None:
                    raise RuntimeError("Xray exited before verification started")
                results = []
                with ThreadPoolExecutor(max_workers=min(20, len(endpoints))) as executor:
                    futures = {
                        executor.submit(self._test_proxy, endpoint, self.base_port + i): endpoint
                        for i, endpoint in enumerate(endpoints)
                    }
                    for future in futures:
                        result = future.result()
                        if result.success_count > 0:
                            results.append(result)
                            if logger:
                                logger.add(result.endpoint, "WORKING", result.latency)
                        elif logger:
                            logger.add(futures[future], "FAILED")
                return sorted(results, key=lambda r: (r.loss, r.latency))
            finally:
                self._stop_xray(proc)

    def _write_xray_config(self, path: str, endpoints: List[str], warp_config: WarpConfig, temp_dir: str):
        dns = warp_config.dns or ["1.1.1.1"]
        config = {
            "log": {
                "access": os.path.join(temp_dir, "access.log"),
                "error": os.path.join(temp_dir, "error.log"),
                "loglevel": "warning"
            },
            "dns": {
                "servers": dns,
                "queryStrategy": "UseIP"
            },
            "inbounds": [],
            "outbounds": [
                {
                    "protocol": "freedom",
                    "settings": {},
                    "tag": "direct"
                }
            ],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": []
            }
        }

        for i, endpoint in enumerate(endpoints):
            inbound_tag = f"http-in-{i + 1}"
            outbound_tag = f"warp-out-{i + 1}"

            config["inbounds"].append({
                "listen": "127.0.0.1",
                "port": self.base_port + i,
                "protocol": "http",
                "tag": inbound_tag
            })

            settings = {
                "address": warp_config.addresses,
                "mtu": warp_config.mtu,
                "noKernelTun": True,
                "secretKey": warp_config.private_key,
                "peers": [
                    {
                        "endpoint": endpoint,
                        "keepAlive": 5,
                        "publicKey": warp_config.public_key
                    }
                ]
            }
            if warp_config.reserved:
                settings["reserved"] = warp_config.reserved

            config["outbounds"].append({
                "protocol": "wireguard",
                "settings": settings,
                "tag": outbound_tag
            })

            config["routing"]["rules"].append({
                "type": "field",
                "inboundTag": [inbound_tag],
                "outboundTag": outbound_tag
            })

        with open(path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)

    def _start_xray(self, config_path: str):
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        return subprocess.Popen(
            [self.xray_path, "-c", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags
        )

    def _stop_xray(self, proc):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)

    def _test_proxy(self, endpoint: str, port: int) -> VerificationResult:
        latencies = []
        proxy = urllib.request.ProxyHandler({
            "http": f"http://127.0.0.1:{port}",
            "https": f"http://127.0.0.1:{port}",
        })
        opener = urllib.request.build_opener(proxy)

        for _ in range(self.retries):
            start = time.time()
            try:
                req = urllib.request.Request(self.TEST_URL, method="HEAD")
                with opener.open(req, timeout=self.timeout) as response:
                    if response.status == 204:
                        latencies.append((time.time() - start) * 1000)
            except (urllib.error.URLError, TimeoutError, OSError):
                pass

        success_count = len(latencies)
        loss = ((self.retries - success_count) / self.retries) * 100
        avg_latency = sum(latencies) / success_count if success_count else 0.0

        return VerificationResult(
            endpoint=endpoint,
            latency=avg_latency,
            loss=loss,
            success_count=success_count,
            retries=self.retries
        )

class AmneziaWGVerifier:
    """Verifies endpoints with amneziawg-go netstack, without creating a Windows tunnel."""

    def __init__(self, config_path="config.conf", helper_path=None, retries=3, timeout=3.0):
        self.config_path = config_path
        self.helper_path = helper_path or self.find_helper()
        self.retries = retries
        self.timeout = timeout

    @staticmethod
    def find_helper() -> str:
        candidates = [
            "awg_verifier.exe",
            os.path.join("awg_verifier", "awg_verifier.exe"),
        ]
        for candidate in candidates:
            if os.path.exists(candidate):
                return candidate
        path_candidate = shutil.which("awg_verifier.exe")
        return path_candidate or ""

    def available(self) -> Tuple[bool, str]:
        if not os.path.exists(self.config_path):
            return False, f"{self.config_path} was not found"
        if not self.helper_path or not os.path.exists(self.helper_path):
            return False, "awg_verifier.exe was not found"
        return True, ""

    def verify(self, endpoints: List[str], logger: RealtimeLogger = None, realtime_callback=None) -> List[VerificationResult]:
        if not endpoints:
            return []

        endpoints = list(dict.fromkeys(endpoints))
        results = []
        
        # Test each endpoint individually (like test_awg_verifier.py does)
        total = len(endpoints)
        
        for i, endpoint in enumerate(endpoints):
            if realtime_callback:
                realtime_callback("progress", i + 1, total, endpoint, None)
            
            # Build command for single endpoint (matches test_awg_verifier.py)
            cmd = [
                self.helper_path,
                "-config", self.config_path,
                "-endpoints", endpoint,  # Single endpoint, not comma-separated list
                "-retries", str(self.retries),
                "-timeout", f"{self.timeout}s",
            ]
            
            try:
                completed = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=max(15, int(self.timeout * self.retries + 8)),
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except subprocess.TimeoutExpired:
                if logger:
                    logger.add(endpoint, "FAILED")
                if realtime_callback:
                    realtime_callback("failed", None, None, endpoint, None)
                continue
            
            output = completed.stdout.strip()
            
            # Parse response (same as test_awg_verifier.py)
            try:
                payload = json.loads(output) if output else {}
            except json.JSONDecodeError:
                if logger:
                    logger.add(endpoint, "FAILED")
                if realtime_callback:
                    realtime_callback("failed", None, None, endpoint, None)
                continue
            
            # Handle error response
            if isinstance(payload, dict):
                if payload.get("error"):
                    if logger:
                        logger.add(endpoint, "FAILED")
                    if realtime_callback:
                        realtime_callback("failed", None, None, endpoint, None)
                continue
            
            # Handle list response (success case)
            if isinstance(payload, list) and len(payload) > 0:
                item = payload[0]
                success_count = int(item.get("success_count", 0))
                
                if success_count > 0:
                    result = VerificationResult(
                        endpoint=item.get("endpoint", endpoint),
                        latency=float(item.get("latency_ms", 0.0)),
                        loss=float(item.get("loss_percent", 100.0)),
                        success_count=success_count,
                        retries=int(item.get("retries", self.retries))
                    )
                    results.append(result)
                    if logger:
                        logger.add(endpoint, "WORKING", result.latency)
                    if realtime_callback:
                        realtime_callback("working", None, None, endpoint, result.latency)
                else:
                    if logger:
                        logger.add(endpoint, "FAILED")
                    if realtime_callback:
                        realtime_callback("failed", None, None, endpoint, None)
            else:
                if logger:
                    logger.add(endpoint, "FAILED")
                if realtime_callback:
                    realtime_callback("failed", None, None, endpoint, None)
        
        return sorted(results, key=lambda r: (r.loss, r.latency))

class WarpTester:
    # Common Warp ports
    PORTS = [
        500, 854, 859, 864, 878, 880, 890, 891, 894, 903,
        908, 928, 934, 939, 942, 943, 945, 946, 955, 968,
        987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387,
        1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177,
        4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559,
        8319, 8742, 8854, 8886
    ]
    
    # IPv4 prefixes used by Cloudflare Warp
    IPV4_PREFIXES = [
        "188.114.96.", "188.114.97.", "188.114.98.", "188.114.99.",
        "162.159.192.", "162.159.193.", "162.159.195.", "8.34.146.",
        "8.39.214.", "8.39.204.", "8.6.112.", "8.35.211.", "8.39.125.",
        "8.47.69."
    ]
    
    # IPv6 prefixes
    IPV6_PREFIXES = [
        "2606:4700:d0::", "2606:4700:d1::"
    ]
    
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.working_endpoints_file = None
        self.scanned_endpoints: Set[str] = set()
        self.min_latency = 0
        self.max_latency = 1000
        
    def set_latency_range(self, min_lat: int, max_lat: int):
        """Set acceptable latency range"""
        self.min_latency = min_lat
        self.max_latency = max_lat
    
    def init_output_file(self):
        """Initialize the output file for working endpoints"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.working_endpoints_file = f"endpoints_{timestamp}.txt"
        # Clear/create file
        with open(self.working_endpoints_file, 'w') as f:
            f.write(f"# Warp Working Endpoints - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Latency range: {self.min_latency}-{self.max_latency}ms\n")
            f.write("# Endpoint | Latency(ms)\n")
            f.write("#" + "="*50 + "\n")
        return self.working_endpoints_file
    
    def save_working_endpoint(self, endpoint: str, latency: float):
        """Save a working endpoint to the file immediately"""
        if self.working_endpoints_file:
            with open(self.working_endpoints_file, 'a') as f:
                f.write(f"{endpoint} | {latency:.1f}ms\n")
    
    def expand_range(self, working_endpoint: str) -> List[str]:
        """Generate nearby endpoints based on a working one"""
        expanded = []
        
        try:
            if '[' in working_endpoint:  # IPv6
                ip_part, port_str = working_endpoint.split(']:')
                ip = ip_part[1:]
                port = int(port_str)
                
                if ':' in ip:
                    parts = ip.split(':')
                    if len(parts) >= 4:
                        base_prefix = ':'.join(parts[:-2])
                        last_part = int(parts[-2], 16)
                        second_last = int(parts[-3], 16)
                        
                        for delta in [-2, -1, 1, 2]:
                            new_last = (last_part + delta) % 65536
                            new_second = (second_last + delta // 2) % 65536
                            new_ip = f"{base_prefix}:{new_second:x}:{new_last:x}:{parts[-1]}"
                            new_endpoint = f"[{new_ip}]:{port}"
                            if new_endpoint not in self.scanned_endpoints:
                                expanded.append(new_endpoint)
                                
            else:  # IPv4
                ip, port_str = working_endpoint.split(':')
                port = int(port_str)
                parts = ip.split('.')
                
                if len(parts) == 4:
                    base_ip = '.'.join(parts[:3])
                    current_last = int(parts[3])
                    
                    # Add nearby IPs
                    for delta in [-3, -2, -1, 1, 2, 3]:
                        new_last = current_last + delta
                        if 0 <= new_last <= 255:
                            new_ip = f"{base_ip}.{new_last}"
                            new_endpoint = f"{new_ip}:{port}"
                            if new_endpoint not in self.scanned_endpoints:
                                expanded.append(new_endpoint)
                    
                    # Try same IP with nearby ports
                    port_index = self.PORTS.index(port) if port in self.PORTS else -1
                    if port_index != -1:
                        for delta in [-2, -1, 1, 2]:
                            new_port_index = port_index + delta
                            if 0 <= new_port_index < len(self.PORTS):
                                new_port = self.PORTS[new_port_index]
                                new_endpoint = f"{ip}:{new_port}"
                                if new_endpoint not in self.scanned_endpoints:
                                    expanded.append(new_endpoint)
        except Exception:
            pass
            
        return expanded[:10]
    
    def generate_endpoints_fast(self, count: int, ip_version: IPVersion, seed_endpoints: List[str] = None) -> List[str]:
        """Generate endpoints with optional seed endpoints from expansions"""
        endpoints = set()
        
        # Add seed endpoints first if provided
        if seed_endpoints:
            for ep in seed_endpoints:
                if ep not in self.scanned_endpoints:
                    endpoints.add(ep)
                    self.scanned_endpoints.add(ep)
        
        remaining = count - len(endpoints)
        if remaining <= 0:
            return list(endpoints)[:count]
        
        if ip_version == IPVersion.IPV4_ONLY:
            prefixes = self.IPV4_PREFIXES
            ports = self.PORTS
            
            while len(endpoints) < count:
                batch_size = min(count - len(endpoints), 1000)
                for _ in range(batch_size):
                    prefix = random.choice(prefixes)
                    last_octet = random.randint(0, 255)
                    port = random.choice(ports)
                    endpoint = f"{prefix}{last_octet}:{port}"
                    if endpoint not in self.scanned_endpoints:
                        endpoints.add(endpoint)
                        self.scanned_endpoints.add(endpoint)
                    
        elif ip_version == IPVersion.IPV6_ONLY:
            prefixes = self.IPV6_PREFIXES
            ports = self.PORTS
            
            while len(endpoints) < count:
                batch_size = min(count - len(endpoints), 1000)
                for _ in range(batch_size):
                    prefix = random.choice(prefixes)
                    suffix_parts = [random.randint(0, 65535) for _ in range(4)]
                    ip = f"[{prefix}{suffix_parts[0]:x}:{suffix_parts[1]:x}:{suffix_parts[2]:x}:{suffix_parts[3]:x}]"
                    port = random.choice(ports)
                    endpoint = f"{ip}:{port}"
                    if endpoint not in self.scanned_endpoints:
                        endpoints.add(endpoint)
                        self.scanned_endpoints.add(endpoint)
                    
        else:  # BOTH
            ipv4_needed = remaining // 2
            ipv6_needed = remaining - ipv4_needed
            
            # Generate IPv4
            while len([e for e in endpoints if '[' not in e]) < ipv4_needed:
                prefix = random.choice(self.IPV4_PREFIXES)
                last_octet = random.randint(0, 255)
                port = random.choice(self.PORTS)
                endpoint = f"{prefix}{last_octet}:{port}"
                if endpoint not in self.scanned_endpoints:
                    endpoints.add(endpoint)
                    self.scanned_endpoints.add(endpoint)
            
            # Generate IPv6
            while len([e for e in endpoints if '[' in e]) < ipv6_needed:
                prefix = random.choice(self.IPV6_PREFIXES)
                suffix_parts = [random.randint(0, 65535) for _ in range(4)]
                ip = f"[{prefix}{suffix_parts[0]:x}:{suffix_parts[1]:x}:{suffix_parts[2]:x}:{suffix_parts[3]:x}]"
                port = random.choice(self.PORTS)
                endpoint = f"{ip}:{port}"
                if endpoint not in self.scanned_endpoints:
                    endpoints.add(endpoint)
                    self.scanned_endpoints.add(endpoint)
        
        return list(endpoints)[:count]
    
    def test_endpoint_fast(self, endpoint: str) -> Tuple[bool, float]:
        """Fast endpoint testing"""
        try:
            if endpoint.startswith('['):
                ip_part, port_str = endpoint.split(']:')
                ip = ip_part[1:]
                port = int(port_str)
                family = socket.AF_INET6
            else:
                ip, port_str = endpoint.split(':')
                port = int(port_str)
                family = socket.AF_INET
            
            # Try UDP first
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            test_packet = bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] + 
                               [random.randint(0, 255) for _ in range(32)])
            
            start_time = time.time()
            sock.sendto(test_packet, (ip, port))
            
            try:
                data, _ = sock.recvfrom(1024)
                if len(data) > 0:
                    latency = (time.time() - start_time) * 1000
                    sock.close()
                    # Check latency range
                    if self.min_latency <= latency <= self.max_latency:
                        return True, latency
                    else:
                        return False, latency
            except socket.timeout:
                pass
            finally:
                sock.close()
            
            # Try TCP fallback
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            start_time = time.time()
            sock.connect((ip, port))
            latency = (time.time() - start_time) * 1000
            sock.close()
            # Check latency range
            if self.min_latency <= latency <= self.max_latency:
                return True, latency
            else:
                return False, latency
            
        except (socket.timeout, socket.error, ConnectionRefusedError, OSError):
            return False, 0.0
    
    def save_results_csv(self, results: List[ScanResult], filename: str):
        """Save scan results to CSV"""
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Endpoint', 'Latency (ms)', 'Status'])
            for r in results:
                writer.writerow([r.endpoint, f"{r.latency:.1f}", "Working"])

class WarpTUI:
    def __init__(self):
        self.tester = WarpTester()
        self.scan_mode = ScanMode.NORMAL
        self.ip_version = IPVersion.IPV4_ONLY
        self.custom_count = 100
        self.workers = 100
        self.results: List[ScanResult] = []
        self.logger = RealtimeLogger(max_entries=50)
        self.expansion_enabled = True
        self.total_scanned = 0
        self.working_found = 0
        self.min_latency = 0
        self.max_latency = 500
        self.verification_enabled = True
        self.verification_config_path = "config.conf"
        self.verification_top_n = 20
        self.verification_retries = 3
        self.verified_results: List[VerificationResult] = []
        
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self):
        header = Panel(
            "[bold cyan]Warp Endpoint Scanner v3.1[/bold cyan]\n"
            "[dim]Advanced scanner with real-time logging, auto-expansion & latency filtering[/dim]",
            box=box.DOUBLE_EDGE,
            style="bold cyan",
            padding=(1, 2)
        )
        console.print(header)
    
    def show_main_menu(self):
        while True:
            self.clear_screen()
            self.print_header()
            
            menu_table = Table(title="Main Menu", box=box.ROUNDED, title_style="bold yellow")
            menu_table.add_column("Option", style="bold cyan", width=8)
            menu_table.add_column("Description", style="white")
            menu_table.add_column("Current", style="green")
            
            current_mode = f"{self.scan_mode.name} ({self.get_mode_count()} endpoints)"
            latency_range = f"{self.min_latency}-{self.max_latency}ms"
            verify_status = "Disabled"
            if self.verification_enabled:
                verify_status = f"Top {self.verification_top_n}, {self.verification_config_path}"
            menu_table.add_row("1", "Scan Mode", current_mode)
            menu_table.add_row("2", "IP Version", self.ip_version.value)
            menu_table.add_row("3", "Concurrent Workers", str(self.workers))
            menu_table.add_row("4", "Latency Range", latency_range)
            menu_table.add_row("5", "Range Expansion", "✅ Enabled" if self.expansion_enabled else "❌ Disabled")
            menu_table.add_row("6", "Start Scan", "▶️")
            menu_table.add_row("7", "View Results", "📊")
            menu_table.add_row("8", "Export Results", "📁")
            menu_table.add_row("9", "About", "ℹ️")
            menu_table.add_row("0", "Exit", "🚪")
            
            menu_table.add_row("10", "WARP Verification", verify_status)
            menu_table.add_row("11", "Test from endpoints.txt", "📝")

            console.print(menu_table)
            console.print("\n[dim]Use number keys to navigate[/dim]")
            
            choice = Prompt.ask("\n[bold yellow]Your choice[/bold yellow]", 
                               choices=["0","1","2","3","4","5","6","7","8","9","10","11"])
            
            if choice == "0":
                if Confirm.ask("\n[red]Exit?[/red]"):
                    console.print("\n[green]Goodbye![/green]")
                    sys.exit(0)
            elif choice == "1":
                self.configure_scan_mode()
            elif choice == "2":
                self.configure_ip_version()
            elif choice == "3":
                self.configure_workers()
            elif choice == "4":
                self.configure_latency_range()
            elif choice == "5":
                self.configure_expansion()
            elif choice == "6":
                self.start_scan()
            elif choice == "7":
                self.show_results()
            elif choice == "8":
                self.export_results()
            elif choice == "9":
                self.show_about()
            elif choice == "10":
                self.configure_verification()
            elif choice == "11":
                self.test_from_file()
    
    def get_mode_count(self) -> int:
        if self.scan_mode == ScanMode.QUICK:
            return 100
        elif self.scan_mode == ScanMode.NORMAL:
            return 1000
        elif self.scan_mode == ScanMode.DEEP:
            return 5000
        else:
            return self.custom_count

    def configure_verification(self):
        self.clear_screen()
        self.print_header()

        awg_verifier = AmneziaWGVerifier(config_path=self.verification_config_path)
        awg_available, awg_reason = awg_verifier.available()
        xray_verifier = XrayWarpVerifier(config_path=self.verification_config_path)
        xray_available, xray_reason = xray_verifier.available()
        if awg_available:
            status = "Ready: AmneziaWG netstack"
        elif xray_available:
            status = f"Fallback: Xray noKernelTun ({awg_reason})"
        else:
            status = f"Not ready: {awg_reason}; fallback: {xray_reason}"

        verify_table = Table(title="WARP Verification", box=box.ROUNDED)
        verify_table.add_column("Option", style="bold cyan")
        verify_table.add_column("Setting", style="white")
        verify_table.add_column("Current", style="green")

        verify_table.add_row("1", "Enabled", "Yes" if self.verification_enabled else "No")
        verify_table.add_row("2", "Config File", self.verification_config_path)
        verify_table.add_row("3", "Top Endpoints To Verify", str(self.verification_top_n))
        verify_table.add_row("4", "Retries Per Endpoint", str(self.verification_retries))
        verify_table.add_row("5", "Status", status)
        verify_table.add_row("0", "Back", "")
        console.print(verify_table)
        console.print("\n[dim]Preferred backend: AmneziaWG netstack. Fallback: Xray noKernelTun. Neither installs a tunnel.[/dim]")

        choice = Prompt.ask(
            "\n[bold yellow]Select setting[/bold yellow]",
            choices=["0", "1", "2", "3", "4"]
        )

        if choice == "1":
            self.verification_enabled = not self.verification_enabled
        elif choice == "2":
            self.verification_config_path = Prompt.ask(
                "[cyan]Config file path[/cyan]",
                default=self.verification_config_path
            )
        elif choice == "3":
            self.verification_top_n = IntPrompt.ask(
                "[cyan]How many top endpoints to verify[/cyan]",
                default=str(self.verification_top_n)
            )
            self.verification_top_n = max(1, min(self.verification_top_n, 500))
        elif choice == "4":
            self.verification_retries = IntPrompt.ask(
                "[cyan]Retries per endpoint[/cyan]",
                default=str(self.verification_retries)
            )
            self.verification_retries = max(1, min(self.verification_retries, 10))

        if choice != "0":
            console.print("\n[green]Verification settings updated[/green]")
            time.sleep(1)
    
    def configure_scan_mode(self):
        self.clear_screen()
        self.print_header()
        
        mode_table = Table(title="Select Scan Mode", box=box.ROUNDED)
        mode_table.add_column("Option", style="bold cyan")
        mode_table.add_column("Mode", style="white")
        mode_table.add_column("Endpoints", style="green")
        mode_table.add_column("Estimated Time", style="yellow")
        
        mode_table.add_row("1", "Quick Scan", "100", "~5-10 seconds")
        mode_table.add_row("2", "Normal Scan", "1000", "~30-60 seconds")
        mode_table.add_row("3", "Deep Scan", "5000", "~2-5 minutes")
        mode_table.add_row("4", "Custom Scan", "User defined", "Variable")
        
        console.print(mode_table)
        
        choice = Prompt.ask("\n[bold yellow]Select scan mode[/bold yellow]", choices=["1","2","3","4"])
        
        if choice == "1":
            self.scan_mode = ScanMode.QUICK
        elif choice == "2":
            self.scan_mode = ScanMode.NORMAL
        elif choice == "3":
            self.scan_mode = ScanMode.DEEP
        elif choice == "4":
            while True:
                try:
                    custom = IntPrompt.ask("[cyan]Enter number of endpoints[/cyan]", default="100")
                    if 1 <= custom <= 10000:
                        self.scan_mode = ScanMode.CUSTOM
                        self.custom_count = custom
                        break
                    else:
                        console.print("[red]Please enter a number between 1 and 10000[/red]")
                except ValueError:
                    console.print("[red]Invalid input. Please enter a number.[/red]")
        
        console.print(f"\n[green]✓ Scan mode set to {self.scan_mode.name}[/green]")
        time.sleep(1)
    
    def configure_ip_version(self):
        self.clear_screen()
        self.print_header()
        
        ip_table = Table(title="Select IP Version", box=box.ROUNDED)
        ip_table.add_column("Option", style="bold cyan")
        ip_table.add_column("Version", style="white")
        ip_table.add_column("Note", style="dim")
        
        ip_table.add_row("1", "IPv4 Only", "Most reliable")
        ip_table.add_row("2", "IPv6 Only", "May be faster if available")
        ip_table.add_row("3", "Both", "More endpoints, slower scan")
        
        console.print(ip_table)
        
        choice = Prompt.ask("\n[bold yellow]Select IP version[/bold yellow]", choices=["1","2","3"])
        
        if choice == "1":
            self.ip_version = IPVersion.IPV4_ONLY
        elif choice == "2":
            self.ip_version = IPVersion.IPV6_ONLY
        elif choice == "3":
            self.ip_version = IPVersion.BOTH
        
        console.print(f"\n[green]✓ IP version set to {self.ip_version.value}[/green]")
        time.sleep(1)
    
    def configure_workers(self):
        self.clear_screen()
        self.print_header()
        
        workers_table = Table(title="Configure Concurrent Workers", box=box.ROUNDED)
        workers_table.add_column("Option", style="bold cyan")
        workers_table.add_column("Description", style="white")
        workers_table.add_column("Performance", style="green")
        
        workers_table.add_row("1", "Conservative (50 workers)", "Slower but network-friendly")
        workers_table.add_row("2", "Balanced (100 workers)", "Recommended")
        workers_table.add_row("3", "Aggressive (200 workers)", "Fast but may trigger rate limits")
        workers_table.add_row("4", "Custom", "User defined")
        
        console.print(workers_table)
        
        choice = Prompt.ask("\n[bold yellow]Select worker count[/bold yellow]", choices=["1","2","3","4"])
        
        if choice == "1":
            self.workers = 50
        elif choice == "2":
            self.workers = 100
        elif choice == "3":
            self.workers = 200
        elif choice == "4":
            while True:
                try:
                    custom = IntPrompt.ask("[cyan]Enter number of workers[/cyan]", default="100")
                    if 1 <= custom <= 500:
                        self.workers = custom
                        break
                    else:
                        console.print("[red]Please enter a number between 1 and 500[/red]")
                except ValueError:
                    console.print("[red]Invalid input. Please enter a number.[/red]")
        
        console.print(f"\n[green]✓ Workers set to {self.workers}[/green]")
        time.sleep(1)
    
    def configure_latency_range(self):
        self.clear_screen()
        self.print_header()
        
        latency_table = Table(title="Configure Latency Range", box=box.ROUNDED)
        latency_table.add_column("Option", style="bold cyan")
        latency_table.add_column("Range", style="white")
        latency_table.add_column("Use Case", style="dim")
        
        latency_table.add_row("1", "0-100ms", "Very fast (may be unstable)")
        latency_table.add_row("2", "0-200ms", "Fast (recommended)")
        latency_table.add_row("3", "0-500ms", "Normal (most stable)")
        latency_table.add_row("4", "0-1000ms", "Slow (everything)")
        latency_table.add_row("5", "Custom", "User defined")
        
        console.print(latency_table)
        console.print("\n[yellow]Note: Very low latency endpoints (<50ms) are often local proxies that may not work properly with Warp.[/yellow]")
        
        choice = Prompt.ask("\n[bold yellow]Select latency range[/bold yellow]", choices=["1","2","3","4","5"])
        
        if choice == "1":
            self.min_latency = 0
            self.max_latency = 100
        elif choice == "2":
            self.min_latency = 0
            self.max_latency = 200
        elif choice == "3":
            self.min_latency = 0
            self.max_latency = 500
        elif choice == "4":
            self.min_latency = 0
            self.max_latency = 1000
        elif choice == "5":
            while True:
                try:
                    console.print("\n[cyan]Enter minimum latency (ms):[/cyan]")
                    min_lat = IntPrompt.ask("", default="0")
                    console.print("[cyan]Enter maximum latency (ms):[/cyan]")
                    max_lat = IntPrompt.ask("", default="500")
                    if 0 <= min_lat < max_lat <= 10000:
                        self.min_latency = min_lat
                        self.max_latency = max_lat
                        break
                    else:
                        console.print("[red]Invalid range. Min must be < Max, and Max <= 10000[/red]")
                except ValueError:
                    console.print("[red]Invalid input. Please enter numbers.[/red]")
        
        self.tester.set_latency_range(self.min_latency, self.max_latency)
        console.print(f"\n[green]✓ Latency range set to {self.min_latency}-{self.max_latency}ms[/green]")
        time.sleep(1)
    
    def configure_expansion(self):
        self.expansion_enabled = not self.expansion_enabled
        status = "enabled" if self.expansion_enabled else "disabled"
        console.print(f"\n[green]✓ Range expansion {status}[/green]")
        time.sleep(1)
    
    def start_scan(self):
        self.clear_screen()
        self.print_header()
        
        # Reset state
        self.results = []
        self.total_scanned = 0
        self.working_found = 0
        self.logger.clear()
        self.tester.scanned_endpoints.clear()
        
        # Set latency range
        self.tester.set_latency_range(self.min_latency, self.max_latency)
        
        # Initialize output file
        output_file = self.tester.init_output_file()
        console.print(f"[dim]Working endpoints will be saved to: {output_file}[/dim]\n")
        
        # Get endpoint count
        endpoint_count = self.get_mode_count()
        
        # Show scan config
        config_table = Table(title="Scan Configuration", box=box.ROUNDED, title_style="bold cyan")
        config_table.add_row("Endpoints to test", str(endpoint_count))
        config_table.add_row("IP Version", self.ip_version.value)
        config_table.add_row("Concurrent Workers", str(self.workers))
        config_table.add_row("Latency Range", f"{self.min_latency}-{self.max_latency}ms")
        config_table.add_row("Range Expansion", "✅ Enabled" if self.expansion_enabled else "❌ Disabled")
        config_table.add_row("Timeout", f"{self.tester.timeout}s")
        
        console.print(config_table)
        
        if not Confirm.ask("\n[bold yellow]Start scan?[/bold yellow]"):
            return
        
        # Initial endpoint generation
        console.print("\n[cyan]🔨 Generating initial endpoints...[/cyan]")
        endpoints = self.tester.generate_endpoints_fast(endpoint_count, self.ip_version)
        console.print(f"[green]✓ Generated {len(endpoints)} initial endpoints[/green]\n")
        
        # Setup real-time display
        self.total_scanned = 0
        self.working_found = 0

        start_time = time.time()
        expansion_queue: List[str] = []
        expansion_index = 0
        logged_endpoints = set()
        results_lock = threading.Lock()
        working_temp = []

        progress = Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
            expand=True
        )
        scan_task = progress.add_task("[cyan]Scanning endpoints...", total=len(endpoints))

        def build_live_display():
            pending_expansions = max(0, len(expansion_queue) - expansion_index)
            elapsed = time.time() - start_time

            stats = Table.grid(expand=True)
            stats.add_column(style="cyan")
            stats.add_column(style="green")
            stats.add_column(style="yellow")
            stats.add_column(style="magenta")
            stats.add_row(
                f"Scanned: {self.total_scanned}",
                f"Working: {self.working_found}",
                f"Expansion queue: {pending_expansions}",
                f"Elapsed: {elapsed:.1f}s"
            )

            return Group(
                progress,
                Panel(stats, title="Live Status", border_style="cyan"),
                Panel(self.logger.display(), title="Real-time Scan Log", border_style="cyan")
            )

        def process_endpoint(endpoint):
            success, latency = self.tester.test_endpoint_fast(endpoint)

            with results_lock:
                if success:
                    result = ScanResult(endpoint=endpoint, latency=latency, timestamp=time.time())
                    working_temp.append(result)
                    self.working_found += 1

                    if endpoint not in logged_endpoints:
                        logged_endpoints.add(endpoint)
                        self.logger.add(endpoint, "WORKING", latency)
                        self.tester.save_working_endpoint(endpoint, latency)

                    if self.expansion_enabled:
                        for new_ep in self.tester.expand_range(endpoint):
                            if new_ep not in self.tester.scanned_endpoints:
                                self.tester.scanned_endpoints.add(new_ep)
                                expansion_queue.append(new_ep)
                else:
                    if endpoint not in logged_endpoints and len(logged_endpoints) < 10000:
                        logged_endpoints.add(endpoint)
                        self.logger.add(endpoint, "FAILED")

                self.total_scanned += 1
                progress.update(
                    scan_task,
                    completed=self.total_scanned,
                    total=max(self.total_scanned, len(endpoints) + len(expansion_queue))
                )

        with Live(build_live_display(), console=console, refresh_per_second=4) as live:
            with ThreadPoolExecutor(max_workers=self.workers) as executor:
                futures = {executor.submit(process_endpoint, ep): ep for ep in endpoints}
                last_display_update = 0

                while futures or expansion_index < len(expansion_queue):
                    done_futures = [future for future in futures if future.done()]
                    for future in done_futures:
                        endpoint = futures.pop(future)
                        try:
                            future.result()
                        except Exception:
                            with results_lock:
                                self.total_scanned += 1
                                if endpoint not in logged_endpoints:
                                    logged_endpoints.add(endpoint)
                                    self.logger.add(endpoint, "FAILED")
                                progress.update(
                                    scan_task,
                                    completed=self.total_scanned,
                                    total=max(self.total_scanned, len(endpoints) + len(expansion_queue))
                                )

                    if expansion_index < len(expansion_queue) and len(futures) < self.workers * 2:
                        batch_size = min(20, len(expansion_queue) - expansion_index)
                        new_endpoints = expansion_queue[expansion_index:expansion_index + batch_size]
                        expansion_index += batch_size

                        for new_ep in new_endpoints:
                            futures[executor.submit(process_endpoint, new_ep)] = new_ep

                    if time.time() - last_display_update > 0.25:
                        pending = max(0, len(expansion_queue) - expansion_index)
                        progress.update(
                            scan_task,
                            description=f"[cyan]Found {self.working_found} working | Queue: {pending}"
                        )
                        live.update(build_live_display())
                        last_display_update = time.time()

                    time.sleep(0.05)

                live.update(build_live_display())

        # Add all working endpoints to results
        self.results = working_temp
            
        scan_time = time.time() - start_time
        
        # Final display
        console.print(f"\n[bold green]✨ Scan completed in {scan_time:.1f} seconds![/bold green]")
        console.print(f"[green]Scanned: {self.total_scanned} endpoints | Working: {self.working_found}[/green]")
        
        # Display real-time log
        console.print("\n[bold cyan]📋 Last 50 scan results:[/bold cyan]")
        console.print(Panel(self.logger.display(), border_style="cyan"))
        
        # Sort results by latency
        self.results.sort(key=lambda x: x.latency)
        self.verified_results = []
        
        # Show top results
        if self.results:
            if self.verification_enabled:
                self.run_warp_verification()

            results_table = Table(title=f"Top {min(10, len(self.results))} Working Endpoints", 
                                 box=box.ROUNDED)
            results_table.add_column("#", style="dim")
            results_table.add_column("Endpoint", style="green")
            results_table.add_column("Latency", style="white")
            
            for i, r in enumerate(self.results[:10], 1):
                latency_color = "bright_green" if r.latency < 50 else "green" if r.latency < 100 else "yellow"
                results_table.add_row(str(i), r.endpoint, f"[{latency_color}]{r.latency:.1f}ms[/{latency_color}]")
            
            console.print(results_table)
            
            # Save sorted results
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.tester.save_results_csv(self.results, f"warp_results_{timestamp}.csv")
            console.print(f"\n[green]✓ Results saved to warp_results_{timestamp}.csv[/green]")
            console.print(f"[green]✓ Working endpoints saved to {output_file}[/green]")
        else:
            console.print("\n[yellow]⚠️ No working endpoints found in the specified latency range![/yellow]")
            console.print("[dim]Try increasing the latency range or disabling range expansion[/dim]")
        
        input("\n[dim]Press Enter to return to main menu...[/dim]")

    def test_from_file(self):
        """Test endpoints directly from a file without scanning first"""
        self.clear_screen()
        self.print_header()
        
        endpoints_file = Prompt.ask(
            "[cyan]Enter endpoints file path[/cyan]", 
            default="endpoints.txt"
        )
        
        if not os.path.exists(endpoints_file):
            console.print(f"\n[red]File not found: {endpoints_file}[/red]")
            time.sleep(2)
            return
        
        # Read endpoints from file
        with open(endpoints_file, 'r') as f:
            endpoints = []
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if line and not line.startswith('#') and not line.startswith(';'):
                    # Remove any extra text after endpoint
                    endpoint = line.split('|')[0].strip() if '|' in line else line
                    endpoints.append(endpoint)
        
        if not endpoints:
            console.print(f"\n[yellow]No valid endpoints found in {endpoints_file}[/yellow]")
            time.sleep(2)
            return
        
        console.print(f"\n[green]✓ Loaded {len(endpoints)} endpoints from {endpoints_file}[/green]")
        
        # Setup verification config
        verify_table = Table(title="Verification Configuration", box=box.ROUNDED, title_style="bold cyan")
        verify_table.add_row("Config File", self.verification_config_path)
        verify_table.add_row("Retries per endpoint", str(self.verification_retries))
        verify_table.add_row("Timeout", f"{self.tester.timeout}s")
        verify_table.add_row("Endpoints to test", str(len(endpoints)))
        console.print(verify_table)
        
        if not Confirm.ask("\n[bold yellow]Start verification?[/bold yellow]"):
            return
        
        # Reset state
        self.results = []
        self.logger.clear()
        self.total_scanned = 0
        self.working_found = 0
        
        # Initialize output file
        output_file = self.tester.init_output_file()
        console.print(f"\n[dim]Working endpoints will be saved to: {output_file}[/dim]")
        
        # Setup progress display
        start_time = time.time()
        
        from rich.layout import Layout
        from rich.live import Live
        
        verification_progress = Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
            expand=True
        )
        verify_task = verification_progress.add_task(
            "[cyan]Verifying endpoints...", 
            total=len(endpoints)
        )
        
        current_verified = 0
        working_verified = 0
        
        def realtime_callback(event_type, current, total, endpoint, latency):
            nonlocal current_verified, working_verified
            if event_type == "progress":
                current_verified = current
                verification_progress.update(verify_task, completed=current)
            elif event_type == "working":
                working_verified += 1
                if endpoint and latency:
                    self.results.append(ScanResult(
                        endpoint=endpoint, 
                        latency=latency, 
                        timestamp=time.time()
                    ))
                    self.tester.save_working_endpoint(endpoint, latency)
                verification_progress.update(
                    verify_task,
                    description=f"[cyan]Found {working_verified} working | {current_verified}/{len(endpoints)}"
                )
            elif event_type == "failed":
                verification_progress.update(
                    verify_task,
                    description=f"[cyan]Working: {working_verified} | {current_verified}/{len(endpoints)}"
                )
        
        def build_verify_display():
            stats = Table.grid(expand=True)
            stats.add_column(style="cyan")
            stats.add_column(style="green")
            stats.add_row(
                f"Total: {len(endpoints)}",
                f"Working: {working_verified}",
                f"Elapsed: {time.time() - start_time:.1f}s"
            )
            return Group(
                verification_progress,
                Panel(stats, title="Status", border_style="cyan"),
                Panel(self.logger.display(), title="Real-time Verification Log", border_style="cyan")
            )
        
        # Try AmneziaWG verifier first
        verifier = AmneziaWGVerifier(
            config_path=self.verification_config_path,
            retries=self.verification_retries,
            timeout=self.tester.timeout
        )
        available, reason = verifier.available()
        if not available:
            fallback = XrayWarpVerifier(
                config_path=self.verification_config_path,
                retries=self.verification_retries,
                timeout=self.tester.timeout
            )
            fallback_available, fallback_reason = fallback.available()
            if fallback_available:
                console.print(f"\n[yellow]AmneziaWG verifier unavailable: {reason}[/yellow]")
                console.print("[dim]Falling back to Xray noKernelTun verifier.[/dim]")
                verifier = fallback
            else:
                console.print(f"\n[red]No verifier available: {reason}; fallback unavailable: {fallback_reason}[/red]")
                return
        
        verifier_name = "AmneziaWG netstack" if isinstance(verifier, AmneziaWGVerifier) else "Xray noKernelTun"
        console.print(f"\n[cyan]Using {verifier_name} for verification...[/cyan]")
        
        try:
            with Live(build_verify_display(), console=console, refresh_per_second=4):
                self.verified_results = verifier.verify(
                    endpoints, 
                    self.logger,
                    realtime_callback=realtime_callback
                )
        except Exception as e:
            console.print(f"\n[red]Verification failed: {e}[/red]")
            return
        
        scan_time = time.time() - start_time
        
        console.print(f"\n[bold green]✨ Verification completed in {scan_time:.1f} seconds![/bold green]")
        console.print(f"[green]Tested: {len(endpoints)} endpoints | Working: {working_verified}[/green]")
        
        # Sort results by latency
        self.results.sort(key=lambda x: x.latency)
        
        # Show results
        if self.results:
            results_table = Table(title=f"Top {min(20, len(self.results))} Verified Working Endpoints", 
                                box=box.ROUNDED)
            results_table.add_column("#", style="dim")
            results_table.add_column("Endpoint", style="green")
            results_table.add_column("Latency", style="white")
            
            for i, r in enumerate(self.results[:20], 1):
                latency_color = "bright_green" if r.latency < 50 else "green" if r.latency < 100 else "yellow"
                results_table.add_row(str(i), r.endpoint, f"[{latency_color}]{r.latency:.1f}ms[/{latency_color}]")
            
            console.print(results_table)
            
            # Save results
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.tester.save_results_csv(self.results, f"verified_results_{timestamp}.csv")
            console.print(f"\n[green]✓ Results saved to verified_results_{timestamp}.csv[/green]")
            console.print(f"[green]✓ Working endpoints saved to {output_file}[/green]")
        else:
            console.print("\n[yellow]⚠️ No working endpoints found![/yellow]")
        
        input("\n[dim]Press Enter to return to main menu...[/dim]")

    def run_warp_verification(self):
        verifier = AmneziaWGVerifier(
            config_path=self.verification_config_path,
            retries=self.verification_retries,
            timeout=self.tester.timeout
        )
        available, reason = verifier.available()
        if not available:
            fallback = XrayWarpVerifier(
                config_path=self.verification_config_path,
                retries=self.verification_retries,
                timeout=self.tester.timeout
            )
            fallback_available, fallback_reason = fallback.available()
            if fallback_available:
                console.print(f"\n[yellow]AmneziaWG verifier unavailable: {reason}[/yellow]")
                console.print("[dim]Falling back to Xray noKernelTun verifier.[/dim]")
                verifier = fallback
            else:
                console.print(f"\n[yellow]WARP verification skipped: {reason}; fallback unavailable: {fallback_reason}[/yellow]")
                console.print("[dim]Fast scan results are still shown below.[/dim]")
                return

        candidates = [result.endpoint for result in self.results[:self.verification_top_n]]
        verifier_name = "AmneziaWG netstack" if isinstance(verifier, AmneziaWGVerifier) else "Xray noKernelTun"
        console.print(
            f"\n[cyan]Verifying top {len(candidates)} endpoints through {verifier_name}...[/cyan]"
        )

        # Clear logger for verification phase
        self.logger.clear()
        
        # Setup progress for real-time display
        verification_progress = Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
            expand=True
        )
        verify_task = verification_progress.add_task(
            "[cyan]Verifying endpoints...", 
            total=len(candidates)
        )
        
        current_verified = 0
        working_verified = 0
        
        def realtime_callback(event_type, current, total, endpoint, latency):
            nonlocal current_verified, working_verified
            if event_type == "progress":
                current_verified = current
                verification_progress.update(verify_task, completed=current)
            elif event_type == "working":
                working_verified += 1
                verification_progress.update(
                    verify_task,
                    description=f"[cyan]Found {working_verified} working | {current_verified}/{len(candidates)}"
                )
                # Add to logger for real-time display
                self.logger.add(endpoint, "WORKING", latency)
            elif event_type == "failed":
                verification_progress.update(
                    verify_task,
                    description=f"[cyan]Working: {working_verified} | {current_verified}/{len(candidates)}"
                )
                # Add to logger for real-time display
                self.logger.add(endpoint, "FAILED")
        
        # Create live display
        from rich.layout import Layout
        from rich.live import Live
        
        def build_verify_display():
            stats = Table.grid(expand=True)
            stats.add_column(style="cyan")
            stats.add_column(style="green")
            stats.add_row(
                f"Tested: {current_verified}/{len(candidates)}",
                f"Working: {working_verified}"
            )
            return Group(
                verification_progress,
                Panel(stats, title="Status", border_style="cyan"),
                Panel(self.logger.display(), title="Real-time Verification Log", border_style="cyan")
            )
        
        try:
            with Live(build_verify_display(), console=console, refresh_per_second=4):
                self.verified_results = verifier.verify(
                    candidates, 
                    self.logger,
                    realtime_callback=realtime_callback
                )
        except Exception as e:
            console.print(f"\n[yellow]WARP verification failed: {e}[/yellow]")
            return

        if not self.verified_results:
            console.print("\n[yellow]No endpoints passed real WARP verification.[/yellow]")
            return

        verified_table = Table(
            title=f"Verified WARP Endpoints ({len(self.verified_results)})",
            box=box.ROUNDED
        )
        verified_table.add_column("#", style="dim")
        verified_table.add_column("Endpoint", style="green")
        verified_table.add_column("Real Latency", justify="right")
        verified_table.add_column("Loss", justify="right")
        verified_table.add_column("Success", justify="right")

        for i, result in enumerate(self.verified_results[:10], 1):
            verified_table.add_row(
                str(i),
                result.endpoint,
                f"{result.latency:.1f}ms",
                f"{result.loss:.1f}%",
                f"{result.success_count}/{result.retries}"
            )

        console.print(verified_table)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"warp_verified_{timestamp}.csv"
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Endpoint', 'Real Latency (ms)', 'Loss (%)', 'Success', 'Retries'])
            for result in self.verified_results:
                writer.writerow([
                    result.endpoint,
                    f"{result.latency:.1f}",
                    f"{result.loss:.1f}",
                    result.success_count,
                    result.retries
                ])
        console.print(f"\n[green]Verified WARP results saved to {filename}[/green]")
    
    def show_results(self):
        if not self.results:
            console.print("\n[yellow]No scan results available. Please run a scan first.[/yellow]")
            time.sleep(2)
            return
        
        self.clear_screen()
        self.print_header()

        if self.verified_results:
            verified_table = Table(
                title=f"[bold green]Verified WARP Endpoints[/bold green]",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan"
            )
            verified_table.add_column("#", style="dim", width=4)
            verified_table.add_column("Endpoint", style="green", width=50)
            verified_table.add_column("Real Latency", justify="right")
            verified_table.add_column("Loss", justify="right")

            for i, r in enumerate(self.verified_results[:50], 1):
                verified_table.add_row(str(i), r.endpoint, f"{r.latency:.1f} ms", f"{r.loss:.1f}%")

            console.print(verified_table)
        
        results_table = Table(title=f"[bold green]Top {min(50, len(self.results))} Working Endpoints[/bold green]",
                             box=box.ROUNDED,
                             show_header=True,
                             header_style="bold cyan")
        
        results_table.add_column("#", style="dim", width=4)
        results_table.add_column("Endpoint", style="white", width=50)
        results_table.add_column("Latency", justify="right", style="green")
        
        for i, r in enumerate(self.results[:50], 1):
            if r.latency < 50:
                latency_color = "bright_green"
            elif r.latency < 100:
                latency_color = "green"
            elif r.latency < 200:
                latency_color = "yellow"
            else:
                latency_color = "red"
            
            results_table.add_row(str(i), r.endpoint, f"[{latency_color}]{r.latency:.1f} ms[/{latency_color}]")
        
        console.print(results_table)
        
        console.print("\n[bold cyan]💡 Best endpoints for configuration:[/bold cyan]")
        for i, r in enumerate(self.results[:5], 1):
            console.print(f"  {i}. [green]{r.endpoint}[/green] [dim]({r.latency:.1f}ms)[/dim]")
        
        input("\n[dim]Press Enter to continue...[/dim]")
    
    def export_results(self):
        if not self.results:
            console.print("\n[yellow]No results to export.[/yellow]")
            time.sleep(1)
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = Prompt.ask("[cyan]Enter filename[/cyan]", default=f"warp_results_{timestamp}.csv")
        if not filename.endswith('.csv'):
            filename += '.csv'
        
        self.tester.save_results_csv(self.results, filename)
        console.print(f"\n[green]✓ Results exported to {filename}[/green]")
        time.sleep(1)
    
    def show_about(self):
        self.clear_screen()
        about_text = Panel(
            "[bold cyan]Warp Endpoint Scanner v3.1[/bold cyan]\n\n"
            "[yellow]New Features:[/yellow]\n"
            "  • Real-time scrolling log (last 50 entries)\n"
            "  • Auto-save working endpoints to endpoints_time.txt\n"
            "  • Smart range expansion when working endpoints found\n"
            "  • Configurable concurrent workers (50-500)\n"
            "  • Dynamic endpoint queue based on discoveries\n"
            "  • Latency range filtering (avoid unstable low-latency endpoints)\n\n"
            "[yellow]Why filter latency?[/yellow]\n"
            "  Very fast endpoints (<50ms) are often local proxies or CDNs\n"
            "  that may not work properly with the WireGuard protocol.\n"
            "  Using endpoints with 100-300ms latency often provides\n"
            "  more stable and reliable Warp connections.\n\n"
            "[yellow]How range expansion works:[/yellow]\n"
            "  When a working endpoint is found, the scanner automatically:\n"
            "  • Tests nearby IPs in the same subnet\n"
            "  • Tests adjacent ports on the same IP\n"
            "  • Adds up to 10 related endpoints to the scan queue\n\n"
            "[yellow]Performance:[/yellow]\n"
            "  • Adjustable concurrency for any network\n"
            "  • Real-time feedback with color-coded results\n"
            "  • Automatic result saving\n\n"
            "[dim]For educational purposes only[/dim]",
            box=box.DOUBLE_EDGE,
            padding=(1, 2)
        )
        console.print(about_text)
        input("\n[dim]Press Enter to return...[/dim]")

def main():
    try:
        tui = WarpTUI()
        tui.show_main_menu()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
