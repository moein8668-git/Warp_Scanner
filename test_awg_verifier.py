#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except ImportError:
    print("rich is required. Run: python -m pip install rich")
    sys.exit(1)


console = Console()

ENDPOINTS = [
    "8.6.112.208:7281",
    "188.114.97.6:7281",
    "8.34.146.1:2371",
    "8.34.146.1:2408",
    "8.34.146.1:1843",
    "8.34.146.1:1701",
    "8.34.146.1:1180",
    "8.34.146.1:1387",
    "8.34.146.1:1074",
    "8.34.146.1:1070",
    "8.34.146.1:1014",
    "8.34.146.1:1018",
    "8.34.146.1:1002",
    "8.34.146.1:1010",
    "8.34.146.1:987",
    "8.34.146.1:988",
    "8.34.146.1:968",
    "8.34.146.1:955",
    "8.34.146.1:946",
    "8.34.146.4:903",
    "8.34.146.0:903",
    "8.34.146.3:903",
    "8.34.146.4:894",
]


@dataclass
class Result:
    endpoint: str
    ok: bool
    latency_ms: float = 0.0
    loss_percent: float = 100.0
    success_count: int = 0
    retries: int = 0
    error: str = ""


def find_helper() -> str:
    candidates = [
        "awg_verifier.exe",
        os.path.join("awg_verifier", "awg_verifier.exe"),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return ""


def run_one(helper: str, config: str, endpoint: str, retries: int, timeout: float) -> Result:
    cmd = [
        helper,
        "-config", config,
        "-endpoints", endpoint,
        "-retries", str(retries),
        "-timeout", f"{timeout}s",
    ]
    start = time.time()
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=max(15, int(timeout * retries + 8)),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        return Result(endpoint=endpoint, ok=False, retries=retries, error="verifier timeout")

    elapsed_ms = (time.time() - start) * 1000
    output = completed.stdout.strip()

    try:
        payload = json.loads(output) if output else {}
    except json.JSONDecodeError:
        return Result(
            endpoint=endpoint,
            ok=False,
            retries=retries,
            error=(completed.stderr or output or "invalid verifier output").strip(),
        )

    if isinstance(payload, dict):
        return Result(endpoint=endpoint, ok=False, retries=retries, error=payload.get("error", "unknown error"))

    if not payload:
        return Result(endpoint=endpoint, ok=False, retries=retries, error="empty verifier result")

    item = payload[0]
    success_count = int(item.get("success_count", 0))
    ok = success_count > 0
    return Result(
        endpoint=item.get("endpoint", endpoint),
        ok=ok,
        latency_ms=float(item.get("latency_ms", elapsed_ms if ok else 0.0)),
        loss_percent=float(item.get("loss_percent", 100.0)),
        success_count=success_count,
        retries=int(item.get("retries", retries)),
        error=item.get("error", ""),
    )


def print_summary(results):
    table = Table(title="AWG Verifier Test Results")
    table.add_column("#", style="dim", justify="right")
    table.add_column("Endpoint")
    table.add_column("Status")
    table.add_column("Latency", justify="right")
    table.add_column("Loss", justify="right")
    table.add_column("Success", justify="right")
    table.add_column("Error")

    for i, result in enumerate(results, 1):
        status = "[green]WORKING[/green]" if result.ok else "[red]FAILED[/red]"
        latency = f"{result.latency_ms:.1f}ms" if result.ok else "-"
        table.add_row(
            str(i),
            result.endpoint,
            status,
            latency,
            f"{result.loss_percent:.1f}%",
            f"{result.success_count}/{result.retries}",
            result.error[:80],
        )

    console.print(table)


def main():
    config = sys.argv[1] if len(sys.argv) > 1 else "config.conf"
    retries = int(os.environ.get("AWG_TEST_RETRIES", "1"))
    timeout = float(os.environ.get("AWG_TEST_TIMEOUT", "4"))

    helper = find_helper()
    if not helper:
        console.print("[red]awg_verifier.exe was not found. Build it first.[/red]")
        sys.exit(1)
    if not os.path.exists(config):
        console.print(f"[red]{config} was not found.[/red]")
        sys.exit(1)

    console.print(Panel(
        f"[bold cyan]AWG verifier smoke test[/bold cyan]\n"
        f"Helper: {helper}\n"
        f"Config: {config}\n"
        f"Endpoints: {len(ENDPOINTS)}\n"
        f"Retries: {retries}, Timeout: {timeout}s",
        border_style="cyan",
    ))

    results = []
    for i, endpoint in enumerate(ENDPOINTS, 1):
        console.print(f"[cyan]{i:02d}/{len(ENDPOINTS)}[/cyan] Testing {endpoint} ...", end="")
        result = run_one(helper, config, endpoint, retries, timeout)
        results.append(result)
        if result.ok:
            console.print(f" [green]WORKING[/green] {result.latency_ms:.1f}ms loss={result.loss_percent:.1f}%")
        else:
            console.print(f" [red]FAILED[/red] {result.error}")

    console.print()
    print_summary(results)

    working = [r for r in results if r.ok]
    if working:
        best = sorted(working, key=lambda r: (r.loss_percent, r.latency_ms))[0]
        console.print(f"\n[bold green]Best:[/bold green] {best.endpoint} ({best.latency_ms:.1f}ms, loss {best.loss_percent:.1f}%)")
    else:
        console.print("\n[yellow]No endpoint passed AWG verification.[/yellow]")


if __name__ == "__main__":
    main()
