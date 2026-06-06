#!/usr/bin/env python3
"""
portscanner.py — Simple Interactive TCP Port Scanner
Scans a target host for open/closed TCP ports and logs results to a file.
"""

import socket
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Colours ───────────────────────────────────────────────────────────────────

GREEN = "\033[32m"
RESET = "\033[0m"

def green(text: str) -> str:
    return f"{GREEN}{text}{RESET}"

# ── Logging Setup ─────────────────────────────────────────────────────────────

LOG_FILE  = "scan_results.log"
DATE_FMT  = "%Y-%m-%d %H:%M:%S"

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(logging.Formatter("%(message)s"))

logging.basicConfig(level=logging.INFO, handlers=[file_handler])
log = logging.getLogger("portscanner")

def log_and_print(line: str, plain_line: str = None) -> None:
    """Print coloured line to terminal and write plain line to log file."""
    print(line)
    log.info(plain_line if plain_line is not None else line)

# ── Service Name Lookup ───────────────────────────────────────────────────────

SERVICES = {
    21: "ftp",       22: "ssh",       23: "telnet",    25: "smtp",
    53: "dns",       80: "http",      110: "pop3",     143: "imap",
    443: "https",    445: "smb",      3306: "mysql",   3389: "rdp",
    5432: "postgresql", 6379: "redis", 8080: "http-alt", 27017: "mongodb",
}

def get_service(port: int) -> str:
    if port in SERVICES:
        return SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp").lower()
    except OSError:
        return "unknown"

# ── Core Scan Function ────────────────────────────────────────────────────────

def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            state = "open" if result == 0 else "closed"
    except OSError:
        state = "error"
    return {"port": port, "state": state, "service": get_service(port)}

# ── Scan Orchestrator ─────────────────────────────────────────────────────────

def run_scan(target: str, ports: list, threads: int = 50, timeout: float = 1.0):
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve host: '{target}'")
        return

    start_time = time.perf_counter()
    results = []

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(scan_port, ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            results.append(future.result())

    elapsed = time.perf_counter() - start_time

    # Sort all results by port number
    results.sort(key=lambda r: r["port"])
    open_results = [r for r in results if r["state"] == "open"]

    # ── Report header
    sep = "-" * 40
    header_plain = [
        "",
        f"Scan report for {target} ({ip})",
        f"Scanned {len(ports)} port(s)",
        sep,
        f"{'PORT':<8} {'STATE':<8} {'SERVICE'}",
        sep,
    ]
    header_colour = [
        "",
        f"Scan report for {green(target)} ({ip})",
        f"Scanned {green(str(len(ports)))} port(s)",
        sep,
        f"{'PORT':<8} {'STATE':<8} {'SERVICE'}",
        sep,
    ]
    for plain, coloured in zip(header_plain, header_colour):
        log_and_print(coloured, plain)

    # ── Per-port rows (only open ports shown, matching nmap-style)
    for r in open_results:
        port_col    = str(r["port"])
        state_col   = r["state"]
        service_col = r["service"]

        plain_row  = f"{port_col:<8} {state_col:<8} {service_col}"
        colour_row = f"{green(port_col.ljust(8))} {green(state_col.ljust(8))} {service_col}"
        log_and_print(colour_row, plain_row)

    if not open_results:
        log_and_print("  (no open ports found)")

    # ── Footer
    footer_plain  = [
        sep,
        f"Scan completed in {elapsed:.2f} seconds",
        f"Log saved to: {os.path.abspath(LOG_FILE)}",
        "",
    ]
    footer_colour = [
        sep,
        f"Scan completed in {green(f'{elapsed:.2f}')} seconds",
        f"Log saved to: {os.path.abspath(LOG_FILE)}",
        "",
    ]
    for plain, coloured in zip(footer_plain, footer_colour):
        log_and_print(coloured, plain)

# ── User Input Helpers ────────────────────────────────────────────────────────

def get_target() -> str:
    while True:
        target = input("\nEnter target IP or hostname: ").strip()
        if target:
            return target
        print("  [!] Target cannot be empty. Try again.")

def get_scan_mode() -> str:
    print("\nScan mode:")
    print("  [1] Single port")
    print("  [2] Multiple ports")
    print("  [3] Port range")
    while True:
        choice = input("Choose (1/2/3): ").strip()
        if choice in ("1", "2", "3"):
            return choice
        print("  [!] Enter 1, 2, or 3.")

def get_ports(mode: str) -> list:
    if mode == "1":
        while True:
            raw = input("Enter port number: ").strip()
            if raw.isdigit() and 1 <= int(raw) <= 65535:
                return [int(raw)]
            print("  [!] Enter a valid port (1-65535).")

    elif mode == "2":
        while True:
            raw = input("Enter ports separated by commas (e.g. 22,80,443): ").strip()
            try:
                ports = [int(p.strip()) for p in raw.split(",")]
                if all(1 <= p <= 65535 for p in ports):
                    return ports
            except ValueError:
                pass
            print("  [!] Invalid input. Use comma-separated numbers, e.g. 22,80,443")

    elif mode == "3":
        while True:
            raw = input("Enter port range (e.g. 1-1024): ").strip()
            try:
                start_str, end_str = raw.split("-")
                start, end = int(start_str.strip()), int(end_str.strip())
                if 1 <= start <= end <= 65535:
                    return list(range(start, end + 1))
            except (ValueError, AttributeError):
                pass
            print("  [!] Invalid range. Use format: START-END, e.g. 1-1024")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 40)
    print("        TCP PORT SCANNER")
    print("=" * 40)
    print(f"  Log file: {os.path.abspath(LOG_FILE)}")

    target = get_target()
    mode   = get_scan_mode()
    ports  = get_ports(mode)

    print(f"\n  Scanning '{target}' ...\n")
    run_scan(target, ports)

if __name__ == "__main__":
    main()
