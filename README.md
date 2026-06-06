# TCP Port Scanner 🔍🔒

A simple, interactive TCP port scanner written in Python. Scan a target host for open ports, identify running services, and automatically save every result to a log file.

---

## Features

- **Three scan modes** — single port, multiple ports, or a port range
- **Concurrent scanning** — uses threads to scan many ports simultaneously
- **Service detection** — identifies common services (HTTP, SSH, MySQL, etc.)
- **Automatic logging** — every scan is saved to `scan_results.log` in plain text

---

## Requirements

- Python 3.8 or higher

---

## Installation

Clone or download the repository, then navigate into the project folder:

```bash
git clone https://github.com/your-username/tcp-port-scanner.git
cd tcp-port-scanner
```

---

## Usage

Run the scanner:

```bash
python portscanner.py
```

You will be guided through three interactive prompts:

**1. Enter a target**

```
Enter target IP or hostname: 142.250.129.101
```

**2. Choose a scan mode**

```
Scan mode:
  [1] Single port
  [2] Multiple ports
  [3] Port range
Choose (1/2/3):
```

**3. Enter the port(s)**

| Mode | Example input |
|------|--------------|
| Single port | `80` |
| Multiple ports | `22,80,443,8080` |
| Port range | `1-1024` |

---

## Sample Output

```
========================================
        TCP PORT SCANNER
========================================
  Log file: /home/user/scan_results.log

Enter target IP or hostname: 142.250.129.101

Scan mode:
  [1] Single port
  [2] Multiple ports
  [3] Port range
Choose (1/2/3): 3

Enter port range (e.g. 1-1024): 1-120

  Scanning '142.250.129.101' ...

> On the terminal, the port number, state, and scan duration are printed in **green**.

---

## Log File

Every scan is automatically appended to `scan_results.log` in the same directory. The log is written in plain text with no colour codes, making it easy to read, search, or share.

```
Scan report for 142.250.129.101 (142.250.129.101)
Scanned 120 port(s)
----------------------------------------
PORT     STATE    SERVICE
----------------------------------------
80       open     http
----------------------------------------
Scan completed in 0.55 seconds
Log saved to: /home/user/scan_results.log
```

To view the log:

```bash
cat scan_results.log
```

To search for open ports across all past scans:

```bash
grep "open" scan_results.log
```

---

## How It Works

1. The target hostname is resolved to an IP address once before scanning begins.
2. Ports are submitted to a thread pool (50 concurrent workers by default).
3. Each worker opens a raw TCP socket and calls `connect_ex()`. A return code of `0` means the port is open; anything else means closed.
4. Results are collected, sorted by port number, and only open ports are displayed.
5. The full report is printed to the terminal and written to the log file simultaneously.

---

## Legal Disclaimer

> **Only scan hosts you own or have explicit written permission to scan.**
> Unauthorised port scanning may violate computer fraud and cybercrime laws in your country. The author assumes no liability for misuse of this tool.

---

## License

MIT License — free to use, modify, and distribute.
