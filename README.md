# 🔎 RedScan

### Authorized Reconnaissance & Vulnerability Assessment Framework

RedScan is a Python-based cybersecurity reconnaissance tool designed for
**authorized security testing and learning**.

It performs basic TCP port scanning, service identification, HTTP inspection,
reverse DNS reconnaissance, security-header checks, banner detection, and
generates scan reports in TXT, JSON, and HTML formats.

> ⚠️ **Legal Notice**
>
> RedScan should only be used against systems that you own or have explicit
> permission to test. Do not scan public systems, networks, or websites
> without authorization.

---

## 🚀 Features

- 🎯 IP address and hostname validation
- 📡 Target reachability checking
- 🔌 TCP port scanning
- 🛠️ Service identification
- ⏱️ Configurable connection timeout
- 🎛️ Multiple scan modes
- 🧾 Basic TCP banner detection
- 🌐 HTTP service inspection
- 🔍 Reverse DNS / hostname lookup
- 🛡️ Basic HTTP security-header checks
- 📄 TXT scan reports
- 📊 JSON scan reports
- 🌐 HTML scan reports
- 🧪 Automated tests using pytest
- 🖥️ Beginner-friendly command-line interface

---

## 📋 Scan Modes

### Quick Mode

Scans common ports:

```text
22, 80, 443, 8080
