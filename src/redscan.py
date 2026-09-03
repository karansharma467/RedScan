#!/usr/bin/env python3

import argparse
import datetime
import ipaddress
import json
import socket
from pathlib import Path


VERSION = "2.0"

QUICK_PORTS = [22, 80, 443, 8080]
WEB_PORTS = [80, 443, 8000, 8080, 8443]


def parse_ports(port_string):
    ports = set()

    for item in port_string.split(","):
        item = item.strip()

        if not item:
            raise ValueError("Empty port value.")

        try:
            if "-" in item:
                parts = item.split("-", 1)

                if len(parts) != 2:
                    raise ValueError(
                        f"Invalid port range: {item}"
                    )

                start = int(parts[0].strip())
                end = int(parts[1].strip())

                if start > end:
                    raise ValueError(
                        f"Invalid port range: {item}"
                    )

                for port in range(start, end + 1):
                    if not 1 <= port <= 65535:
                        raise ValueError(
                            f"Port must be between 1 and 65535: {port}"
                        )

                    ports.add(port)

            else:
                port = int(item)

                if not 1 <= port <= 65535:
                    raise ValueError(
                        f"Port must be between 1 and 65535: {port}"
                    )

                ports.add(port)

        except ValueError:
            raise ValueError(
                f"Invalid port value: {item}"
            )

    if not ports:
        raise ValueError("No valid ports supplied.")

    return sorted(ports)

def validate_target(target):
    try:
        ipaddress.ip_address(target)
        return target

    except ValueError:
        try:
            return socket.gethostbyname(target)

        except socket.gaierror:
            raise ValueError(
                "Invalid target or hostname."
            )


def check_reachability(target):
    try:
        result = socket.gethostbyname(target)
        return result is not None

    except socket.gaierror:
        return False


def reverse_dns(target):
    try:
        hostname = socket.gethostbyaddr(target)[0]
        return hostname

    except (socket.herror, socket.gaierror):
        return "Not available"


def scan_port(target, port, timeout):
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(timeout)

    try:
        result = sock.connect_ex(
            (target, port)
        )

        if result == 0:
            return True

        return False

    except (socket.timeout, socket.error):
        return False

    finally:
        sock.close()


def identify_service(port):
    try:
        return socket.getservbyport(
            port,
            "tcp"
        )

    except OSError:
        return "unknown"


def grab_banner(target, port, timeout):
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(timeout)

    try:
        sock.connect(
            (target, port)
        )

        banner = sock.recv(
            1024
        ).decode(
            "utf-8",
            errors="replace"
        ).strip()

        if not banner:
            return "No banner received"

        banner = " ".join(
            banner.split()
        )

        return banner[:300]

    except (socket.timeout, socket.error):
        return "Banner unavailable"

    finally:
        sock.close()


def inspect_http(target, port, timeout):
    findings = []

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(timeout)

    try:
        sock.connect(
            (target, port)
        )

        request = (
            "HEAD / HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        sock.sendall(
            request.encode()
        )

        response = sock.recv(
            8192
        ).decode(
            "iso-8859-1",
            errors="replace"
        )

        lines = response.splitlines()

        status_line = (
            lines[0]
            if lines
            else "No HTTP response"
        )

        headers = {}

        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(
                    ":",
                    1
                )

                headers[
                    key.strip().lower()
                ] = value.strip()

        server = headers.get(
            "server",
            "Not disclosed"
        )

        if server != "Not disclosed":
            findings.append(
                {
                    "severity": "INFO",
                    "title":
                        "Server information disclosure",
                    "description":
                        f"HTTP Server header: {server}",
                }
            )

        if "x-content-type-options" not in headers:
            findings.append(
                {
                    "severity": "LOW",
                    "title":
                        "Missing X-Content-Type-Options",
                    "description":
                        "The HTTP response does not include "
                        "the X-Content-Type-Options header.",
                }
            )

        if "x-frame-options" not in headers:
            findings.append(
                {
                    "severity": "LOW",
                    "title":
                        "Missing X-Frame-Options",
                    "description":
                        "The HTTP response does not include "
                        "the X-Frame-Options header.",
                }
            )

        if "content-security-policy" not in headers:
            findings.append(
                {
                    "severity": "LOW",
                    "title":
                        "Missing Content-Security-Policy",
                    "description":
                        "The HTTP response does not include "
                        "a Content-Security-Policy header.",
                }
            )

        if (
            port == 443
            and "strict-transport-security"
            not in headers
        ):
            findings.append(
                {
                    "severity": "MEDIUM",
                    "title": "Missing HSTS",
                    "description":
                        "HTTPS service does not include "
                        "the Strict-Transport-Security header.",
                }
            )

        try:
            options_sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            options_sock.settimeout(
                timeout
            )

            options_sock.connect(
                (target, port)
            )

            options_request = (
                "OPTIONS / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )

            options_sock.sendall(
                options_request.encode()
            )

            options_response = (
                options_sock.recv(
                    8192
                ).decode(
                    "iso-8859-1",
                    errors="replace"
                )
            )

            options_sock.close()

            for line in options_response.splitlines():

                if line.lower().startswith(
                    "allow:"
                ):
                    allow_value = (
                        line.split(
                            ":",
                            1
                        )[1].strip()
                    )

                    findings.append(
                        {
                            "severity": "INFO",
                            "title":
                                "HTTP methods advertised",
                            "description":
                                f"Allow header: "
                                f"{allow_value}",
                        }
                    )

                    break

        except (socket.timeout, socket.error):
            pass

        return {
            "status": status_line,
            "server": server,
            "findings": findings,
        }

    except (socket.timeout, socket.error):

        return {
            "status":
                "HTTP inspection failed",
            "server":
                "Unknown",
            "findings": [],
        }

    finally:
        sock.close()


def calculate_risk_summary(findings):
    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for finding in findings:
        severity = finding.get(
            "severity",
            "INFO"
        )

        if severity in summary:
            summary[severity] += 1

    return summary


def get_overall_risk(summary):
    if summary["CRITICAL"] > 0:
        return "CRITICAL"

    if summary["HIGH"] > 0:
        return "HIGH"

    if summary["MEDIUM"] > 0:
        return "MEDIUM"

    if summary["LOW"] > 0:
        return "LOW"

    return "INFO"


def save_text_report(
    target,
    hostname,
    mode,
    ports,
    timeout,
    open_ports,
    findings,
    scan_time,
):
    reports_dir = Path("reports")
    reports_dir.mkdir(
        exist_ok=True
    )

    timestamp = datetime.datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        reports_dir
        / f"scan_{target}_{timestamp}.txt"
    )

    risk_summary = calculate_risk_summary(
        findings
    )

    overall_risk = get_overall_risk(
        risk_summary
    )

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        file.write("=" * 60 + "\n")
        file.write(
            "RedScan Security Assessment Report\n"
        )
        file.write("=" * 60 + "\n\n")

        file.write(
            f"RedScan Version : {VERSION}\n"
        )
        file.write(
            f"Target          : {target}\n"
        )
        file.write(
            f"Hostname        : {hostname}\n"
        )
        file.write(
            f"Scan Mode       : {mode}\n"
        )
        file.write(
            f"Scan Time       : {scan_time}\n"
        )
        file.write(
            f"Timeout         : {timeout} seconds\n"
        )
        file.write(
            f"Ports Scanned   : {len(ports)}\n"
        )
        file.write(
            f"Open Ports      : {len(open_ports)}\n"
        )
        file.write(
            f"Findings        : {len(findings)}\n"
        )
        file.write(
            f"Overall Risk    : {overall_risk}\n\n"
        )

        file.write("-" * 60 + "\n")
        file.write("RISK SUMMARY\n")
        file.write("-" * 60 + "\n\n")

        for severity, count in risk_summary.items():
            file.write(
                f"{severity:<10}: {count}\n"
            )

        file.write("\n")

        file.write("-" * 60 + "\n")
        file.write("OPEN PORTS\n")
        file.write("-" * 60 + "\n\n")

        if open_ports:

            for item in open_ports:

                file.write(
                    f"Port       : {item['port']}\n"
                )

                file.write(
                    f"Service    : {item['service']}\n"
                )

                file.write(
                    f"Banner     : {item['banner']}\n"
                )

                if item.get("http"):

                    file.write(
                        f"HTTP Status: "
                        f"{item['http']['status']}\n"
                    )

                    file.write(
                        f"HTTP Server: "
                        f"{item['http']['server']}\n"
                    )

                file.write("\n")

        else:
            file.write(
                "No open TCP ports detected.\n\n"
            )

        file.write("-" * 60 + "\n")
        file.write("SECURITY FINDINGS\n")
        file.write("-" * 60 + "\n\n")

        if findings:

            for index, finding in enumerate(
                findings,
                1
            ):

                file.write(
                    f"{index}. "
                    f"[{finding['severity']}] "
                    f"{finding['title']}\n"
                )

                file.write(
                    f"   "
                    f"{finding['description']}\n\n"
                )

        else:
            file.write(
                "No findings detected.\n"
            )

    return filename


def save_json_report(
    target,
    hostname,
    mode,
    ports,
    timeout,
    open_ports,
    findings,
    scan_time,
):
    reports_dir = Path("reports")
    reports_dir.mkdir(
        exist_ok=True
    )

    timestamp = datetime.datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        reports_dir
        / f"scan_{target}_{timestamp}.json"
    )

    risk_summary = calculate_risk_summary(
        findings
    )

    overall_risk = get_overall_risk(
        risk_summary
    )

    report = {
        "redscan_version": VERSION,
        "target": target,
        "hostname": hostname,
        "scan_mode": mode,
        "scan_time": scan_time,
        "ports_scanned": ports,
        "timeout_seconds": timeout,
        "open_port_count": len(open_ports),
        "finding_count": len(findings),
        "overall_risk": overall_risk,
        "risk_summary": risk_summary,
        "open_ports": open_ports,
        "findings": findings,
    }

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    return filename


def save_html_report(
    target,
    hostname,
    mode,
    ports,
    timeout,
    open_ports,
    findings,
    scan_time,
):
    reports_dir = Path("reports")
    reports_dir.mkdir(
        exist_ok=True
    )

    timestamp = datetime.datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        reports_dir
        / f"scan_{target}_{timestamp}.html"
    )

    risk_summary = calculate_risk_summary(
        findings
    )

    overall_risk = get_overall_risk(
        risk_summary
    )

    severity_class = {
        "INFO": "info",
        "LOW": "low",
        "MEDIUM": "medium",
        "HIGH": "high",
        "CRITICAL": "critical",
    }

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>RedScan Report - {target}</title>

<style>

body {{
    font-family: Arial, Helvetica, sans-serif;
    background: #f4f6f8;
    margin: 0;
    padding: 0;
    color: #222;
}}

.container {{
    max-width: 1100px;
    margin: 40px auto;
    background: white;
    padding: 35px;
    border-radius: 12px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.08);
}}

h1 {{
    margin-bottom: 5px;
}}

.subtitle {{
    color: #666;
    margin-bottom: 30px;
}}

.summary {{
    display: grid;
    grid-template-columns:
    repeat(4, 1fr);
    gap: 15px;
    margin-bottom: 30px;
}}

.card {{
    padding: 20px;
    background: #f7f8fa;
    border-radius: 8px;
    text-align: center;
}}

.card strong {{
    display: block;
    font-size: 28px;
    margin-top: 8px;
}}

.risk-summary {{
    display: grid;
    grid-template-columns:
    repeat(5, 1fr);
    gap: 10px;
    margin-bottom: 30px;
}}

.risk-card {{
    padding: 15px;
    border-radius: 8px;
    text-align: center;
    background: #f7f8fa;
}}

.risk-card strong {{
    display: block;
    font-size: 24px;
    margin-top: 5px;
}}

.overall-risk {{
    padding: 18px;
    margin-bottom: 30px;
    background: #f7f8fa;
    border-radius: 8px;
    font-size: 20px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
    margin-bottom: 30px;
}}

th, td {{
    padding: 12px;
    border-bottom: 1px solid #ddd;
    text-align: left;
}}

th {{
    background: #f0f2f5;
}}

.finding {{
    padding: 15px;
    margin: 10px 0;
    border-radius: 8px;
    border-left: 5px solid;
}}

.info {{
    background: #eef5ff;
    border-color: #3498db;
}}

.low {{
    background: #fff8e6;
    border-color: #f1c40f;
}}

.medium {{
    background: #fff0e6;
    border-color: #e67e22;
}}

.high {{
    background: #ffeaea;
    border-color: #e74c3c;
}}

.critical {{
    background: #f5e6e6;
    border-color: #8e0000;
}}

.meta {{
    line-height: 1.8;
}}

code {{
    background: #f1f1f1;
    padding: 3px 6px;
    border-radius: 4px;
}}

.footer {{
    margin-top: 35px;
    color: #777;
    font-size: 13px;
}}

@media (max-width: 700px) {{

    .summary {{
        grid-template-columns: 1fr 1fr;
    }}

    .risk-summary {{
        grid-template-columns: 1fr 1fr;
    }}

    .container {{
        margin: 10px;
        padding: 20px;
    }}
}}

</style>

</head>

<body>

<div class="container">

<h1>🔎 RedScan Security Assessment</h1>

<div class="subtitle">
Authorized Reconnaissance &
Vulnerability Assessment Framework
</div>

<div class="meta">

<strong>Target:</strong>
<code>{target}</code>
<br>

<strong>Hostname:</strong>
{hostname}
<br>

<strong>Scan Mode:</strong>
{mode}
<br>

<strong>Scan Time:</strong>
{scan_time}
<br>

<strong>Timeout:</strong>
{timeout} seconds

</div>

<h2>Scan Summary</h2>

<div class="summary">

<div class="card">
Ports Scanned
<strong>{len(ports)}</strong>
</div>

<div class="card">
Open Ports
<strong>{len(open_ports)}</strong>
</div>

<div class="card">
Findings
<strong>{len(findings)}</strong>
</div>

<div class="card">
Version
<strong>{VERSION}</strong>
</div>

</div>

<div class="overall-risk">

<strong>Overall Risk:</strong>
{overall_risk}

</div>

<h2>Risk Summary</h2>

<div class="risk-summary">

<div class="risk-card">
CRITICAL
<strong>{risk_summary["CRITICAL"]}</strong>
</div>

<div class="risk-card">
HIGH
<strong>{risk_summary["HIGH"]}</strong>
</div>

<div class="risk-card">
MEDIUM
<strong>{risk_summary["MEDIUM"]}</strong>
</div>

<div class="risk-card">
LOW
<strong>{risk_summary["LOW"]}</strong>
</div>

<div class="risk-card">
INFO
<strong>{risk_summary["INFO"]}</strong>
</div>

</div>

<h2>Open Ports</h2>

<table>

<tr>
<th>Port</th>
<th>Service</th>
<th>Banner</th>
<th>HTTP</th>
</tr>
"""

    if open_ports:

        for item in open_ports:

            http_info = "—"

            if item.get("http"):

                http_info = (
                    f"{item['http']['status']}<br>"
                    f"Server: "
                    f"{item['http']['server']}"
                )

            html += f"""
<tr>
<td>{item['port']}</td>
<td>{item['service']}</td>
<td>{item['banner']}</td>
<td>{http_info}</td>
</tr>
"""

    else:

        html += """
<tr>
<td colspan="4">
No open TCP ports detected.
</td>
</tr>
"""

    html += """
</table>

<h2>Security Findings</h2>
"""

    if findings:

        for finding in findings:

            css_class = severity_class.get(
                finding["severity"],
                "info"
            )

            html += f"""
<div class="finding {css_class}">

<strong>
[{finding["severity"]}]
{finding["title"]}
</strong>

<br>

{finding["description"]}

</div>
"""

    else:

        html += """
<p>No findings detected.</p>
"""

    html += f"""
<div class="footer">

Generated by RedScan v{VERSION}.<br>

This report contains reconnaissance and
assessment observations.

Findings should be manually verified before
treating them as confirmed vulnerabilities.

</div>

</div>

</body>
</html>
"""

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html)

    return filename


def main():

    parser = argparse.ArgumentParser(
        description=
        "RedScan - Authorized Reconnaissance "
        "& Vulnerability Assessment Framework"
    )

    parser.add_argument(
        "target",
        help=
        "Target IP address or hostname"
    )

    parser.add_argument(
        "--mode",
        choices=[
            "quick",
            "web",
            "custom"
        ],
        default="quick",
        help="Scan mode"
    )

    parser.add_argument(
        "--ports",
        help=
        "Custom ports, e.g. "
        "22,80,443 or 1-100"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help=
        "TCP connection timeout "
        "in seconds"
    )

    parser.add_argument(
        "--format",
        choices=[
            "txt",
            "json",
            "html",
            "both",
            "all"
        ],
        default="txt",
        help="Report format"
    )

    args = parser.parse_args()

    print()
    print("=" * 60)
    print(f"RedScan v{VERSION}")
    print(
        "Authorized Reconnaissance & "
        "Vulnerability Assessment"
    )
    print("=" * 60)

    try:
        target = validate_target(
            args.target
        )

    except ValueError as error:

        print(
            f"[!] Error: {error}"
        )

        return

    print(
        f"\n[*] Target: {target}"
    )

    if not check_reachability(
        target
    ):

        print(
            "[!] Target is not reachable."
        )

        return

    print(
        "[+] Target is reachable."
    )

    hostname = reverse_dns(
        target
    )

    print(
        f"[*] Hostname: {hostname}"
    )

    if args.mode == "quick":

        ports = QUICK_PORTS

    elif args.mode == "web":

        ports = WEB_PORTS

    else:

        if not args.ports:

            print(
                "[!] Custom mode requires "
                "--ports."
            )

            return

        try:

            ports = parse_ports(
                args.ports
            )

        except ValueError as error:

            print(
                f"[!] Error: {error}"
            )

            return

    print(
        f"[*] Scan mode: {args.mode}"
    )

    print(
        f"[*] Ports: {ports}"
    )

    print(
        f"[*] Timeout: "
        f"{args.timeout} seconds"
    )

    print(
        "\n[*] Starting TCP scan...\n"
    )

    open_ports = []
    findings = []

    for port in ports:

        print(
            f"[*] Scanning port "
            f"{port}...",
            end=" "
        )

        if scan_port(
            target,
            port,
            args.timeout
        ):

            service = identify_service(
                port
            )

            print(
                f"OPEN ({service})"
            )

            banner = "Not requested"

            if port not in [
                80,
                443,
                8000,
                8080,
                8443
            ]:

                banner = grab_banner(
                    target,
                    port,
                    args.timeout
                )

            result = {
                "port": port,
                "service": service,
                "banner": banner,
            }

            if port in [
                80,
                443,
                8000,
                8080,
                8443
            ]:

                print(
                    "    [*] Inspecting "
                    "HTTP service..."
                )

                http_result = inspect_http(
                    target,
                    port,
                    args.timeout
                )

                result["http"] = http_result

                findings.extend(
                    http_result["findings"]
                )

                print(
                    "    [+] HTTP Status: "
                    f"{http_result['status']}"
                )

                print(
                    "    [+] Server: "
                    f"{http_result['server']}"
                )

            else:

                print(
                    "    [*] Banner: "
                    f"{banner}"
                )

            open_ports.append(
                result
            )

        else:

            print(
                "CLOSED/FILTERED"
            )

    scan_time = datetime.datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    risk_summary = calculate_risk_summary(
        findings
    )

    overall_risk = get_overall_risk(
        risk_summary
    )

    print()
    print("=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)

    print(
        f"Target       : {target}"
    )

    print(
        f"Hostname     : {hostname}"
    )

    print(
        f"Ports scanned: {len(ports)}"
    )

    print(
        f"Open ports   : {len(open_ports)}"
    )

    print(
        f"Findings     : {len(findings)}"
    )

    print(
        f"Overall Risk : {overall_risk}"
    )

    print()
    print("Risk Summary:")

    for severity, count in risk_summary.items():

        print(
            f"  {severity:<8}: {count}"
        )

    if open_ports:

        print("\nOpen Ports:")

        for item in open_ports:

            print(
                f"  {item['port']}/tcp "
                f"- {item['service']}"
            )

    if findings:

        print(
            "\nSecurity Findings:"
        )

        for finding in findings:

            print(
                f"  [{finding['severity']}] "
                f"{finding['title']}"
            )

    print()

    if args.format in [
        "txt",
        "both",
        "all"
    ]:

        txt_file = save_text_report(
            target,
            hostname,
            args.mode,
            ports,
            args.timeout,
            open_ports,
            findings,
            scan_time,
        )

        print(
            f"[+] Text report: "
            f"{txt_file}"
        )

    if args.format in [
        "json",
        "both",
        "all"
    ]:

        json_file = save_json_report(
            target,
            hostname,
            args.mode,
            ports,
            args.timeout,
            open_ports,
            findings,
            scan_time,
        )

        print(
            f"[+] JSON report: "
            f"{json_file}"
        )

    if args.format in [
        "html",
        "all"
    ]:

        html_file = save_html_report(
            target,
            hostname,
            args.mode,
            ports,
            args.timeout,
            open_ports,
            findings,
            scan_time,
        )

        print(
            f"[+] HTML report: "
            f"{html_file}"
        )

    print(
        "\n[+] Scan completed successfully."
    )


if __name__ == "__main__":
    main()
