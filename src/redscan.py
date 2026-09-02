#!/usr/bin/env python3

import argparse
import ipaddress
import json
import os
import socket
import subprocess
from datetime import datetime


VERSION = "1.6"

SCAN_MODES = {
    "quick": "22,80,443,8080",
    "web": "80,443,8000,8080,8443",
}

HTTP_PORTS = [80, 443, 8000, 8080, 8443]


def show_banner():
    print("=" * 65)
    print(f"                    REDSCAN v{VERSION}")
    print("             Authorized Security Scanner")
    print("=" * 65)


def validate_target(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def reverse_dns_lookup(target):
    print(
        f"\n[*] Performing reverse DNS lookup for {target}..."
    )

    try:
        hostname, aliases, addresses = socket.gethostbyaddr(
            target
        )

        print(f"[+] Hostname: {hostname}")

        if aliases:
            print(
                f"[+] Aliases: {', '.join(aliases)}"
            )

        return hostname, aliases

    except (socket.herror, socket.gaierror):
        print("[-] No hostname found.")
        return "Not found", []


def check_reachability(target):
    print(
        f"\n[*] Checking reachability of {target}..."
    )

    result = subprocess.run(
        ["ping", "-c", "1", "-W", "2", target],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if result.returncode == 0:
        print("[+] Target is reachable.")
        return True

    print("[-] Target is not reachable.")
    return False


def parse_ports(port_string):
    ports = set()

    for part in port_string.split(","):
        part = part.strip()

        if not part:
            continue

        if "-" in part:
            try:
                start, end = map(
                    int,
                    part.split("-", 1)
                )
            except ValueError:
                raise ValueError(
                    f"Invalid port range: {part}"
                )

            if (
                start < 1
                or end > 65535
                or start > end
            ):
                raise ValueError(
                    f"Invalid port range: {part}"
                )

            ports.update(
                range(start, end + 1)
            )

        else:
            try:
                port = int(part)
            except ValueError:
                raise ValueError(
                    f"Invalid port: {part}"
                )

            if port < 1 or port > 65535:
                raise ValueError(
                    f"Invalid port: {part}"
                )

            ports.add(port)

    return sorted(ports)


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

        return result == 0

    finally:
        sock.close()


def detect_service(port):
    try:
        return socket.getservbyport(
            port,
            "tcp"
        )
    except OSError:
        return "unknown"


def grab_banner(target, port, timeout=2):
    try:
        sock = socket.create_connection(
            (target, port),
            timeout=timeout
        )

        sock.settimeout(timeout)

        data = sock.recv(1024)

        sock.close()

        if not data:
            return None

        banner = data.decode(
            "utf-8",
            errors="replace"
        ).strip()

        if not banner:
            return None

        return (
            banner
            .replace("\r", "")
            .replace("\n", " ")
        )

    except (
        socket.timeout,
        ConnectionRefusedError,
        OSError
    ):
        return None


def inspect_http(target, port):
    print(
        f"    [*] Inspecting HTTP service "
        f"on port {port}..."
    )

    try:
        sock = socket.create_connection(
            (target, port),
            timeout=2
        )

        request = (
            "HEAD / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        sock.sendall(
            request.encode()
        )

        response = sock.recv(
            8192
        ).decode(
            "utf-8",
            errors="replace"
        )

        sock.close()

        lines = response.splitlines()

        status = (
            lines[0]
            if lines
            else "No response"
        )

        headers = {}

        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(
                    ":",
                    1
                )

                headers[
                    name.strip().lower()
                ] = value.strip()

        server = headers.get(
            "server",
            "Not disclosed"
        )

        print(
            f"    [+] HTTP response: {status}"
        )

        print(
            f"    [+] Server: {server}"
        )

        return status, headers

    except (
        socket.timeout,
        ConnectionRefusedError,
        OSError
    ) as error:

        print(
            f"    [-] HTTP inspection failed: "
            f"{error}"
        )

        return (
            "Inspection failed",
            {}
        )


def check_http_security(headers, port):
    findings = []

    if not headers:
        return findings

    if "server" in headers:
        findings.append({
            "severity": "INFO",
            "title": "Server information disclosed",
            "details": (
                f"Server header: "
                f"{headers['server']}"
            )
        })

    if "x-content-type-options" not in headers:
        findings.append({
            "severity": "LOW",
            "title": "Missing X-Content-Type-Options",
            "details": (
                "The response does not include "
                "X-Content-Type-Options."
            )
        })

    if "x-frame-options" not in headers:
        findings.append({
            "severity": "LOW",
            "title": "Missing X-Frame-Options",
            "details": (
                "The response does not include "
                "X-Frame-Options."
            )
        })

    if "content-security-policy" not in headers:
        findings.append({
            "severity": "LOW",
            "title": "Missing Content-Security-Policy",
            "details": (
                "The response does not include "
                "a Content-Security-Policy header."
            )
        })

    if port == 443:
        if "strict-transport-security" not in headers:
            findings.append({
                "severity": "MEDIUM",
                "title": "Missing HSTS",
                "details": (
                    "HTTPS service does not advertise "
                    "Strict-Transport-Security."
                )
            })

    return findings


def check_http_methods(target, port):
    findings = []

    try:
        sock = socket.create_connection(
            (target, port),
            timeout=2
        )

        request = (
            "OPTIONS / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        sock.sendall(
            request.encode()
        )

        response = sock.recv(
            4096
        ).decode(
            "utf-8",
            errors="replace"
        )

        sock.close()

        allow = None

        for line in response.splitlines():
            if line.lower().startswith("allow:"):
                allow = line.split(
                    ":",
                    1
                )[1].strip()
                break

        if allow:
            print(
                f"    [+] Allowed HTTP methods: {allow}"
            )

            findings.append({
                "severity": "INFO",
                "title": "HTTP methods advertised",
                "details": (
                    f"Allow header: {allow}"
                )
            })

        return findings

    except (
        socket.timeout,
        ConnectionRefusedError,
        OSError
    ):
        return findings


def run_security_checks(
    target,
    port,
    headers
):
    findings = []

    print(
        "    [*] Running basic security checks..."
    )

    findings.extend(
        check_http_security(
            headers,
            port
        )
    )

    findings.extend(
        check_http_methods(
            target,
            port
        )
    )

    if findings:
        for finding in findings:
            print(
                f"    [{finding['severity']}] "
                f"{finding['title']}"
            )
    else:
        print(
            "    [+] No basic findings detected."
        )

    return findings


def scan_ports(
    target,
    ports,
    timeout
):
    results = []

    print(
        f"\n[*] Scanning "
        f"{len(ports)} port(s)..."
    )

    print(
        f"[*] Connection timeout: "
        f"{timeout} second(s)"
    )

    for port in ports:

        print(
            f"[*] Checking port {port}...",
            end=" "
        )

        if scan_port(
            target,
            port,
            timeout
        ):

            service = detect_service(
                port
            )

            print(
                f"OPEN ({service})"
            )

            http_status = None
            headers = {}
            server = None
            banner = None
            findings = []

            if port in HTTP_PORTS:

                http_status, headers = (
                    inspect_http(
                        target,
                        port
                    )
                )

                server = headers.get(
                    "server"
                )

                findings = run_security_checks(
                    target,
                    port,
                    headers
                )

            else:

                print(
                    "    [*] Attempting "
                    "banner detection..."
                )

                banner = grab_banner(
                    target,
                    port
                )

                if banner:
                    print(
                        f"    [+] Banner: "
                        f"{banner}"
                    )
                else:
                    print(
                        "    [-] No banner received."
                    )

            results.append({
                "port": port,
                "service": service,
                "banner": banner,
                "http_status": http_status,
                "server": server,
                "findings": findings
            })

        else:

            print("CLOSED")

    return results


def print_summary(
    target,
    hostname,
    ports,
    results,
    timeout,
    mode
):
    print(
        "\n" + "=" * 65
    )

    print(
        "                        SCAN SUMMARY"
    )

    print(
        "=" * 65
    )

    print(
        f"Target         : {target}"
    )

    print(
        f"Hostname       : {hostname}"
    )

    print(
        f"Scan mode      : {mode}"
    )

    print(
        f"Ports scanned  : {len(ports)}"
    )

    print(
        f"Timeout        : "
        f"{timeout} second(s)"
    )

    print(
        f"Open ports     : {len(results)}"
    )

    total_findings = sum(
        len(result["findings"])
        for result in results
    )

    print(
        f"Findings       : {total_findings}"
    )

    if results:

        print(
            "\nOpen Services:"
        )

        for result in results:

            print(
                f"  - Port "
                f"{result['port']}: "
                f"{result['service']}"
            )

            if result["banner"]:
                print(
                    f"    Banner: "
                    f"{result['banner']}"
                )

            if result["http_status"]:
                print(
                    f"    HTTP: "
                    f"{result['http_status']}"
                )

            if result["server"]:
                print(
                    f"    Server: "
                    f"{result['server']}"
                )

            if result["findings"]:

                print(
                    "    Security findings:"
                )

                for finding in result[
                    "findings"
                ]:

                    print(
                        f"      "
                        f"[{finding['severity']}] "
                        f"{finding['title']}"
                    )

    else:

        print(
            "\nNo open ports found."
        )

    print(
        "=" * 65
    )


def save_text_report(
    target,
    hostname,
    ports,
    results,
    start_time,
    timeout,
    mode
):
    os.makedirs(
        "reports",
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        f"reports/"
        f"scan_{target}_{timestamp}.txt"
    )

    with open(
        filename,
        "w"
    ) as report:

        report.write(
            "=" * 65 + "\n"
        )

        report.write(
            f"RedScan v{VERSION} Scan Report\n"
        )

        report.write(
            "=" * 65 + "\n\n"
        )

        report.write(
            f"Target: {target}\n"
        )

        report.write(
            f"Hostname: {hostname}\n"
        )

        report.write(
            f"Scan mode: {mode}\n"
        )

        report.write(
            "Scan time: "
            f"{start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        )

        report.write(
            f"Ports scanned: {len(ports)}\n"
        )

        report.write(
            f"Timeout: {timeout} second(s)\n"
        )

        report.write(
            f"Open ports: {len(results)}\n"
        )

        total_findings = sum(
            len(result["findings"])
            for result in results
        )

        report.write(
            f"Findings: {total_findings}\n\n"
        )

        for result in results:

            report.write(
                f"- Port {result['port']}: "
                f"{result['service']}\n"
            )

            if result["banner"]:
                report.write(
                    f"  Banner: "
                    f"{result['banner']}\n"
                )

            if result["http_status"]:
                report.write(
                    f"  HTTP: "
                    f"{result['http_status']}\n"
                )

            if result["server"]:
                report.write(
                    f"  Server: "
                    f"{result['server']}\n"
                )

            for finding in result["findings"]:
                report.write(
                    f"  [{finding['severity']}] "
                    f"{finding['title']}\n"
                )

                report.write(
                    f"    {finding['details']}\n"
                )

            report.write("\n")

    print(
        f"[+] Text report saved: {filename}"
    )

    return filename


def save_json_report(
    target,
    hostname,
    ports,
    results,
    start_time,
    timeout,
    mode
):
    os.makedirs(
        "reports",
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        f"reports/"
        f"scan_{target}_{timestamp}.json"
    )

    total_findings = sum(
        len(result["findings"])
        for result in results
    )

    report_data = {
        "redscan_version": VERSION,
        "target": target,
        "hostname": hostname,
        "scan_mode": mode,
        "scan_time": start_time.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "ports_scanned": ports,
        "timeout_seconds": timeout,
        "open_port_count": len(results),
        "finding_count": total_findings,
        "open_ports": results
    }

    with open(
        filename,
        "w"
    ) as report:

        json.dump(
            report_data,
            report,
            indent=4
        )

    print(
        f"[+] JSON report saved: {filename}"
    )

    return filename


def main():

    parser = argparse.ArgumentParser(
        description=(
            "RedScan - "
            "Authorized Security Scanner"
        )
    )

    parser.add_argument(
        "target",
        help=(
            "Target IPv4 or IPv6 address"
        )
    )

    parser.add_argument(
        "--mode",
        choices=[
            "quick",
            "web",
            "custom"
        ],
        default="quick",
        help=(
            "Scan mode: quick, web, "
            "or custom "
            "(default: quick)"
        )
    )

    parser.add_argument(
        "--ports",
        default=None,
        help=(
            "Custom ports, e.g. "
            "22,80,443 or 20-25"
        )
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help=(
            "TCP connection timeout "
            "in seconds "
            "(default: 1.0)"
        )
    )

    parser.add_argument(
        "--format",
        choices=[
            "txt",
            "json",
            "both"
        ],
        default="txt",
        help=(
            "Report format: txt, json, "
            "or both (default: txt)"
        )
    )

    args = parser.parse_args()

    show_banner()

    if not validate_target(
        args.target
    ):

        print(
            f"\n[-] Invalid IP address: "
            f"{args.target}"
        )

        return

    if args.timeout <= 0:

        print(
            "\n[-] Timeout must be "
            "greater than 0."
        )

        return

    if args.mode == "custom":

        if not args.ports:

            print(
                "\n[-] Custom mode requires "
                "--ports."
            )

            print(
                "    Example: "
                "--mode custom "
                "--ports 20-25"
            )

            return

        port_string = args.ports

    elif args.ports:

        port_string = args.ports

    else:

        port_string = (
            SCAN_MODES[args.mode]
        )

    try:

        ports = parse_ports(
            port_string
        )

    except ValueError as error:

        print(
            f"\n[-] {error}"
        )

        return

    if not ports:

        print(
            "\n[-] No valid ports specified."
        )

        return

    start_time = datetime.now()

    print(
        f"\n[*] Target: "
        f"{args.target}"
    )

    print(
        f"[*] Scan mode: "
        f"{args.mode}"
    )

    print(
        f"[*] Ports: "
        f"{port_string}"
    )

    print(
        f"[*] Timeout: "
        f"{args.timeout} second(s)"
    )

    print(
        f"[*] Report format: "
        f"{args.format}"
    )

    hostname, aliases = (
        reverse_dns_lookup(
            args.target
        )
    )

    check_reachability(
        args.target
    )

    results = scan_ports(
        args.target,
        ports,
        args.timeout
    )

    print_summary(
        args.target,
        hostname,
        ports,
        results,
        args.timeout,
        args.mode
    )

    if args.format in ["txt", "both"]:

        save_text_report(
            args.target,
            hostname,
            ports,
            results,
            start_time,
            args.timeout,
            args.mode
        )

    if args.format in ["json", "both"]:

        save_json_report(
            args.target,
            hostname,
            ports,
            results,
            start_time,
            args.timeout,
            args.mode
        )


if __name__ == "__main__":
    main()

