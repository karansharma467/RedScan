#!/usr/bin/env python3

import argparse
import ipaddress
import os
import socket
import subprocess
from datetime import datetime


def show_banner():
    print("=" * 45)
    print("          REDSCAN v0.9")
    print("    Authorized Security Scanner")
    print("=" * 45)


def validate_target(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def check_reachability(target):
    print(f"\n[*] Checking reachability of {target}...")

    result = subprocess.run(
        ["ping", "-c", "1", "-W", "2", target],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0


def parse_ports(port_input):
    ports = set()

    for item in port_input.split(","):
        item = item.strip()

        if "-" in item:
            try:
                start, end = map(int, item.split("-", 1))

                if start < 1 or end > 65535 or start > end:
                    raise ValueError

                ports.update(range(start, end + 1))

            except ValueError:
                print(f"[-] Invalid port range: {item}")
                return None

        else:
            try:
                port = int(item)

                if port < 1 or port > 65535:
                    raise ValueError

                ports.add(port)

            except ValueError:
                print(f"[-] Invalid port: {item}")
                return None

    return sorted(ports)


def scan_port(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    try:
        result = sock.connect_ex((target, port))
        return result == 0

    except socket.error:
        return False

    finally:
        sock.close()


def detect_service(port):
    try:
        service = socket.getservbyport(port, "tcp")
        return service.upper()

    except OSError:
        return "UNKNOWN"


def inspect_http(target, port):
    print(f"    [*] Inspecting HTTP service on port {port}...")

    try:
        sock = socket.create_connection((target, port), timeout=2)

        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        sock.sendall(request.encode())

        response = sock.recv(4096).decode(
            "utf-8",
            errors="replace"
        )

        sock.close()

        lines = response.splitlines()

        status_line = ""
        server_header = ""

        if lines:
            status_line = lines[0]
            print(f"    [+] HTTP response: {status_line}")

        for line in lines:
            if line.lower().startswith("server:"):
                server_header = line
                print(f"    [+] {line}")

        return status_line, server_header

    except (socket.timeout, socket.error):
        print("    [-] HTTP inspection failed.")
        return "", ""


def scan_ports(target, ports):
    print("\n[*] Starting TCP port scan...")
    print(f"[*] Ports to scan: {len(ports)}")

    open_ports = []

    for port in ports:
        print(f"[*] Checking port {port}...", end=" ")

        if scan_port(target, port):
            service = detect_service(port)

            print(f"OPEN ({service})")

            http_status = ""
            server_header = ""

            if service in ["HTTP", "HTTP-ALT"] or port in [80, 443, 8080, 8000]:
                http_status, server_header = inspect_http(target, port)

            open_ports.append(
                (port, service, http_status, server_header)
            )

        else:
            print("CLOSED")

    print("\n[*] Scan complete.")

    if open_ports:
        print("\n[+] Open ports and services:")

        for port, service, http_status, server_header in open_ports:
            print(f"    - Port {port}: {service}")

            if http_status:
                print(f"      {http_status}")

            if server_header:
                print(f"      {server_header}")

    else:
        print("\n[-] No open ports found.")

    return open_ports


def save_report(target, ports, open_ports):
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    filename = f"reports/scan_{target}_{timestamp}.txt"

    with open(filename, "w", encoding="utf-8") as report:
        report.write("REDSCAN SECURITY REPORT\n")
        report.write("=" * 50 + "\n\n")

        report.write(f"Target: {target}\n")
        report.write(f"Scan time: {datetime.now()}\n")
        report.write(f"Ports scanned: {len(ports)}\n\n")

        report.write("OPEN PORTS\n")
        report.write("-" * 50 + "\n")

        if open_ports:
            for port, service, http_status, server_header in open_ports:
                report.write(
                    f"Port {port}: {service}\n"
                )

                if http_status:
                    report.write(
                        f"  {http_status}\n"
                    )

                if server_header:
                    report.write(
                        f"  {server_header}\n"
                    )

        else:
            report.write("No open ports found.\n")

    print(f"\n[+] Report saved: {filename}")


def main():
    show_banner()

    parser = argparse.ArgumentParser(
        description="Authorized reconnaissance scanner"
    )

    parser.add_argument(
        "target",
        help="Target IPv4 address"
    )

    parser.add_argument(
        "--ports",
        default="22,80,443",
        help="Ports to scan. Example: 22,80,443 or 1-100"
    )

    args = parser.parse_args()

    print(f"\n[+] Target: {args.target}")

    if not validate_target(args.target):
        print("[-] Invalid IP address.")
        return

    print("[+] Valid IP address.")

    ports = parse_ports(args.ports)

    if ports is None:
        return

    if not ports:
        print("[-] No ports specified.")
        return

    if check_reachability(args.target):
        print("[+] Target is reachable.")
    else:
        print("[-] Target is not reachable.")
        return

    open_ports = scan_ports(args.target, ports)

    save_report(
        args.target,
        ports,
        open_ports
    )


if __name__ == "__main__":
    main()
