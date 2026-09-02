#!/usr/bin/env python3

import argparse
import ipaddress
import os
import socket
import subprocess
from datetime import datetime


VERSION = "1.3"


SCAN_MODES = {
    "quick": "22,80,443,8080",
    "web": "80,443,8000,8080,8443",
}


HTTP_PORTS = [80, 443, 8000, 8080, 8443]


def show_banner():
    print("=" * 60)
    print(f"                 REDSCAN v{VERSION}")
    print("          Authorized Security Scanner")
    print("=" * 60)


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
                start, end = map(int, part.split("-", 1))
            except ValueError:
                raise ValueError(f"Invalid port range: {part}")

            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")

            ports.update(range(start, end + 1))

        else:
            try:
                port = int(part)
            except ValueError:
                raise ValueError(f"Invalid port: {part}")

            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port: {part}")

            ports.add(port)

    return sorted(ports)


def scan_port(target, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target, port))
        return result == 0
    finally:
        sock.close()


def detect_service(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def grab_banner(target, port, timeout=2):
    """
    Attempt a passive TCP banner read.

    Some services send identifying information immediately
    after a TCP connection is established.
    """

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
        )

        banner = banner.strip()

        if not banner:
            return None

        return banner.replace("\r", "").replace("\n", " ")

    except (socket.timeout, ConnectionRefusedError, OSError):
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

        sock.sendall(
            b"HEAD / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Connection: close\r\n\r\n"
        )

        response = sock.recv(4096).decode(
            "utf-8",
            errors="replace"
        )

        sock.close()

        lines = response.splitlines()

        status = lines[0] if lines else "No response"
        server = "Not disclosed"

        for line in lines:
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
                break

        print(f"    [+] HTTP response: {status}")
        print(f"    [+] Server: {server}")

        return status, server

    except (socket.timeout, ConnectionRefusedError, OSError) as error:
        print(
            f"    [-] HTTP inspection failed: {error}"
        )
        return "Inspection failed", "Not available"


def scan_ports(target, ports, timeout):
    results = []

    print(f"\n[*] Scanning {len(ports)} port(s)...")
    print(
        f"[*] Connection timeout: "
        f"{timeout} second(s)"
    )

    for port in ports:
        print(
            f"[*] Checking port {port}...",
            end=" "
        )

        if scan_port(target, port, timeout):
            service = detect_service(port)

            print(f"OPEN ({service})")

            http_status = None
            server = None
            banner = None

            if port in HTTP_PORTS:
                http_status, server = inspect_http(
                    target,
                    port
                )
            else:
                print(
                    f"    [*] Attempting banner detection "
                    f"on port {port}..."
                )

                banner = grab_banner(
                    target,
                    port
                )

                if banner:
                    print(
                        f"    [+] Banner: {banner}"
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
                "server": server
            })

        else:
            print("CLOSED")

    return results


def print_summary(
    target,
    ports,
    results,
    timeout,
    mode
):
    print("\n" + "=" * 60)
    print("                     SCAN SUMMARY")
    print("=" * 60)

    print(f"Target         : {target}")
    print(f"Scan mode      : {mode}")
    print(f"Ports scanned  : {len(ports)}")
    print(f"Timeout        : {timeout} second(s)")
    print(f"Open ports     : {len(results)}")

    if results:
        print("\nOpen Services:")

        for result in results:
            print(
                f"  - Port {result['port']}: "
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

    else:
        print("\nNo open ports found.")

    print("=" * 60)


def save_report(
    target,
    ports,
    results,
    start_time,
    timeout,
    mode
):
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        f"reports/scan_{target}_{timestamp}.txt"
    )

    with open(filename, "w") as report:
        report.write("=" * 60 + "\n")
        report.write(
            f"RedScan v{VERSION} Scan Report\n"
        )
        report.write("=" * 60 + "\n\n")

        report.write(f"Target: {target}\n")
        report.write(f"Scan mode: {mode}\n")
        report.write(
            f"Scan time: "
            f"{start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        report.write(
            f"Ports scanned: {len(ports)}\n"
        )
        report.write(
            f"Timeout: {timeout} second(s)\n"
        )
        report.write(
            f"Open ports: {len(results)}\n\n"
        )

        if results:
            report.write("Open Services:\n")

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

        else:
            report.write(
                "No open ports found.\n"
            )

    print(
        f"\n[+] Report saved: {filename}"
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "RedScan - Authorized Security Scanner"
        )
    )

    parser.add_argument(
        "target",
        help="Target IPv4 or IPv6 address"
    )

    parser.add_argument(
        "--mode",
        choices=["quick", "web", "custom"],
        default="quick",
        help=(
            "Scan mode: quick, web, or custom "
            "(default: quick)"
        )
    )

    parser.add_argument(
        "--ports",
        default=None,
        help=(
            "Custom ports, e.g. 22,80,443 "
            "or 20-25"
        )
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help=(
            "TCP connection timeout in seconds "
            "(default: 1.0)"
        )
    )

    args = parser.parse_args()

    show_banner()

    if not validate_target(args.target):
        print(
            f"\n[-] Invalid IP address: "
            f"{args.target}"
        )
        return

    if args.timeout <= 0:
        print(
            "\n[-] Timeout must be greater than 0."
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
                "--mode custom --ports 20-25"
            )
            return

        port_string = args.ports

    elif args.ports:
        port_string = args.ports

    else:
        port_string = SCAN_MODES[args.mode]

    try:
        ports = parse_ports(port_string)
    except ValueError as error:
        print(f"\n[-] {error}")
        return

    if not ports:
        print(
            "\n[-] No valid ports specified."
        )
        return

    start_time = datetime.now()

    print(f"\n[*] Target: {args.target}")
    print(f"[*] Scan mode: {args.mode}")
    print(f"[*] Ports: {port_string}")
    print(
        f"[*] Timeout: "
        f"{args.timeout} second(s)"
    )

    check_reachability(args.target)

    results = scan_ports(
        args.target,
        ports,
        args.timeout
    )

    print_summary(
        args.target,
        ports,
        results,
        args.timeout,
        args.mode
    )

    save_report(
        args.target,
        ports,
        results,
        start_time,
        args.timeout,
        args.mode
    )


if __name__ == "__main__":
    main()
