#!/usr/bin/env python3

import argparse
import ipaddress
import socket
import subprocess


def show_banner():
    print("=" * 45)
    print("          REDSCAN v0.7")
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


def scan_ports(target, ports):
    print("\n[*] Starting TCP port scan...")
    print(f"[*] Ports to scan: {len(ports)}")

    open_ports = []

    for port in ports:
        print(f"[*] Checking port {port}...", end=" ")

        if scan_port(target, port):
            service = detect_service(port)

            print(f"OPEN ({service})")

            open_ports.append((port, service))
        else:
            print("CLOSED")

    print("\n[*] Scan complete.")

    if open_ports:
        print("\n[+] Open ports and services:")

        for port, service in open_ports:
            print(f"    - Port {port}: {service}")

    else:
        print("\n[-] No open ports found.")


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

    scan_ports(args.target, ports)


if __name__ == "__main__":
    main()
