#!/usr/bin/env python3

import argparse
import ipaddress
import socket
import subprocess


def show_banner():
    print("=" * 40)
    print("       REDSCAN v0.5")
    print(" Authorized Security Scanner")
    print("=" * 40)


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


def scan_port(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    try:
        result = sock.connect_ex((target, port))

        if result == 0:
            return True

        return False

    except socket.error:
        return False

    finally:
        sock.close()


def scan_ports(target, ports):
    print("\n[*] Starting TCP port scan...")

    for port in ports:
        print(f"[*] Checking port {port}...", end=" ")

        if scan_port(target, port):
            print("OPEN")
        else:
            print("CLOSED")


def main():
    show_banner()

    parser = argparse.ArgumentParser(
        description="Authorized reconnaissance scanner"
    )

    parser.add_argument(
        "target",
        help="Target IPv4 or IPv6 address"
    )

    args = parser.parse_args()

    print(f"\n[+] Target: {args.target}")

    if not validate_target(args.target):
        print("[-] Invalid IP address.")
        return

    print("[+] Valid IP address.")

    if check_reachability(args.target):
        print("[+] Target is reachable.")
    else:
        print("[-] Target is not reachable.")
        return

    ports = [22, 80, 443]

    scan_ports(args.target, ports)


if __name__ == "__main__":
    main()
