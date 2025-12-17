#!/usr/bin/env python3

import subprocess
import shutil
import sys
import ipaddress
import socket
import xml.etree.ElementTree as ET


def check_nmap_installed():
    """Ensure Nmap is available on the system."""
    if not shutil.which("nmap"):
        print("[!] ERROR: Nmap is not installed or not in PATH.")
        print("    Install it from https://nmap.org/download.html")
        sys.exit(1)


def validate_target(target):
    """
    Validate IP address or hostname.
    Returns True if valid, otherwise exits.
    """
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        # Not an IP, try resolving as hostname
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            print("[!] ERROR: Invalid IP address or hostname.")
            sys.exit(1)


def run_nmap_scan(target):
    """
    Run a fast, full TCP port scan using Nmap.
    Returns parsed XML root.
    """
    print(f"\n[*] Scanning started against target: {target}")
    print("[*] Scanning all 65,535 TCP ports. Please wait...\n")

    command = [
        "nmap",
        "-p-",
        "-T4",
        "--min-rate", "1000",
        "-sT",
        "-oX", "-",
        target
    ]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print("[!] ERROR: Nmap scan failed.")
        print(e.stderr.strip())
        sys.exit(1)

    return ET.fromstring(result.stdout)


def parse_results(xml_root):
    """
    Extract open ports, state, and service name from Nmap XML.
    """
    results = []

    for host in xml_root.findall("host"):
        status = host.find("status").get("state")
        if status != "up":
            print("[!] Target appears to be down or unreachable.")
            sys.exit(1)

        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):
            state = port.find("state").get("state")
            if state == "open":
                port_id = port.get("portid")
                service_elem = port.find("service")
                service = service_elem.get("name") if service_elem is not None else "unknown"

                results.append({
                    "port": port_id,
                    "state": state,
                    "service": service
                })

    return results


def display_results(results):
    """
    Display scan results in a clean, structured format.
    """
    print("\n========== SCAN RESULTS ==========")

    if not results:
        print("No open TCP ports found.")
    else:
        print(f"{'PORT':<10}{'STATE':<10}{'SERVICE'}")
        print("-" * 35)
        for entry in results:
            print(f"{entry['port']:<10}{entry['state']:<10}{entry['service']}")

    print("\n[*] Scanning completed successfully.")


def main():
    print("ENTER IP ADDRESS TO BE SCANNED")
    target = input("> ").strip()

    check_nmap_installed()
    validate_target(target)

    xml_root = run_nmap_scan(target)
    results = parse_results(xml_root)
    display_results(results)


if __name__ == "__main__":
    main()
