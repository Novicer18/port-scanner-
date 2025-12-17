#!/usr/bin/env python3
"""
Advanced Interactive Port Scanner with Nmap Integration
Author: Security Engineer / Network Automation Specialist
Description: Fast, comprehensive port scanning tool using Nmap for TCP port discovery
"""

import subprocess
import sys
import re
import ipaddress
import socket
from datetime import datetime

def validate_ip_address(ip_str):
    """
    Validate if the input is a valid IP address or hostname
    
    Args:
        ip_str (str): IP address or hostname to validate
        
    Returns:
        tuple: (bool, str) - (is_valid, error_message_or_ip)
    """
    if not ip_str or ip_str.strip() == "":
        return False, "Input cannot be empty"
    
    ip_str = ip_str.strip()
    
    # Try to validate as IP address first
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return True, str(ip_obj)
    except ValueError:
        pass
    
    # Try to validate as hostname
    try:
        # Try DNS resolution
        socket.gethostbyname(ip_str)
        return True, ip_str
    except socket.error:
        return False, f"Invalid IP address or unresolvable hostname: {ip_str}"

def check_nmap_installed():
    """
    Check if Nmap is installed on the system
    
    Returns:
        bool: True if Nmap is installed, False otherwise
    """
    try:
        # Try to run nmap --version to check if it's installed
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

def format_port_results(nmap_output):
    """
    Parse and format Nmap output into a clean, structured format
    
    Args:
        nmap_output (str): Raw Nmap output
        
    Returns:
        dict: Formatted results with scan metadata and ports
    """
    results = {
        'scan_start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'target': '',
        'ports': [],
        'summary': {
            'total_ports_scanned': 0,
            'open_ports': 0,
            'filtered_ports': 0,
            'closed_ports': 0
        }
    }
    
    # Parse Nmap output
    lines = nmap_output.split('\n')
    port_pattern = re.compile(r'^(\d+)/(tcp|udp)\s+(\w+)\s+(.+)$')
    
    for line in lines:
        line = line.strip()
        
        # Extract target information
        if line.startswith('Nmap scan report for '):
            results['target'] = line.replace('Nmap scan report for ', '')
        
        # Parse port information
        port_match = port_pattern.match(line)
        if port_match:
            port, protocol, state, service = port_match.groups()
            
            port_info = {
                'port': int(port),
                'protocol': protocol,
                'state': state,
                'service': service.strip()
            }
            
            results['ports'].append(port_info)
            
            # Update summary statistics
            results['summary']['total_ports_scanned'] += 1
            if state == 'open':
                results['summary']['open_ports'] += 1
            elif state == 'filtered':
                results['summary']['filtered_ports'] += 1
            elif state == 'closed':
                results['summary']['closed_ports'] += 1
    
    return results

def display_results(results):
    """
    Display scan results in a clean, structured format
    
    Args:
        results (dict): Formatted scan results
    """
    print("\n" + "="*70)
    print("PORT SCAN RESULTS")
    print("="*70)
    
    print(f"\nTarget: {results['target']}")
    print(f"Scan Started: {results['scan_start_time']}")
    print(f"Scan Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    print(f"\n{'-'*70}")
    print("PORT SUMMARY:")
    print(f"  Total Ports Scanned: {results['summary']['total_ports_scanned']}")
    print(f"  Open Ports: {results['summary']['open_ports']}")
    print(f"  Filtered Ports: {results['summary']['filtered_ports']}")
    print(f"  Closed Ports: {results['summary']['closed_ports']}")
    
    if results['ports']:
        print(f"\n{'-'*70}")
        print("DETAILED PORT INFORMATION:")
        print(f"{'-'*70}")
        print(f"{'PORT':<10} {'PROTOCOL':<10} {'STATE':<10} {'SERVICE':<30}")
        print(f"{'-'*70}")
        
        # Sort ports by port number
        sorted_ports = sorted(results['ports'], key=lambda x: x['port'])
        
        for port_info in sorted_ports:
            if port_info['state'] == 'open':  # Only show open ports for clarity
                print(f"{port_info['port']:<10} {port_info['protocol']:<10} "
                      f"{port_info['state']:<10} {port_info['service'][:30]:<30}")
    
    # Show all ports if no open ports found
    if results['summary']['open_ports'] == 0 and results['ports']:
        print("\nNo open ports found. Showing all scanned ports:")
        print(f"{'-'*70}")
        print(f"{'PORT':<10} {'PROTOCOL':<10} {'STATE':<10} {'SERVICE':<30}")
        print(f"{'-'*70}")
        
        sorted_ports = sorted(results['ports'], key=lambda x: x['port'])
        for port_info in sorted_ports:
            print(f"{port_info['port']:<10} {port_info['protocol']:<10} "
                  f"{port_info['state']:<10} {port_info['service'][:30]:<30}")
    
    print("\n" + "="*70)
    print("SCAN COMPLETED SUCCESSFULLY")
    print("="*70)

def perform_nmap_scan(target):
    """
    Perform comprehensive Nmap scan using system Nmap
    
    Args:
        target (str): IP address or hostname to scan
        
    Returns:
        tuple: (bool, str) - (success, output_or_error_message)
    """
    try:
        print(f"\n[+] Starting comprehensive scan of {target}...")
        print(f"[+] Scanning all 65535 TCP ports (this may take a few minutes)...")
        
        # Nmap command for fast, comprehensive TCP scan
        # Options explained:
        # -p- : Scan all ports (1-65535)
        # -T4 : Aggressive timing template for faster scans
        # -sS : TCP SYN scan (default, doesn't complete TCP handshake)
        # --min-rate 1000 : Send packets no slower than 1000 per second
        # -n : No DNS resolution (faster)
        # --open : Only show open ports in output
        # -oG - : Output in greppable format to stdout
        
        nmap_command = [
            "nmap",
            "-p-",           # Scan all ports
            "-T4",           # Aggressive timing
            "-sS",           # SYN scan (stealth)
            "--min-rate", "1000",  # Minimum packet rate
            "-n",            # No DNS resolution
            "--open",        # Only show open ports
            target
        ]
        
        print(f"[+] Command: {' '.join(nmap_command)}")
        print("[+] Please wait while scanning in progress...\n")
        
        # Execute Nmap scan with timeout
        process = subprocess.run(
            nmap_command,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
            check=True
        )
        
        return True, process.stdout
        
    except subprocess.TimeoutExpired:
        return False, "Scan timed out after 5 minutes. Target may be blocking scans or network issues."
    except subprocess.CalledProcessError as e:
        return False, f"Nmap scan failed with error: {e.stderr}"
    except Exception as e:
        return False, f"Unexpected error during scan: {str(e)}"

def interactive_scan():
    """
    Main interactive scanning function
    """
    print("\n" + "="*70)
    print("ADVANCED PORT SCANNER WITH NMAP INTEGRATION")
    print("="*70)
    print("\n⚠️  WARNING: Only scan systems you own or have permission to scan.")
    print("   Unauthorized scanning may be illegal in your jurisdiction.")
    print("="*70)
    
    # Check if Nmap is installed
    print("\n[+] Checking if Nmap is installed...")
    if not check_nmap_installed():
        print("\n❌ ERROR: Nmap is not installed or not in PATH.")
        print("Please install Nmap from: https://nmap.org/download.html")
        print("\nFor Ubuntu/Debian: sudo apt-get install nmap")
        print("For CentOS/RHEL: sudo yum install nmap")
        print("For macOS: brew install nmap")
        sys.exit(1)
    
    print("[✓] Nmap is installed and available.")
    
    # Get target input
    print("\n" + "="*70)
    print("ENTER IP ADDRESS OR HOSTNAME TO BE SCANNED")
    print("="*70)
    
    while True:
        target = input("\nTarget IP/Hostname: ").strip()
        
        is_valid, validation_result = validate_ip_address(target)
        
        if is_valid:
            target = validation_result
            break
        else:
            print(f"\n❌ Invalid input: {validation_result}")
            print("Please enter a valid IP address (e.g., 192.168.1.1) or hostname (e.g., example.com)")
            print("Example: scanme.nmap.org (for testing purposes)")
    
    # Confirm scan
    print(f"\n[+] Target validated: {target}")
    print("\n⚠️  This scan will:")
    print("   - Scan ALL 65535 TCP ports")
    print("   - Use fast scanning techniques")
    print("   - May trigger security alerts on the target")
    
    confirm = input("\nDo you want to proceed with the scan? (yes/no): ").strip().lower()
    
    if confirm not in ['yes', 'y']:
        print("\n[!] Scan cancelled by user.")
        sys.exit(0)
    
    # Perform scan
    try:
        success, scan_result = perform_nmap_scan(target)
        
        if success:
            # Format and display results
            formatted_results = format_port_results(scan_result)
            display_results(formatted_results)
            
            # Optional: Save results to file
            save_option = input("\nDo you want to save the results to a file? (yes/no): ").strip().lower()
            if save_option in ['yes', 'y']:
                filename = f"port_scan_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(filename, 'w') as f:
                    f.write("PORT SCAN REPORT\n")
                    f.write("="*50 + "\n")
                    f.write(f"Target: {target}\n")
                    f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("\nRAW NMAP OUTPUT:\n")
                    f.write("="*50 + "\n")
                    f.write(scan_result)
                    f.write("\n" + "="*50 + "\n")
                    f.write("FORMATTED RESULTS:\n")
                    f.write("="*50 + "\n")
                    
                    for port_info in formatted_results['ports']:
                        if port_info['state'] == 'open':
                            f.write(f"Port {port_info['port']}/{port_info['protocol']}: "
                                   f"{port_info['state']} - {port_info['service']}\n")
                
                print(f"[✓] Results saved to: {filename}")
        
        else:
            print(f"\n❌ Scan failed: {scan_result}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        sys.exit(1)

def main():
    """
    Main entry point
    """
    try:
        interactive_scan()
    except KeyboardInterrupt:
        print("\n\n[!] Program terminated by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()
