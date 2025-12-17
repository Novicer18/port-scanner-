# 🔍 Python Nmap Port Scanner

An interactive, fast, and ethical **Python-based TCP port scanning tool** that integrates directly with **Nmap** to perform full-range scans across all 65,535 TCP ports.  
Designed for **security engineers, ethical hackers, and network automation professionals**.

---

## 🚀 Features

- Interactive CLI-based interface
- Scans **all 65,535 TCP ports**
- Fast scanning using optimized Nmap timing options
- Detects and displays:
  - Open ports
  - Port states
  - Service names (when available)
- Clean, readable, structured terminal output
- Input validation for IP addresses and hostnames
- Clear status messages during execution
- Robust error handling:
  - Nmap not installed
  - Invalid target
  - Unreachable host

---

## 🧠 How It Works

1. Prompts the user to enter an IP address or hostname
2. Validates the input (IP format or resolvable hostname)
3. Executes an optimized full TCP port scan using Nmap
4. Parses Nmap XML output directly in memory
5. Displays discovered open ports and services in a structured table

---

## 📋 Requirements

### System Requirements
- **Python 3.7+**
- **Nmap** (must be installed and accessible via PATH)

### Install Nmap

**Linux (Debian/Ubuntu):**
```bash
sudo apt install nmap
-git clone https://github.com/yourusername/python-nmap-port-scanner.git
cd python-nmap-port-scanner
```
## how to run
```python3 port_scanner.py
```
