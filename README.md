![image](https://github.com/user-attachments/assets/8558b1ac-2f20-48d8-b2b8-469db8d09562)
My first big project, cleaner repository. ENJOY
# TCP Watch v1.0.1
![License](https://img.shields.io/badge/license-Custom%20BSD-blue)
![Version](https://img.shields.io/badge/version-1.0.1-green)
![Go Version](https://img.shields.io/badge/Go-1.20+-00ADD8)

A real-time network monitoring & DDoS protection tool written in Go, featuring live traffic analysis, attack detection, and system resource monitoring.

- ## **Change Log:**
  - Fixed flags that was not detecting
  - Fixed tcp dump error displaying in tcp-watch
  - Improved BPF creation and handling

## 🚀 Features

- **Real-time Network Monitoring**
  - Live packet analysis
  - Traffic visualization
  - Bandwidth usage tracking
  - Packets monitoring

- **DDoS Protection**
  - Automatic attack detection
  - IP blacklisting
  - Multiple attack pattern recognitions
  - Multiple types of ddos detection for robust detection
  - BPF creation system has been added

- **System Monitoring**
  - CPU usage tracking
  - RAM utilization
  - System resource analysis
  - Process monitoring
  - Traffic monitoring

- **Web Interface**
  - Real-time traffic graphs
  - System statistics
  - Blocked IP management
  - Attack logs visualization

## 📋 Requirements

- Golang 1.20 or higher
- libpcap-dev
- Root privileges (for packet capture)

# Install dependencies
sudo apt-get install libpcap-dev  # For Debian/Ubuntu
sudo yum install libpcap-devel    # For CentOS/RHEL

🔧 Installation

1. apt-get update
2. apt install screen
3. apt install golang-go
4. apt install git
5. apt install libpcap-dev
6. apt install apache2 (optional if you want the web verison aswell)
7. apt install npm
8. npm init -y && npm install express ws
9. git clone https://github.com/tcpfailed/tcp-watch/
10. cd tcp-watch
11. go mod init tcpwatch
12. go mod tidy
13. apt install iptables-persistent
14. apt install tcpdump
15. **edit line 686** : return ipv4.String() + ":22 **and change :22 to the port you want to monitor**
16. **edit line 695** : handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever) **and replace eth0 with your interface**
17. **edit line 499** : "IP": true, "IP":  true, **and replace the IP fields with the ips you dont want blocked or added to bpf. Add more if needed**
18. **edit line 162** : cmd := exec.Command("tcpdump", "-i", "eth0", rule) **and replace eth0 with your interface**
19. go run tcpwatch.go

🔧 Compiling

go build tcpwatch.go

# Basic usage
go run tcpwatch.go (non built)
./tcpwatch.go (built)

# Web usage
do step 5 & 6 & 7 and then do screen node index.js


🎯 Key Features

    Live traffic monitoring
    Automatic DDoS protection
    IP blacklisting system
    Resource usage tracking
    Web interface for monitoring
    Attack pattern recognition
    System performance analysis
    BPF creation from attacks

🌐 Web Interface

Access the web interface at http://your-server-ip:3000 for:

    Real-time traffic graphs
    System statistics
    Blocked IP management
    Attack logs

⚙️ Configuration

Default configuration provides:

    3000 PPS threshold for filtering
    Automatic IP blocking
    60-second PCAP captures during attacks
    Whitelisted system IPs protection
    Auto BPF creation

📝 License

Copyright (c) 2025 tcpfailed. All rights reserved.
Custom BSD License with Commercial Use Restriction.
See LICENSE for details.
🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
📞 Contact

    Author: tcpfailed
    Discord: tcprouting

⚠️ Disclaimer

This tool is for network monitoring and protection purposes only. Users are responsible for compliance with local laws and regulations.
