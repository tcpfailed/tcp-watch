My first big project, cleaner repository. ENJOY
# TCP Watch v1.0.1
![License](https://img.shields.io/badge/license-Custom%20BSD-blue)
![Version](https://img.shields.io/badge/version-1.0.1-green)
![Go Version](https://img.shields.io/badge/Go-1.20+-00ADD8)

A real-time network monitoring & DDoS protection tool written in Go, featuring live traffic analysis, attack detection, and system resource monitoring.

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
2. apt install golang-go
3. apt install git
4. apt install libpcap-dev
5. apt install apache2 (optional if you want the web verison aswell)
6. apt install npm
7. npm init -y && npm install express ws
8. git clone https://github.com/TCPTHEGOAT/tcp-watch/
9. cd tcp-watch
10. go mod init tcpwatch
11. go mod tidy
12. edit line "966 : return ipv4.String() + ":22" **and change :22 to the port you want to monitor**
13. edit line "439 : handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)" **and replace eth0 with your interface**
14. go run tcpwatch.go

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
