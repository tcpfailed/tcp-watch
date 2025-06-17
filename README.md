![image](https://github.com/user-attachments/assets/2c06d2d7-0592-40b0-95db-dd6e0b621aa2)
# TCP Watch v1.0.2
![License](https://img.shields.io/badge/license-Custom%20BSD-blue)
![Version](https://img.shields.io/badge/version-1.0.2-green)
![Go Version](https://img.shields.io/badge/Go-1.20+-00ADD8)

A real-time network monitoring & DDoS protection tool written in Go, featuring live traffic analysis, attack detection, and system resource monitoring.

- ## Improvements
  - Fixed flags that was not detecting
  - Fixed tcp dump error displaying in tcp-watch
  - Improved BPF creation and handling
  - Improved display on blacklisted ips. Now clears the ips being displayed on screen when it reaches the end of the list to read. 
  - Automatically finds your default interface and utilizes it 
  - Added small ascii loading animation
  - More attack method detections
  - Source ports coming from harmful ips are now more accurate and stable
  - Added current interface to main ui
  - Working on themes, possibly licenses (soon)
  - Tcp dump, bpf work 2x as fast now at blocking traffic
  - Fixed error messages while running when resources get exhausted, to help it not spam your terminal or bug the ui
  - All ports should get detected now for traffic, this means no effort to edit default set port 22 inside the file, you can now leave default and still read traffic from other ports
  - Slightly enhanced the graph, memory, traffic totals to be more stable
  - Now requires no extra fields can just run it at default ttl for time of reloading on the script
  - Improved & cleaned up a good chunk of the code 
  - Improved cpu usage, resource consumption now being easier on startup for first time, when running
  - Improved and used better and newer code functions for all you geeks out there
  - More math logic has been added to help calculate certain functions more accurately
  - Fixed over half the bugs
  - Implemented permanent and semi permanent logs, one for a quick and easy display of attacking ips via tcp-watch that proceeds to flush, just mainly meant to allocate quick attack logs to. The other one is for permanent logs to view to help create filters, manual-bpf, attack & malicious traffic patches
  - Fixed static data and replaced with real server data. This static data was from the beta/test version of TCP-WATCH
  - Planning to add automatic malicious ip reporting for ips that are logged and it automatically uses their asn to find their providers abuse email to be more efficient at getting attacks servers banned, unless they are bulletproof of course 

# 🧠 Help
If you get an error **[./tcpwatch.go:552:13: duplicate key "IP" in map literal]** thats just due to you not putting your server ip in on line 571. You need to replace one of the "IP" literals with your ssh ip. This feature is so that tcp dump or any other protection measure doesn't accidentally blacklist your server ip and you should probably add yourself unless your adding ip tables, which this script does not interfer with ip tables just adds the malicious ips, ignores the ips you set in this field to your tables similar to an ip set.

![image](https://github.com/user-attachments/assets/03efc316-0670-4085-801b-978c0a35f65e)

# 🧠 LOGS
The blacklistedips.txt is a simple temporary log file for displaying it to the user (you) its just something the logs can quickly allocate to & be ready quickly so it can list all ips in the attacking ips section and flush it when its done reading / displaying so its more stable. 
![image](https://github.com/user-attachments/assets/3e482a15-9d7c-4bf2-8757-0ebe606b2f19)

when running TCP-WATCH, the blacklistedips.log works same as the .txt version but the .log is meant to keep long-term logs on all ips that have attacked and their methods, src ports, dst ports, size, connections etc. Its everything you need to improve your server infastructure without ever flushing the ips! Examples below
![image](https://github.com/user-attachments/assets/2cbb60de-0ade-4425-a8b5-fbcffe4417a0)

![image](https://github.com/user-attachments/assets/b907c214-0176-4fa5-89aa-18e0d75a02a6)

# 🚀 Features

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
  - Tcpdump
  - Iptables

- **System Monitoring**
  - CPU usage tracking
  - RAM utilization
  - System resource analysis
  - Process monitoring
  - Traffic monitoring
  - Traffic graph

- **Web Interface**
  - Real-time traffic graphs
  - System statistics
  - Blocked IP management
  - Attack logs visualization

# 📋 Requirements

- Golang 1.20 or higher
- libpcap-dev
- Sudo privileges (pcap)


## 1. Update packages
sudo apt-get update             
sudo yum update -y               
## or: sudo dnf update -y         

## 2. Install screen
sudo apt install screen          
sudo yum install screen         

## 3. Install Go
sudo apt install golang-go       
sudo yum install golang          

## 4. Install git
sudo apt install git             
sudo yum install git             

## 5. Install libpcap
sudo apt install libpcap-dev     
sudo yum install libpcap-devel   

## 6. Install apache
sudo apt install apache2         
sudo yum install httpd         

## 7. Install node & npm
sudo apt install npm            
sudo yum install nodejs          

## 8. Initialize node packages
npm init -y && npm install express ws

## 9. Clone the repository
git clone https://github.com/tcpfailed/tcp-watch/

## 10. Install iptables persistent/save service
sudo apt install iptables-persistent       
sudo yum install iptables-services        
sudo service iptables save                

## 11. Install tcpdump
sudo apt install tcpdump                   
sudo yum install tcpdump                   

## 12. CD into the project directory
cd tcp-watch

## 13. Initialize Go
go mod init tcpwatch

## 14. Fetch Go dependencies
go mod tidy

## 15. Run the Go program
go run tcpwatch.go

# 🔧 Compiling **(Optional)**

go build tcpwatch.go

## Basic usage
go run tcpwatch.go (non built)
./tcpwatch.go (built)

## Web usage
do step 5 & 6 & 7 and then do screen node index.js


# 🎯 Key Features

    Live traffic monitoring
    Automatic DDoS protection
    IP blacklisting system
    Resource usage tracking
    Web interface for monitoring
    Attack pattern recognition
    System performance analysis
    BPF creation from attacks

# 🌐 Web Interface

    Real-time traffic graphs
    System statistics
    Blocked IP management
    Attack logs

# ⚙️ Configuration

Default configuration provides:

    3000 PPS threshold for filtering
    Automatic IP blocking
    60-second PCAP captures during attacks
    Whitelisted system IPs protection
    Auto BPF creation

# 📝 License

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
<img width="316" alt="Screenshot 2025-06-17 030746" src="https://github.com/user-attachments/assets/032827fa-4d53-4e2b-b059-8483f266762d" />

