#!/bin/sh
wget "https://github.com/tcpfailed/tcp-watch/raw/main/tcpwatch.go" --no-check-certificate -O tcpwatch.go
echo "tcpwatch main file has been updated! | output: tcpwatch.go has been updated! |"
wget "https://github.com/tcpfailed/tcp-watch/raw/main/server.js" --no-check-certificate -O server.js
echo "tcpwatch web server has been updated! | output: server.js has been updated! |"
wget "https://github.com/tcpfailed/tcp-watch/raw/main/abusedb.go" --no-check-certificate -O abusedb.go
echo "tcpwatch abuse ip database report has been updated! | output: abusedb.go has been updated! |"
wget "https://github.com/tcpfailed/tcp-watch/raw/main/bpfmaker.go" --no-check-certificate -O bpfmaker.go
echo "tcpwatch bpf creation has been updated! | output: bpfmaker.go has been updated! |"


