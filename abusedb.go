package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	apiKey := "f61b40b42407c8ea32f4ad7f5742b79405c803677810d96c55da70d3e357537bd80a79ba14ef2cce"

	file, err := os.Open("blacklistedips.log")
	if err != nil {
		fmt.Println("Failed to open log file:", err)
		return
	}
	defer file.Close()

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "IP: ") {
			parts := strings.Split(line, "IP: ")
			if len(parts) < 2 {
				continue
			}
			ip := strings.Fields(parts[1])[0]
			if seen[ip] {
				continue 
			}
			seen[ip] = true

			data := fmt.Sprintf("ip=%s&categories=15,4,23&comment=TCP Watch Auto Report: Detected a ddos attack and suspicious activity from this IP, indicating a potential attack", ip)
			req, err := http.NewRequest("POST", "https://api.abuseipdb.com/api/v2/report", bytes.NewBufferString(data))
			if err != nil {
				fmt.Println("Failed to build request for", ip, ":", err)
				continue
			}
			req.Header.Set("Key", apiKey)
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				fmt.Println("Error reporting", ip, ":", err)
				continue
			}
			resp.Body.Close()

			fmt.Println("Reported:", ip)
			time.Sleep(1200 * time.Millisecond) 
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
	}
}
