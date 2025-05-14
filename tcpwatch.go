package main

import (
	"fmt"
	"io/ioutil"
  "bufio"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
  "time"
  "bytes"
  "encoding/json"
  "net/http"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
  "github.com/google/gopacket/pcapgo"
  "github.com/google/gopacket/layers"
)

const (
    VERSION = "v1.0.1"
    
    colorReset     = "\033[0m"
    colorRed       = "\033[31m"
    colorYellow    = "\033[33m"
    colorGreen     = "\033[32m"    
    colorLightGreen = "\033[92m"
    colorWhite     = "\033[97m"
    colorGray      = "\033[90m"
    colorYellowBg  = "\033[30;43m"
    colorBgReset   = "\033[49m"
    
    boxVertical    = "║"
    boxHorizontal  = "═"
    boxTopLeft     = "╔"
    boxTopRight    = "╗"
    boxBottomLeft  = "╚"
    boxBottomRight = "╝"
    boxTeeRight    = "╣"
    boxTeeLeft     = "╠"
    boxTeeDown     = "╦"
    boxTeeUp       = "╩"
    
    GRAPH_WIDTH  = 70
    GRAPH_HEIGHT = 25
    MIN_WIDTH    = 80
    MIN_HEIGHT   = 2
)

const (
    DISCORD_WEBHOOK_URL = "WEBHOOK"
)

const (
    ATTACK_SYN  = "SYN Flood"
    ATTACK_ACK  = "ACK Flood"
    ATTACK_FIN  = "FIN Flood"
    ATTACK_PSH  = "PSH Flood"
    ATTACK_FRAG = "Fragment Flood"
    ATTACK_AMP  = "Amplification"
    ATTACK_GRE  = "GRE Flood"
    ATTACK_STD  = "STD Flood"
    ATTACK_XMAS = "XMAS Scan"
    ATTACK_UDP  = "UDP Flood"
    ATTACK_ICMP = "ICMP Flood"
)

type DiscordMessage struct {
    Content     string `json:"content,omitempty"`
    Username    string `json:"username,omitempty"`
    AvatarURL   string `json:"avatar_url,omitempty"`
    Embeds      []DiscordEmbed `json:"embeds,omitempty"`
}

type DiscordEmbed struct {
    Title       string `json:"title,omitempty"`
    Description string `json:"description,omitempty"`
    Color       int    `json:"color,omitempty"`
    Fields      []DiscordField `json:"fields,omitempty"`
    Timestamp   string `json:"timestamp,omitempty"`
}

type DiscordField struct {
    Name   string `json:"name"`
    Value  string `json:"value"`
    Inline bool   `json:"inline,omitempty"`
}

type AttackState struct {
    isOngoing    bool
    startTime    time.Time
    peakPPS      int
    peakMbps     float64
    attackerIPs  map[string]bool
}

type AttackStats struct {
    synCount  int
    ackCount  int
    finCount  int
    pshCount  int
    fragCount int
    greCount  int
    udpCount  int
    icmpCount int
    xmasCount int
    ampFactor float64
}

type BlacklistEntry struct {
    IP          string
    SourcePort  string
    Protocol    string
    TargetPort  string
    Reason      string
    Timestamp   time.Time
}

type TCPWatch struct {
    startTime       time.Time
    packetsPerSec   int
    lastHighestPPS  int
    incomingIPs     int
    currentMbit     float64
    avgMbit         float64
    minMbit         float64
    maxMbit         float64
    totalGBytes     float64
    values          []float64
    systemIP        string
    cpuModel        string
    cpuUsage        float64
    ramUsed         int
    ramTotal        int
    ramFree         int
    prevCPUTotal    float64
    prevCPUIdle     float64
    blacklistedIPs  int
    isCapturing     bool
    currentPcapFile string
    blockedIPs      map[string]time.Time
    blacklistCount  int
    memoryUsed      float64
    memoryFree      float64
    swapUsed        float64
    swapFree        float64
    processCount    int
    attackingIPs    map[string]string
    lastDisplayIndex int
    whitelistedIPs  map[string]bool
    attackState     AttackState
    lastAlertTime   time.Time
}

func getTerminalSize() (width, height int) {
	cmd := exec.Command("stty", "size")
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()
	if err != nil {
		return MIN_WIDTH, MIN_HEIGHT
	}

	parts := strings.Split(strings.TrimSpace(string(out)), " ")
	if len(parts) != 2 {
		return MIN_WIDTH, MIN_HEIGHT
	}

	height, _ = strconv.Atoi(parts[0])
	width, _ = strconv.Atoi(parts[1])
	if height < MIN_HEIGHT {
		height = MIN_HEIGHT
	}
	if width < MIN_WIDTH {
		width = MIN_WIDTH
	}
	return width, height
}

func sendAttackAlert(tw *TCPWatch, newIP string, attackType string) error {
    message := DiscordMessage{
        Username:  "TCP Watch Alert",
        AvatarURL: "https://i.imgur.com/your-alert-icon.png",
        Embeds: []DiscordEmbed{
            {
                Title:       "Attack Detected",
                Description: fmt.Sprintf("Attack detected and mitigated by TCP Watch"),
                Color:       16711680, 
                Fields: []DiscordField{
                    {
                        Name:   "Traffic Stats",
                        Value:  fmt.Sprintf("```\nCurrent PPS: %d\nPeak PPS: %d\nCurrent Mbps: %.2f\nPeak Mbps: %.2f\n```",
                            tw.packetsPerSec,
                            tw.attackState.peakPPS,
                            tw.currentMbit,
                            tw.attackState.peakMbps),
                        Inline: false,
                    },
                    {
                        Name:   "New Attacker IP",
                        Value:  fmt.Sprintf("`%s`", newIP),
                        Inline: true,
                    },
                    {
                        Name:   "Attack Type",
                        Value:  fmt.Sprintf("`%s`", attackType),
                        Inline: true,
                    },
                    {
                        Name:   "Attack Duration",
                        Value:  fmt.Sprintf("`%s`", time.Since(tw.attackState.startTime).Round(time.Second)),
                        Inline: true,
                    },
                    {
                        Name:   "Total IPs Blocked",
                        Value:  fmt.Sprintf("`%d`", len(tw.attackState.attackerIPs)),
                        Inline: true,
                    },
                },
                Timestamp: time.Now().Format(time.RFC3339),
            },
        },
    }

    jsonData, err := json.Marshal(message)
    if err != nil {
        return err
    }

    resp, err := http.Post(DISCORD_WEBHOOK_URL, "application/json", bytes.NewBuffer(jsonData))
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    return nil
}

func setTerminalSize() {

    fmt.Printf("\x1b[8;65;204t")
    serverIP := getServerIP()
    fmt.Printf("\033]0;Welcome To TCP Watch V1.0.1 (In Development!) {%s}\007", serverIP)
}

func parseHexIP(hexIP string) string {
    if len(hexIP) < 8 {
        return ""
    }
    
    var ip [4]byte
    hex := hexIP[:8]
    fmt.Sscanf(hex, "%02x%02x%02x%02x", &ip[3], &ip[2], &ip[1], &ip[0])
    return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func detectAttack(ipData *struct {
    total     int
    portCount map[string]int
    protocol  string
    srcPort   string
    dstPort   string
    attacks   AttackStats
    lastBytes int64
}) string {
    if ipData.attacks.synCount > 100 {
        return ATTACK_SYN
    }
    if ipData.attacks.ackCount > 200 {
        return ATTACK_ACK
    }
    if ipData.attacks.finCount > 100 {
        return ATTACK_FIN
    }
    if ipData.attacks.pshCount > 100 {
        return ATTACK_PSH
    }
    if ipData.attacks.fragCount > 50 {
        return ATTACK_FRAG
    }
    if ipData.attacks.ampFactor > 10 {
        return ATTACK_AMP
    }
    if ipData.attacks.greCount > 50 {
        return ATTACK_GRE
    }
    if ipData.attacks.udpCount > 200 {
        return ATTACK_UDP
    }
    if ipData.attacks.xmasCount > 10 {
        return ATTACK_XMAS
    }
    if ipData.total > 300 && 
       (ipData.attacks.synCount > 0 || 
        ipData.attacks.ackCount > 0 || 
        ipData.attacks.udpCount > 0) {
        return ATTACK_STD
    }

    return ""
}

func newTCPWatch() *TCPWatch {
    tw := &TCPWatch{
        attackState: AttackState{
            isOngoing: false,
            attackerIPs: make(map[string]bool),
        },
        startTime:        time.Now(),
        values:          make([]float64, 0, GRAPH_WIDTH),
        minMbit:         math.MaxFloat64,
        ramTotal:        2000,
        isCapturing:     false,
        currentPcapFile: "",
        blockedIPs:      make(map[string]time.Time),
        blacklistCount:  0,
        attackingIPs:    make(map[string]string),
        lastDisplayIndex: 0,
        whitelistedIPs: map[string]bool{
            "REPLACEIP": true,
            "REPLACEIP":  true,
            "127.0.0.1":     true,
            "::1":           true,
        },
    }

    tw.systemIP = tw.getServerIP()
    tw.updateSystemInfo()
    return tw
}

func sendDiscordAlert(ip string, reason string, details string) error {
    message := DiscordMessage{
        Username:  "TCP Watch Alert",
        AvatarURL: "https://www.svgrepo.com/show/360745/shield-half.svg", 
        Embeds: []DiscordEmbed{
            {
                Title:       "Attack Detected",
                Description: "TCP Watch has detected and blocked an attack",
                Color:       16711680, 
                Fields: []DiscordField{
                    {
                        Name:   "Attacker IP",
                        Value:  fmt.Sprintf("`%s`", ip),
                        Inline: true,
                    },
                    {
                        Name:   "Attack Type",
                        Value:  fmt.Sprintf("`%s`", reason),
                        Inline: true,
                    },
                    {
                        Name:   "Details",
                        Value:  details,
                        Inline: false,
                    },
                },
                Timestamp: time.Now().Format(time.RFC3339),
            },
        },
    }

    jsonData, err := json.Marshal(message)
    if err != nil {
        return fmt.Errorf("error marshaling Discord message: %v", err)
    }

    resp, err := http.Post(DISCORD_WEBHOOK_URL, "application/json", bytes.NewBuffer(jsonData))
    if err != nil {
        return fmt.Errorf("error sending Discord alert: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
        body, _ := ioutil.ReadAll(resp.Body)
        return fmt.Errorf("Discord API error: %s - %s", resp.Status, string(body))
    }

    return nil
}

func (tw *TCPWatch) logBlacklistedIP(entry BlacklistEntry) {
    logFile := "blacklistedips.txt"
    
    logEntry := fmt.Sprintf("[%s] IP: %s | Source Port: %s | Protocol: %s | Target Port: %s | Reason: %s\n",
        entry.Timestamp.Format("01-02-06 15:04:05"),
        entry.IP,
        entry.SourcePort,
        entry.Protocol,
        entry.TargetPort,
        entry.Reason)

    f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return
    }
    defer f.Close()

    f.WriteString(logEntry)
}

func (tw *TCPWatch) blacklistIP(ip string, srcPort string, targetPort string, protocol string, reason string) error {
    if tw.whitelistedIPs[ip] {
        return nil 
    }
    if _, exists := tw.blockedIPs[ip]; exists {
        return nil
    }

    ipAddr := strings.Split(ip, ":")[0]
    cmd := exec.Command("iptables", "-A", "INPUT", "-s", ipAddr, "-j", "DROP")
    err := cmd.Run()
    if err != nil {
        return err
    }

    entry := BlacklistEntry{
        IP:         ip,
        SourcePort: srcPort,
        Protocol:   protocol,
        TargetPort: targetPort,
        Reason:     reason,
        Timestamp:  time.Now(),
    }

    tw.logBlacklistedIP(entry)

    if tw.attackState.isOngoing {
        if !tw.attackState.attackerIPs[ip] {
            tw.attackState.attackerIPs[ip] = true
            go func() {
                alertDetails := fmt.Sprintf(
                    "```\nTraffic Stats:\nCurrent PPS: %d\nPeak PPS: %d\n"+
                    "Current Mbps: %.2f\nPeak Mbps: %.2f\n"+
                    "Attack Duration: %s\nTotal IPs Blocked: %d\n\n"+
                    "Connection Details:\nSource Port: %s\nTarget Port: %s\n"+
                    "Protocol: %s\nReason: %s```",
                    tw.packetsPerSec, tw.attackState.peakPPS,
                    tw.currentMbit, tw.attackState.peakMbps,
                    time.Since(tw.attackState.startTime).Round(time.Second),
                    len(tw.attackState.attackerIPs),
                    srcPort, targetPort, protocol, reason)
                
                if err := sendDiscordAlert(ip, reason, alertDetails); err != nil {
                    fmt.Printf("Failed to send Discord alert: %v\n", err)
                }
            }()
        }
    }

    tw.blockedIPs[ip] = entry.Timestamp
    tw.blacklistCount++
    return nil
}


func startPacketCapture(interfaceName string, reason string) string {
    timestamp := time.Now().Format("01-02-06_15_04_05")
    filename := fmt.Sprintf("attack_dump_%s_%s.pcap", reason, timestamp)
    
    handle, err := pcap.OpenLive(interfaceName, 65535, true, pcap.BlockForever)
    if err != nil {
        return ""
    }
    defer handle.Close()

    f, err := os.Create(filename)
    if err != nil {
        return ""
    }
    defer f.Close()

    w := pcapgo.NewWriter(f)
    err = w.WriteFileHeader(65535, handle.LinkType())
    if err != nil {
        return ""
    }

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    timeout := time.After(60 * time.Second)

    for {
        select {
        case <-timeout:
            return filename
        default:
            packet, err := packetSource.NextPacket()
            if err != nil {
                continue
            }
            w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
        }
    }
}

func (tw *TCPWatch) updateSystemInfo() {
	if data, err := ioutil.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "model name") {
				tw.cpuModel = strings.TrimSpace(strings.Split(line, ":")[1])
				break
			}
		}
	}

	if data, err := ioutil.ReadFile("/proc/stat"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "cpu ") {
				fields := strings.Fields(line)
				if len(fields) > 4 {
					user, _ := strconv.ParseFloat(fields[1], 64)
					nice, _ := strconv.ParseFloat(fields[2], 64)
					system, _ := strconv.ParseFloat(fields[3], 64)
					idle, _ := strconv.ParseFloat(fields[4], 64)
					iowait, _ := strconv.ParseFloat(fields[5], 64)

					idle_total := idle + iowait
					total := user + nice + system + idle_total

					if tw.prevCPUTotal > 0 {
						idle_diff := idle_total - tw.prevCPUIdle
						total_diff := total - tw.prevCPUTotal
						tw.cpuUsage = (1.0 - idle_diff/total_diff) * 100
					}

					tw.prevCPUTotal = total
					tw.prevCPUIdle = idle_total
				}
				break
			}
		}
	}

	if data, err := ioutil.ReadFile("/proc/meminfo"); err == nil {
		var total, available uint64
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				total, _ = strconv.ParseUint(strings.Fields(line)[1], 10, 64)
			} else if strings.HasPrefix(line, "MemAvailable:") {
				available, _ = strconv.ParseUint(strings.Fields(line)[1], 10, 64)
			}
		}
		tw.ramTotal = int(total / 1024)
		tw.ramFree = int(available / 1024)
		tw.ramUsed = tw.ramTotal - tw.ramFree
	}
}

func (tw *TCPWatch) getServerIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipv4 := ipnet.IP.To4(); ipv4 != nil {
					return ipv4.String() + ":22"
				}
			}
		}
	}
	return ""
}

func (tw *TCPWatch) updateNetworkStats() {
    handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
    if err != nil {
        return
    }
    defer handle.Close()

    packets := 0
    var totalBytes int64
    packetsPerIP := make(map[string]*struct {
        total     int
        portCount map[string]int
        protocol  string
        srcPort   string
        dstPort   string
        attacks   AttackStats
        lastBytes int64
    })

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    packetChan := packetSource.Packets()
    timeout := time.After(time.Second)

    for {
        select {
        case packet := <-packetChan:
            if packet != nil {
                packets++
                totalBytes += int64(len(packet.Data()))

                ipLayer := packet.Layer(layers.LayerTypeIPv4)
                if ipLayer != nil {
                    ip, _ := ipLayer.(*layers.IPv4)
                    if ip != nil {
                        srcIP := ip.SrcIP.String()
                        
                        if _, exists := packetsPerIP[srcIP]; !exists {
                            packetsPerIP[srcIP] = &struct {
                                total     int
                                portCount map[string]int
                                protocol  string
                                srcPort   string
                                dstPort   string
                                attacks   AttackStats
                                lastBytes int64
                            }{
                                portCount: make(map[string]int),
                            }
                        }

                        ipData := packetsPerIP[srcIP]
                        
                        
                        if ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset != 0 {
                            ipData.attacks.fragCount++
                        }

                        switch {
                        case packet.Layer(layers.LayerTypeTCP) != nil:
                            tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
                            ipData.protocol = "TCP"
                            ipData.srcPort = tcp.SrcPort.String()
                            ipData.dstPort = tcp.DstPort.String()

                            
                            if tcp.SYN && !tcp.ACK { 
                                ipData.attacks.synCount++
                            }
                            if tcp.ACK && !tcp.SYN && !tcp.FIN && !tcp.PSH { 
                                ipData.attacks.ackCount++
                            }
                            if tcp.FIN && !tcp.ACK { 
                                ipData.attacks.finCount++
                            }
                            if tcp.PSH { 
                                ipData.attacks.pshCount++
                            }

                            if tcp.FIN && tcp.PSH && tcp.URG {
                                ipData.attacks.xmasCount++
                            }

                        case packet.Layer(layers.LayerTypeUDP) != nil:
                            udp, _ := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
                            ipData.protocol = "UDP"
                            ipData.srcPort = udp.SrcPort.String()
                            ipData.dstPort = udp.DstPort.String()
                            ipData.attacks.udpCount++


                            packetSize := int64(len(packet.Data()))
                            if ipData.lastBytes > 0 {
                                ratio := float64(packetSize) / float64(ipData.lastBytes)
                                if ratio > ipData.attacks.ampFactor {
                                    ipData.attacks.ampFactor = ratio
                                }
                            }
                            ipData.lastBytes = packetSize

                        case packet.Layer(layers.LayerTypeGRE) != nil:
                            ipData.protocol = "GRE"
                            ipData.attacks.greCount++

                        case packet.Layer(layers.LayerTypeICMPv4) != nil:
                            ipData.protocol = "ICMP"
                            ipData.attacks.icmpCount++
                        }


                        ipData.total++
                        portKey := fmt.Sprintf("%s:%s", ipData.srcPort, ipData.dstPort)
                        ipData.portCount[portKey]++


                        attackType := detectAttack(ipData)
                        if attackType != "" {
                            reason := fmt.Sprintf("Detected %s attack: %d packets/sec", 
                                attackType, ipData.total)
                            tw.blacklistIP(srcIP, 
                                ipData.srcPort, 
                                ipData.dstPort, 
                                ipData.protocol, 
                                reason)
                        }
                    }
                }
            }
        case <-timeout:
            goto ProcessStats
        }
    }

ProcessStats:
    tw.packetsPerSec = packets
    if packets > tw.lastHighestPPS {
        tw.lastHighestPPS = packets
    }

    if (tw.incomingIPs > 200 || packets > 3000) {
        if !tw.attackState.isOngoing {
            tw.attackState.isOngoing = true
            tw.attackState.startTime = time.Now()
            tw.attackState.attackerIPs = make(map[string]bool)
            tw.attackState.peakPPS = packets
            tw.attackState.peakMbps = tw.currentMbit
        } else {
            if packets > tw.attackState.peakPPS {
                tw.attackState.peakPPS = packets
            }
            if tw.currentMbit > tw.attackState.peakMbps {
                tw.attackState.peakMbps = tw.currentMbit
            }
        }

        if !tw.isCapturing {
            tw.isCapturing = true
            go func() {
                reason := "high_traffic"
                if tw.incomingIPs > 200 {
                    reason = "high_ips"
                }
                tw.currentPcapFile = startPacketCapture("eth0", reason)
                time.Sleep(60 * time.Second)
                tw.isCapturing = false
                tw.currentPcapFile = ""
            }()
        }

        if packets > 3000 {
            for ip, ipData := range packetsPerIP {
                if ipData.total > 30 {
                    tw.blacklistIP(ip,
                        ipData.srcPort,
                        ipData.dstPort,
                        ipData.protocol,
                        "High traffic threshold exceeded")
                }
            }
        }
    } else if tw.attackState.isOngoing && packets < 200 && tw.currentMbit < 50 {
        tw.attackState.isOngoing = false
        tw.attackState.peakPPS = 0
        tw.attackState.peakMbps = 0
    }

    mbits := float64(totalBytes*8) / 1000000
    tw.currentMbit = mbits
    tw.values = append(tw.values, mbits)
    if len(tw.values) > GRAPH_WIDTH {
        tw.values = tw.values[1:]
    }

    if mbits > tw.maxMbit {
        tw.maxMbit = mbits
    }
    if mbits < tw.minMbit {
        tw.minMbit = mbits
    }
    if tw.avgMbit == 0 {
        tw.avgMbit = mbits
    } else {
        tw.avgMbit = (tw.avgMbit + mbits) / 2
    }

    tw.totalGBytes += float64(totalBytes) / (1024 * 1024 * 1024)
}

func (tw *TCPWatch) updateIncomingIPs() {
    data, err := ioutil.ReadFile("/proc/net/tcp")
    if err == nil {
        lines := strings.Split(string(data), "\n")
        ips := make(map[string]int) 
        
        for _, line := range lines[1:] {
            fields := strings.Fields(line)
            if len(fields) > 2 {
                remoteAddr := fields[2]
                ip := parseHexIP(remoteAddr)
                if ip != "" {
                    ips[ip]++
                    
                    
                    if ips[ip] > 10 { 
                        tw.blacklistIP(ip,
                            "unknown", 
                            "unknown", 
                            "TCP",     
                            fmt.Sprintf("Too many connections: %d", ips[ip]))
                    }
                }
            }
        }
        tw.incomingIPs = len(ips)
    }
}

func (tw *TCPWatch) drawTrafficGraph() string {
    var result strings.Builder
    maxValue := 0.0
    
    for len(tw.values) < GRAPH_WIDTH {
        tw.values = append(tw.values, 0.0)
    }

    for _, v := range tw.values {
        if v > maxValue {
            maxValue = v
        }
    }
    maxValue = maxValue * 1.5 
    
    if maxValue == 0 {
        maxValue = 1
    }

    height := 25  
    width := 70  

    for i := 0; i < height; i++ {
        threshold := maxValue * float64(height-i) / float64(height)
        
        result.WriteString(strings.Repeat(" ", 2))
        
        for j := 0; j < width; j++ {
            if j < len(tw.values) {
                value := tw.values[j]
                if value >= threshold {
                    result.WriteString("#")
                } else {
                    result.WriteString(" ")
                }
            } else {
                result.WriteString(" ")
            }
        }
        result.WriteString("\n")
    }
    return result.String()
}


func cleanup() {
	fmt.Print("\033[?25h")
	fmt.Print("\033[2J")   
	fmt.Print("\033[H")    
	os.Exit(0)
}

func (tw *TCPWatch) updateSystemStats() {
    if data, err := ioutil.ReadFile("/proc/meminfo"); err == nil {
        var memTotal, memFree, swapTotal, swapFree uint64
        scanner := bufio.NewScanner(strings.NewReader(string(data)))
        for scanner.Scan() {
            line := scanner.Text()
            if strings.HasPrefix(line, "MemTotal:") {
                fmt.Sscanf(line, "MemTotal: %d", &memTotal)
            } else if strings.HasPrefix(line, "MemFree:") {
                fmt.Sscanf(line, "MemFree: %d", &memFree)
            } else if strings.HasPrefix(line, "SwapTotal:") {
                fmt.Sscanf(line, "SwapTotal: %d", &swapTotal)
            } else if strings.HasPrefix(line, "SwapFree:") {
                fmt.Sscanf(line, "SwapFree: %d", &swapFree)
            }
        }
        tw.memoryUsed = float64(memTotal-memFree) / 1024 / 1024
        tw.memoryFree = float64(memFree) / 1024 / 1024
        tw.swapUsed = float64(swapTotal-swapFree) / 1024 / 1024
        tw.swapFree = float64(swapFree) / 1024 / 1024
    }

    if files, err := ioutil.ReadDir("/proc"); err == nil {
        count := 0
        for _, f := range files {
            if _, err := strconv.Atoi(f.Name()); err == nil {
                count++
            }
        }
        tw.processCount = count
    }
}

func (tw *TCPWatch) display() {
    width, _ := getTerminalSize()
    boxWidth := width - 2

    fmt.Print("\033[H\033[2J") 

    headerFormat := fmt.Sprintf("%s%%-%ds%s", colorYellowBg, boxWidth, colorReset)
    header := fmt.Sprintf("TCP Watch | %s                TCP Watch Start Time: %s         Tcp Solo Development Team",
        VERSION,
        tw.startTime.Format("01/02/06 15:04:05"))
    fmt.Printf(headerFormat, header)
    fmt.Println()

    fmt.Printf("%s%s%s%s\n", 
        colorGray,
        boxTopLeft, 
        strings.Repeat(boxHorizontal, boxWidth-2), 
        boxTopRight)



    fmt.Printf("%s %-*s      %s\n", 
        colorGray + boxVertical + colorWhite,
        boxWidth-4,
        fmt.Sprintf("[ CREDITS ] created with love by tcpfailed                               System IP: %s%s",
            colorLightGreen, tw.systemIP),
        colorGray + boxVertical)

  
    fmt.Printf("%s %-*s %s\n", 
        colorGray + boxVertical + colorWhite,
        boxWidth-4,
        fmt.Sprintf("                                                                         Current PPS: %d",
            tw.packetsPerSec),
        colorGray + boxVertical)

    fmt.Printf("%s %-*s %s\n", 
        colorGray + boxVertical + colorWhite,
        boxWidth-4,
        fmt.Sprintf("TCP Watch %s is now in development, join the discord!", VERSION),
        colorGray + boxVertical)

   
    fmt.Printf("%s%s%s\n",
        colorGray + boxTeeLeft,
        "CPU INFO" + strings.Repeat(boxHorizontal, boxWidth-10),
        colorGray + boxTeeRight)

 
    fmt.Printf("%s %-*s %s\n", 
        colorGray + boxVertical + colorWhite,
        boxWidth-4,
        "CPU: " + tw.cpuModel,
        colorGray + boxVertical)

    fmt.Printf("%s %-*s %s\n", 
        colorGray + boxVertical + colorWhite,
        boxWidth-4,
        fmt.Sprintf("CPU Usage: %.2f%%", tw.cpuUsage),
        colorGray + boxVertical)

    fmt.Printf("%s %-*s              %s\n", 
        colorGray + boxVertical + colorWhite,
        boxWidth-7,
        fmt.Sprintf("Ram Usage: %d/%dMB | Free: %s%d%s",
            tw.ramUsed, tw.ramTotal, colorLightGreen, tw.ramFree, colorWhite),
        colorGray + boxVertical)

    fmt.Printf("%s%s%s\n",
        colorGray + boxTeeLeft,
        "BANNER" + strings.Repeat(boxHorizontal, boxWidth-8),
        colorGray + boxTeeRight)
        
    fmt.Printf("%s %-*s          %s\n", 
        colorGray + boxVertical,
        boxWidth-4,
        fmt.Sprintf("         %s╔╦╗╔═╗╔═╗  ╦ ╦╔═╗╔╦╗╔═╗╦ ╦%s", colorYellow, colorReset),
        colorGray + boxVertical)
    fmt.Printf("%s %-*s          %s\n", 
        colorGray + boxVertical,
        boxWidth-4,
        fmt.Sprintf("          %s║ ║  ╠═╝  ║║║╠═╣ ║ ║  ╠═╣%s", colorYellow, colorReset),
        colorGray + boxVertical)
    fmt.Printf("%s %-*s          %s\n", 
        colorGray + boxVertical,
        boxWidth-4,
        fmt.Sprintf("          %s╩ ╚═╝╩    ╚╩╝╩ ╩ ╩ ╚═╝╩ ╩%s", colorYellow, colorReset),
        colorGray + boxVertical)

    fmt.Printf("%s%s%s\n",
        colorGray + boxTeeLeft,
        strings.Repeat(boxHorizontal, boxWidth-2),
        colorGray + boxTeeRight)

    fmt.Printf("%s %-*s           %s\n", 
        colorGray + boxVertical + colorWhite,
        boxWidth-4,
        fmt.Sprintf("Last Highest PPS: %s%d%s",
            colorLightGreen, tw.lastHighestPPS, colorWhite),
        colorGray + boxVertical)

    fmt.Printf("%s %-*s           %s\n", 
        colorGray + boxVertical + colorWhite,
        boxWidth-4,
        fmt.Sprintf("Start Filtering At: %s3000%s packets",
            colorLightGreen, colorWhite),
        colorGray + boxVertical)

    fmt.Printf("%s %-*s %s\n", 
        colorGray + boxVertical + colorWhite,
        boxWidth-4,
        fmt.Sprintf("Incoming IPs: %d", tw.incomingIPs),
        colorGray + boxVertical)

    fmt.Printf("%s %-*s %s\n", 
        colorGray + boxVertical,
        boxWidth-4,
        "",
        colorGray + boxVertical)

    trafficStats := []string{
        fmt.Sprintf("Curr: %.2f MBit/s", tw.currentMbit),
        fmt.Sprintf("Avg: %.2f MBit/s", tw.avgMbit),
        fmt.Sprintf("Min: %.2f MBit/s", tw.minMbit),
        fmt.Sprintf("Max: %.2f MBit/s", tw.maxMbit),
        fmt.Sprintf("Ttl: %.2f GByte", tw.totalGBytes),
    }

    for _, stat := range trafficStats {
        fmt.Printf("%s %-*s %s\n", 
            colorGray + boxVertical + colorWhite,
            boxWidth-4,
            stat,
            colorGray + boxVertical)
    }

    fmt.Printf("%s %-*s %s\n", 
        colorGray + boxVertical,
        boxWidth-4,
        "",
        colorGray + boxVertical)

fmt.Printf("%s %-*s %s\n", 
    colorGray + boxVertical + colorWhite,
    boxWidth-4,
    fmt.Sprintf("Blacklisted IPs to Display: %d", tw.blacklistCount),
    colorGray + boxVertical)

    fmt.Printf("%s %-*s %s\n", 
        colorGray + boxVertical,
        boxWidth-4,
        "",
        colorGray + boxVertical)

    graph := tw.drawTrafficGraph()
    graphLines := strings.Split(graph, "\n")
    for _, line := range graphLines {
        if line != "" {
            fmt.Printf("%s %-*s %s\n", 
                colorGray + boxVertical,
                boxWidth-4,
                line,
                colorGray + boxVertical)
        }
    }

    memStats := []string{
        fmt.Sprintf("Memory Used: %.2f GB", tw.memoryUsed),
        fmt.Sprintf("Memory Free: %.2f GB", tw.memoryFree),
        fmt.Sprintf("Swap Used: %.2f GB", tw.swapUsed),
        fmt.Sprintf("Swap Free: %.2f GB", tw.swapFree),
        fmt.Sprintf("Processes: %d", tw.processCount),
    }

    for _, stat := range memStats {
        fmt.Printf("%s %-*s %s\n", 
            colorGray + boxVertical + colorWhite,
            boxWidth-4,
            stat,
            colorGray + boxVertical)
    }

    fmt.Printf("%s %-*s %s\n", 
        colorGray + boxVertical,
        boxWidth-4,
        "",
        colorGray + boxVertical)

    fmt.Printf("%s %-*s %s\n", 
        colorGray + boxVertical + colorRed,
        boxWidth-4,
        "Current Attacking IPs:",
        colorGray + boxVertical)

    var blockedEntries []string
    if data, err := ioutil.ReadFile("blacklistedips.txt"); err == nil {
        lines := strings.Split(string(data), "\n")
        for _, line := range lines {
            if line != "" {
                blockedEntries = append(blockedEntries, line)
            }
        }
    }

    entriesShown := 0
    for i := tw.lastDisplayIndex; i < len(blockedEntries) && entriesShown < 2; i++ {
        fmt.Printf("%s %-*s %s\n", 
            colorGray + boxVertical + colorWhite,
            boxWidth-4,
            blockedEntries[i],
            colorGray + boxVertical)
        entriesShown++
    }

    for i := entriesShown; i < 2; i++ {
        fmt.Printf("%s %-*s %s\n", 
            colorGray + boxVertical + colorWhite,
            boxWidth-4,
            "No more entries",
            colorGray + boxVertical)
    }

    tw.lastDisplayIndex += 2
    if tw.lastDisplayIndex >= len(blockedEntries) {
        tw.lastDisplayIndex = 0
    }

    fmt.Printf("%s %-*s %s\n", 
        colorGray + boxVertical,
        boxWidth-4,
        "",
        colorGray + boxVertical)

    if tw.isCapturing && tw.currentPcapFile != "" {
        fmt.Printf("%s%-*s%s\n",
            colorYellowBg,
            boxWidth,
            fmt.Sprintf("Packet capture in progress... Recording to: %s", tw.currentPcapFile),
            colorReset)
    }

    fmt.Printf("%s%s%s%s%s\n",
        colorGray,
        boxBottomLeft,
        strings.Repeat(boxHorizontal, boxWidth-2),
        boxBottomRight,
        colorReset)
}
func getServerIP() string {
    ifaces, err := net.Interfaces()
    if err != nil {
        return "unknown"
    }
    for _, iface := range ifaces {
        if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
            continue
        }
        addrs, err := iface.Addrs()
        if err != nil {
            continue
        }
        for _, addr := range addrs {
            if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
                if ipv4 := ipnet.IP.To4(); ipv4 != nil {
                    return ipv4.String() + ":22"
                }
            }
        }
    }
    return "unknown"
}
    
func main() {

  if os.Geteuid() != 0 {
        fmt.Println("This program must be run as root (sudo)")
        os.Exit(1)
    }

    setTerminalSize()
	tw := newTCPWatch()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	fmt.Print("\033[?25l")
	defer fmt.Print("\033[?25h")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sigChan:
			fmt.Print("\033[?25h") 
			fmt.Print("\033[2J")   
			fmt.Print("\033[H")    
			return
		case <-ticker.C:
			tw.updateSystemInfo()
			tw.updateNetworkStats()
			tw.updateIncomingIPs()
			tw.display()
      tw.updateSystemStats()
		}
	}
}
