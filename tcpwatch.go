package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
  "log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	VERSION = "v1.0.2"

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

type AttackPattern struct {
	Pattern     string
	Count       int
	FirstSeen   time.Time
	LastSeen    time.Time
	BPFRule     string
	PacketSizes []int
	Protocols   map[string]int
	Flags       map[string]int
	Ports       map[int]int
}

type PatternAnalyzer struct {
	patterns   map[string]*AttackPattern
	mu         sync.RWMutex
	sampleSize int
	threshold  int
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
type AttackState struct {
    isOngoing    bool
    startTime    time.Time
    peakPPS      int
    peakMbps     float64
    attackerIPs  map[string]bool
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
	analyzer        *PatternAnalyzer
	bpfRules        map[string]string
	attackState     AttackState
	lastAlertTime   time.Time 
  interfaceName string
  iface string
}

func showASCIILoadingScreen() {
    asciiArt := `▄▄▄▄▄ ▄▄·  ▄▄▄·    ▄▄▌ ▐ ▄▌ ▄▄▄· ▄▄▄▄▄ ▄▄·  ▄ .▄    
•██  ▐█ ▌▪▐█ ▄█    ██· █▌▐█▐█ ▀█ •██  ▐█ ▌▪██▪▐█    
 ▐█.▪██ ▄▄ ██▀·    ██▪▐█▐▐▌▄█▀▀█  ▐█.▪██ ▄▄██▀▐█    
 ▐█▌·▐███▌▐█▪·•    ▐█▌██▐█▌▐█ ▪▐▌ ▐█▌·▐███▌██▌▐▀    
 ▀▀▀ ·▀▀▀ .▀        ▀▀▀▀ ▀▪ ▀  ▀  ▀▀▀ ·▀▀▀ ▀▀▀ ·    
                                             
Loading tcp-watch`

    for _, char := range asciiArt {
        fmt.Printf("%c", char)
        time.Sleep(10 * time.Millisecond) 
    }

    for i := 0; i < 5; i++ {
        fmt.Print(".")
        time.Sleep(500 * time.Millisecond)
    }
    fmt.Println()

    time.Sleep(1 * time.Second)

    fmt.Print("\033[H\033[2J") 
}

func getDefaultInterface() (string, error) {
showASCIILoadingScreen()
    out, err := exec.Command("ip", "route", "show", "default").Output()
    if err != nil {
        return "", err
    }

    parts := strings.Fields(string(out))
    for i, part := range parts {
        if part == "dev" && i+1 < len(parts) {
            return parts[i+1], nil
        }
    }

    return "", fmt.Errorf("could not detect default interface")
}

func (tw *TCPWatch) startPacketAnalysis(interfaceName string) {
	tw.interfaceName = interfaceName 

	go func() {
		for {
			cmd := exec.Command("tcpdump", "-i", interfaceName, "-n", "-v", "-c", "1000")
			output, err := cmd.Output()
			if err != nil {
				fmt.Printf("tcpdump error: %v\n", err)
				time.Sleep(time.Second)
				continue
			}

			tw.analyzePackets(string(output))
			time.Sleep(time.Second)
		}
	}()
}

func (tw *TCPWatch) extractPattern(line string) string {
    if strings.Contains(line, "SYN") {
        return "SYN_flood"
    } else if strings.Contains(line, "UDP") {
        return "UDP_flood"
    }
    return ""
}

func (tw *TCPWatch) analyzePackets(output string) {
    lines := strings.Split(output, "\n")
    for _, line := range lines {
        if line == "" {
            continue
        }

        pattern := tw.extractPattern(line)
        if pattern == "" {
            continue
        }

        tw.analyzer.mu.Lock()
        if _, exists := tw.analyzer.patterns[pattern]; !exists {
            tw.analyzer.patterns[pattern] = &AttackPattern{
                Pattern:     pattern,
                FirstSeen:   time.Now(),
                Protocols:   make(map[string]int),
                Flags:       make(map[string]int),
                Ports:       make(map[int]int),
                PacketSizes: make([]int, 0),
            }
        }

        p := tw.analyzer.patterns[pattern]
        p.Count++
        p.LastSeen = time.Now()

        proto := extractProtocol(line)
        if proto != "" {
            p.Protocols[proto]++
        }

        flags := extractFlags(line)
        for _, flag := range flags {
            p.Flags[flag]++
        }

        ports := extractPorts(line)
        for _, port := range ports {
            p.Ports[port]++
        }

        size := extractPacketSize(line)
        if size > 0 {
            p.PacketSizes = append(p.PacketSizes, size)
        }

        if p.Count >= tw.analyzer.threshold && p.BPFRule == "" {
            p.BPFRule = tw.generateBPFRule(p)
            tw.applyBPFRule(p.BPFRule)
        }

        tw.analyzer.mu.Unlock()
    }
}


func (tw *TCPWatch) generateBPFRule(p *AttackPattern) string {
	var ruleParts []string

	protocol := getMostCommon(p.Protocols)
	if protocol != "" {
		ruleParts = append(ruleParts, protocol)
	}

	commonPorts := getMostCommonPorts(p.Ports, 2)
	for _, port := range commonPorts {
		ruleParts = append(ruleParts, fmt.Sprintf("port %d", port))
	}

	flags := getMostCommonFlags(p.Flags)
	for _, flag := range flags {
		switch flag {
		case "SYN":
			ruleParts = append(ruleParts, "tcp[tcpflags] & tcp-syn != 0")
		case "ACK":
			ruleParts = append(ruleParts, "tcp[tcpflags] & tcp-ack != 0")
		case "FIN":
			ruleParts = append(ruleParts, "tcp[tcpflags] & tcp-fin != 0")
		}
	}

	avgSize := calculateAverage(p.PacketSizes)
	if avgSize > 0 {
		ruleParts = append(ruleParts, fmt.Sprintf("greater %d", int(avgSize)))
	}

	return strings.Join(ruleParts, " and ")
}


func (tw *TCPWatch) applyBPFRule(rule string) {
    
	cmd := exec.Command("tcpdump", "-i", tw.interfaceName, rule)
    if err := cmd.Start(); err != nil {
        fmt.Printf("%v\n", err)
        return
    }

    tw.bpfRules[rule] = time.Now().String()

    
    fmt.Printf("\n%s\n", rule)
}

func extractProtocol(line string) string {
    protocols := []string{"tcp", "udp", "icmp"}
    for _, proto := range protocols {
        if strings.Contains(strings.ToLower(line), proto) {
            return proto
        }
    }
    return ""
}

func extractFlags(line string) []string {
    var flags []string
    flagPatterns := map[string]string{
        "SYN": `\[S\]`,
        "ACK": `\[A\]`,
        "FIN": `\[F\]`,
        "RST": `\[R\]`,
        "PSH": `\[P\]`,
        "URG": `\[U\]`,
    }

    for flag, pattern := range flagPatterns {
        if matched, _ := regexp.MatchString(pattern, line); matched {
            flags = append(flags, flag)
        }
    }
    return flags
}

func extractPorts(line string) []int {
    var ports []int
    portPattern := regexp.MustCompile(`port (\d+)`)
    matches := portPattern.FindAllStringSubmatch(line, -1)
    for _, match := range matches {
        if port, err := strconv.Atoi(match[1]); err == nil {
            ports = append(ports, port)
        }
    }
    return ports
}

func extractPacketSize(line string) int {
    sizePattern := regexp.MustCompile(`length (\d+)`)
    if match := sizePattern.FindStringSubmatch(line); len(match) > 1 {
        size, _ := strconv.Atoi(match[1])
        return size
    }
    return 0
}

func getMostCommon(m map[string]int) string {
    var maxKey string
    var maxVal int
    for k, v := range m {
        if v > maxVal {
            maxKey = k
            maxVal = v
        }
    }
    return maxKey
}

func getMostCommonFlags(flags map[string]int) []string {
    threshold := 0.7 
    var result []string
    total := 0
    for _, count := range flags {
        total += count
    }
    for flag, count := range flags {
        if float64(count)/float64(total) >= threshold {
            result = append(result, flag)
        }
    }
    return result
}

func getMostCommonPorts(ports map[int]int, limit int) []int {
    type portCount struct {
        port  int
        count int
    }
    var counts []portCount
    for port, count := range ports {
        counts = append(counts, portCount{port, count})
    }
    sort.Slice(counts, func(i, j int) bool {
        return counts[i].count > counts[j].count
    })
    var result []int
    for i := 0; i < limit && i < len(counts); i++ {
        result = append(result, counts[i].port)
    }
    return result
}

func calculateAverage(numbers []int) float64 {
    if len(numbers) == 0 {
        return 0
    }
    sum := 0
    for _, n := range numbers {
        sum += n
    }
    return float64(sum) / float64(len(numbers))
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

func setTerminalSize() {

    fmt.Printf("\x1b[8;65;204t")
    serverIP := getServerIP()
    fmt.Printf("\033]0;Welcome To TCP Watch V1.0.2 (In Development!) {%s}\007", serverIP)
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
    iface, err := getDefaultInterface()
    if err != nil {
        log.Fatalf("Failed to detect default interface: %v", err)
    }

    fmt.Printf("Detected default network interface: %s\n", iface)  

    tw := &TCPWatch{
        startTime:        time.Now(),
        values:           make([]float64, 0, GRAPH_WIDTH),
        minMbit:          math.MaxFloat64,
        ramTotal:         2000,
        isCapturing:      false,
        currentPcapFile:  "",
        blockedIPs:       make(map[string]time.Time),
        blacklistCount:   0,
        attackingIPs:     make(map[string]string),
        lastDisplayIndex: 0,
        iface:            iface, 
        whitelistedIPs: map[string]bool{
            "IP": true,
            "IP": true,
            "127.0.0.1":     true,
            "::1":           true,
        },
        analyzer: &PatternAnalyzer{
            patterns:   make(map[string]*AttackPattern),
            sampleSize: 1000,
            threshold:  100,
            mu:         sync.RWMutex{},
        },
        bpfRules: make(map[string]string),
        attackState: AttackState{
            isOngoing:   false,
            attackerIPs: make(map[string]bool),
        },
        lastAlertTime: time.Now(),
    }

    tw.systemIP = tw.getServerIP()
    tw.updateSystemInfo()

    go tw.startPacketAnalysis(tw.iface)

    return tw
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

    f, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
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
        IP:          ip,
        SourcePort:  srcPort,
        Protocol:    protocol,
        TargetPort:  targetPort,
        Reason:      reason,
        Timestamp:   time.Now(),
    }

    tw.logBlacklistedIP(entry)

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
    handle, err := pcap.OpenLive(tw.iface, 1600, true, pcap.BlockForever)
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

    if (tw.incomingIPs > 100 || packets > 300) && !tw.isCapturing {
        tw.isCapturing = true
        go func() {
            reason := "high_traffic"
            if tw.incomingIPs > 100 {
                reason = "high_ips"
            }
            tw.currentPcapFile = startPacketCapture(tw.iface, reason)
            time.Sleep(60 * time.Second)
            tw.isCapturing = false
            tw.currentPcapFile = "" 
        }()

        if packets > 300 {
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
    fmt.Sprintf("                                                                         Current Interface: %s", tw.iface),
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

    data, err := ioutil.ReadFile("blacklistedips.txt")
    if err == nil {
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
        ioutil.WriteFile("blacklistedips.txt", []byte(""), 0644)
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
