package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
  	"flag"
  	"runtime"

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

type Blocker struct {
	blockedIPS map[string]int
	mu sync.Mutex
	blockedThreshold int
}

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
    IP         string
    SourcePort string
    TargetPort string
    Timestamp  time.Time
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
  ramTotal int
  handle *pcap.Handle
}


func (tw *TCPWatch) stopPacketCapture() {
	if tw.handle != nil {
		tw.handle.Close()
		tw.handle = nil
	}

	tw.isCapturing = false

	if tw.currentPcapFile != "" {
		err := os.Remove(tw.currentPcapFile)
		if err != nil {
			fmt.Printf("Failed to delete pcap file: %v\n", err)
		} else {
			fmt.Printf("Deleted pcap file: %s\n", tw.currentPcapFile)
		}
		tw.currentPcapFile = ""
	}
}

func cleanupOldPcaps() {
	files, err := filepath.Glob("*.pcap")
	if err != nil {
		fmt.Printf("Failed to find past pcap files: %v\n", err)
		return
	}

	for _, f := range files {
		os.Remove(f)
	}
}

func NewBlocker(threshold int) *Blocker {
	return &Blocker{
		blockedIPS: make(map[string]int),
		blockedThreshold: threshold,

	}
}
func normalizeIPv6(ip string) string {
    ip = strings.ReplaceAll(ip, "0000", "0")
    return strings.Trim(ip, ":")
}


func (b *Blocker) BlockIP(ip string, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.blockedIPS[ip] > 0 {
		return
	}
	var cmd *exec.Cmd
	if isIPv6(ip) {
		cmd = exec.Command("ip6tables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	} else {
		cmd = exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	}
	if err := cmd.Run(); err != nil {
		fmt.Printf("Failed to block IP %s: %v\n", ip, err)
		return
	}
	b.blockedIPS[ip] = 1
}

func isIPv6(ip string) bool {
	parsed := net.ParseIP(strings.Split(ip, "%")[0])
	return parsed != nil && parsed.To4() == nil
}

func runScreenSession(sessionName, goFile string) error {
    cmd := exec.Command("screen", "-dmS", sessionName, "go", "run", goFile)
    return cmd.Start()
}

func killScreenSession(sessionName string) error {
    cmd := exec.Command("pkill", "-f", fmt.Sprintf("SCREEN.*%s", sessionName))
    return cmd.Run()
}

func runAbuseDBInBackground() error {
    screenSession := "abusedb_session"

    cmd := exec.Command("screen", screenSession, "go", "run", "abusedb.go")

    err := cmd.Start()
    if err != nil {
        return fmt.Errorf("failed to start abusedb.go in screen: %w", err)
    }

    fmt.Printf("abusedb started in background with screen session: %s (PID: %d)\n", screenSession, cmd.Process.Pid)

    return nil
}

func runBPFInBackground() error {
    screenSession := "bpf_session"

    cmd := exec.Command("screen", "-dmS", screenSession, "go", "run", "bpfmaker.go")

    err := cmd.Start()
    if err != nil {
        return fmt.Errorf("failed to start bpfmaker.go in screen: %w", err)
    }

    fmt.Printf("bpfmaker.go started in background with screen session: %s (PID: %d)\n", screenSession, cmd.Process.Pid)

    return nil
}

func getTotalRAM() int {
    data, err := ioutil.ReadFile("/proc/meminfo")
    if err != nil {
        return 0
    }

    for _, line := range strings.Split(string(data), "\n") {
        if strings.HasPrefix(line, "MemTotal:") {
            parts := strings.Fields(line)
            if len(parts) >= 2 {
                totalKB, err := strconv.Atoi(parts[1])
                if err == nil {
                    return totalKB / 1024 
                }
            }
        }
    }
    return 0
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
	cleanupOldPcaps()
    iface, err := getDefaultInterface()
    if err != nil {
        log.Fatalf("Failed to detect default interface: %v", err)
    }

    fmt.Printf("Detected default network interface: %s\n", iface)

    tw := &TCPWatch{
        startTime:        time.Now(),
        values:           make([]float64, 0, GRAPH_WIDTH),
        minMbit:          math.MaxFloat64,
        ramTotal:         getTotalRAM(), 
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
    tempFile := "blacklistedips.txt"
    logFile := "blacklistedips.log"

logEntry := fmt.Sprintf("[%s] Blocked IP: %s | Source Port: %s | Target Port: %s\n",
    entry.Timestamp.Format("01-02-06 15:04:05"),
    entry.IP,
    entry.SourcePort,
    entry.TargetPort)


    f1, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err == nil {
        f1.WriteString(logEntry)
        f1.Close()
    }

    f2, err := os.OpenFile(tempFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err == nil {
        f2.WriteString(logEntry)
        f2.Close()
    }
}

func (tw *TCPWatch) blacklistIP(ip string, srcPort, targetPort, protocol, reason string) error {
	if tw.whitelistedIPs[ip] {
		return nil
	}
	if _, exists := tw.blockedIPs[ip]; exists {
		return nil
	}

	ipAddr := strings.Split(ip, "%")[0]
	isV6 := isIPv6(ipAddr)

	cmd := exec.Command(
		func() string {
			if isV6 { return "ip6tables" }
			return "iptables"
		}(),
		"-A", "INPUT", "-s", ipAddr, "-j", "DROP",
	)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ip block cmd failed: %w", err)
	}

entry := BlacklistEntry{
    IP:         ipAddr,
    SourcePort: srcPort,
    TargetPort: targetPort,
    Timestamp:  time.Now(),
}

tw.logBlacklistedIP(entry)

tw.blockedIPs[ipAddr] = entry.Timestamp
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
					return ipv4.String()
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
func parseHexIPAndPort(hexAddr string) (string, string) {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return "", ""
	}

	ipHex := parts[0]
	portHex := parts[1]

	portInt, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return "", ""
	}
	port := strconv.Itoa(int(portInt))

	if len(ipHex) == 8 {
		b, err := hex.DecodeString(ipHex)
		if err != nil || len(b) != 4 {
			return "", port
		}
		return net.IPv4(b[3], b[2], b[1], b[0]).String(), port
	}

	if len(ipHex) == 32 {
		b, err := hex.DecodeString(ipHex)
		if err != nil || len(b) != 16 {
			return "", port
		}
		ip := net.IP(b)
		return ip.String(), port
	}

	return "", port
}


func (tw *TCPWatch) updateIncomingIPs() {
	files := []struct {
		path     string
		protocol string
	}{
		{"/proc/net/tcp", "TCP"},
		{"/proc/net/tcp6", "TCP"},
		{"/proc/net/udp", "UDP"},
		{"/proc/net/udp6", "UDP"},
		{"/proc/net/raw", "RAW"},
		{"/proc/net/raw6", "RAW"},
		{"/proc/net/icmp", "ICMP"},
		{"/proc/net/icmp6", "ICMP"},
		{"/proc/net/gre", "GRE"},
		{"/proc/net/gre6", "GRE"},
	}

    ipCounts := make(map[string]int)

    type connInfo struct {
        srcPort string
        dstPort string
    }

    ipDetails := make(map[string]connInfo)

    for _, file := range files {
        data, err := ioutil.ReadFile(file.path)
        if err != nil {
            continue
        }

        lines := strings.Split(string(data), "\n")
        for _, line := range lines[1:] {
            fields := strings.Fields(line)
            if len(fields) < 3 {
                continue
            }
            localHex := fields[1]
            remoteHex := fields[2]

            srcIP, srcPort := parseHexIPEnhanced(remoteHex)
            _, dstPort := parseHexIPEnhanced(localHex)

            if srcIP == "" {
                continue
            }
            ipCounts[srcIP]++
            ipDetails[srcIP] = connInfo{srcPort: srcPort, dstPort: dstPort}
        }
    }

    tw.incomingIPs = len(ipCounts)

    for ip, count := range ipCounts {
        if count > 10 {
            details := ipDetails[ip]
            _ = tw.blacklistIP(ip, details.srcPort, details.dstPort, "", "")
            fmt.Printf("Blacklisted IP: %s | Source Port: %s | Destination Port: %s\n", ip, details.srcPort, details.dstPort)
        }
    }
}

func parseHexIPEnhanced(hexAddr string) (string, string) {
    parts := strings.Split(hexAddr, ":")
    if len(parts) != 2 {
        return "", "" 
    }
    ipHex := parts[0]
    portHex := parts[1]

    port, err := strconv.ParseUint(portHex, 16, 16)
    if err != nil {
        return "", ""
    }

    var ip net.IP
    if len(ipHex) == 8 {
        b, err := hex.DecodeString(ipHex)
        if err != nil || len(b) != 4 {
            return "", ""
        }
        ip = net.IP{b[3], b[2], b[1], b[0]}
    } else if len(ipHex) == 32 {
        b, err := hex.DecodeString(ipHex)
        if err != nil || len(b) != 16 {
            return "", "" 
        }
        ip = make(net.IP, 16)
        for i := 0; i < 16; i++ {
            ip[i] = b[15-i]
        }
    } else {
        return "", "" 
    }
    return ip.String(), fmt.Sprintf("%d", port)
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
        fmt.Sprintf("https://github.com/tcpfailed/tcp-watch                                   Current PPS: %d",
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
    err := os.WriteFile("blacklistedips.txt", []byte(""), 0644)
    if err != nil {
        fmt.Println("Failed to clear temporary IP list:", err)
    }
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
    
    if err := runBPFInBackground(); err != nil {
        fmt.Println("Error running bpf:", err)
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
                    return ipv4.String() 
                }
            }
        }
    }
    return "unknown"
}
    
func main() {
    var intervalMS int
    flag.IntVar(&intervalMS, "t", 0, "Required: Update interval in milliseconds (minimum 50ms)")
    flag.Parse()

    if intervalMS == 0 {
        fmt.Println("Error: -t flag is required. Example: -t 1000")
        flag.Usage()
        os.Exit(1)
    }

    if intervalMS < 50 {
        fmt.Println("Minimum allowed interval is 50ms. Using 50ms.")
        intervalMS = 50
    }

    pid := os.Getpid()
    cores := runtime.NumCPU()
    fmt.Printf("Detected %d CPU cores, applying cpulimit...\n", cores)

    cpulimitCmd := exec.Command("cpulimit",
        "-p", fmt.Sprintf("%d", pid),
        "-l", "45",
    )
    cpulimitCmd.Stdout = os.Stdout
    cpulimitCmd.Stderr = os.Stderr

    if err := cpulimitCmd.Start(); err != nil {
        fmt.Printf("Failed to start cpulimit: %v\n", err)
    } else {
        fmt.Println("cpulimit started successfully")
    }

    defer func() {
        if cpulimitCmd.Process != nil {
            fmt.Println("Stopping cpulimit...")
            cpulimitCmd.Process.Kill()
            cpulimitCmd.Wait()
            fmt.Println("cpulimit stopped.")
        }
    }()

    abuseDBSession := "abusedb_session"
    bpfSession := "bpf_session"

    if err := runScreenSession(abuseDBSession, "abusedb.go"); err != nil {
        fmt.Println("Failed to start abusedb.go:", err)
    } else {
        fmt.Println("abusedb.go running in screen session:", abuseDBSession)
    }

    if err := runScreenSession(bpfSession, "bpfmaker.go"); err != nil {
        fmt.Println("Failed to start bpfmaker.go:", err)
    } else {
        fmt.Println("bpfmaker.go running in screen session:", bpfSession)
    }

    setTerminalSize()
    tw := newTCPWatch()

    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

    fmt.Print("\033[?25l")
    defer fmt.Print("\033[?25h")

    ticker := time.NewTicker(time.Duration(intervalMS) * time.Millisecond)
    defer ticker.Stop()

    iteration := 0

    for {
        select {
        case <-sigChan:
            fmt.Print("\033[?25h")
            fmt.Print("\033[2J")
            fmt.Print("\033[H")

            fmt.Println("\nStopping background screen sessions...")

            if err := killScreenSession(abuseDBSession); err != nil {
                fmt.Println("Error stopping abusedb screen session:", err)
            } else {
                fmt.Println("Stopped abusedb screen session.")
            }

            if err := killScreenSession(bpfSession); err != nil {
                fmt.Println("Error stopping bpf screen session:", err)
            } else {
                fmt.Println("Stopped bpf screen session.")
            }

            fmt.Println("Shutdown complete.")
            return

        case <-ticker.C:
            tw.updateSystemInfo()
            tw.updateNetworkStats()

            if iteration%(600/intervalMS) == 0 {
                tw.updateIncomingIPs()
            }

            tw.updateSystemStats()
            tw.display()
            tw.updateSystemStats()

            iteration++
        }
    }
}
