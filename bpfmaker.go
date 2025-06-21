package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"syscall"
)

const (
	bpfFile      = "tcpwatch_bpf.txt"
)

var (
	runningProcesses = make(map[string]*exec.Cmd)
	activeFilters    = make(map[string]string)
	lastModTime      time.Time
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("[BPFMaker] Starting with enhanced monitoring...")

	if err := verifyEnvironment(); err != nil {
		log.Fatalf("Startup verification failed: %v", err)
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := checkAndProcessBPF(); err != nil {
			log.Printf("Processing error: %v", err)
		}
	}
}

func verifyEnvironment() error {
	if _, err := os.Stat(bpfFile); os.IsNotExist(err) {
		log.Printf("BPF file %s doesn't exist, creating...", bpfFile)
		if err := os.WriteFile(bpfFile, []byte{}, 0644); err != nil {
			return fmt.Errorf("failed to create BPF file: %w", err)
		}
	}

	for _, dir := range []string{"bpf_rules", "bpf_logs"} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
		log.Printf("Verified directory: %s", dir)
	}

	if _, err := exec.LookPath("tcpdump"); err != nil {
		return fmt.Errorf("tcpdump not found in PATH: %w", err)
	}
	log.Println("Verified tcpdump availability")

	return nil
}

func checkAndProcessBPF() error {
	info, err := os.Stat(bpfFile)
	if err != nil {
		return fmt.Errorf("failed to stat BPF file: %w", err)
	}

	if info.ModTime().Equal(lastModTime) {
		return nil 
	}
	lastModTime = info.ModTime()

	log.Printf("Detected changes in %s, processing...", bpfFile)

	content, err := os.ReadFile(bpfFile)
	if err != nil {
		return fmt.Errorf("failed to read BPF file: %w", err)
	}

	log.Printf("Current BPF file content:\n%s", string(content))

	seenRules := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	lineNum := 0
	rulesAdded := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		log.Printf("Processing line %d: %s", lineNum, line)

		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			log.Printf("Invalid format at line %d - expected 'pattern|filter', got '%s'", lineNum, line)
			continue
		}

		pattern := strings.TrimSpace(parts[0])
		bpf := strings.TrimSpace(parts[1])

		if pattern == "" || bpf == "" {
			log.Printf("Empty pattern or filter at line %d", lineNum)
			continue
		}

		if seenRules[pattern] {
			log.Printf("Skipping duplicate pattern: %s", pattern)
			continue
		}
		seenRules[pattern] = true

		if prev, exists := activeFilters[pattern]; exists && prev == bpf {
			log.Printf("Rule unchanged for %s, skipping restart", pattern)
			continue
		}

		ruleFile := filepath.Join("bpf_rules", sanitizeFilename(pattern)+".bpf")
		log.Printf("Creating rule %d: Pattern='%s', Filter='%s'", lineNum, pattern, bpf)

		if err := os.WriteFile(ruleFile, []byte(bpf), 0644); err != nil {
			log.Printf("Failed to write rule file %s: %v", ruleFile, err)
			continue
		}

		if err := startTcpdumpCapture(pattern, bpf); err != nil {
			log.Printf("Failed to start tcpdump for %s: %v", pattern, err)
			continue
		}

		activeFilters[pattern] = bpf
		rulesAdded++
		log.Printf("Successfully activated rule for %s", pattern)
	}

	if rulesAdded > 0 {
		log.Printf("Applied %d new or updated BPF rules", rulesAdded)
	}

	return nil
}

func startTcpdumpCapture(name, filter string) error {
	if cmd, exists := runningProcesses[name]; exists {
		log.Printf("Stopping existing capture for %s (PID %d)", name, cmd.Process.Pid)
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); err != nil {
			log.Printf("Warning: failed to kill process group %d: %v", cmd.Process.Pid, err)
		}
		delete(runningProcesses, name)
		time.Sleep(200 * time.Millisecond)
	}

	outputFile := filepath.Join("bpf_logs", sanitizeFilename(name)+".pcap")
	log.Printf("Starting capture for %s -> %s", name, outputFile)

	cmd := exec.Command("tcpdump", "-i", "any", "-nn", "-w", outputFile, filter)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	log.Printf("Running tcpdump command: tcpdump -i any -nn -w %s %s", outputFile, filter)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("tcpdump failed to start: %w", err)
	}

	runningProcesses[name] = cmd
	go monitorProcess(name, cmd)

	log.Printf("Started tcpdump for %s (PID %d)", name, cmd.Process.Pid)
	return nil
}

func monitorProcess(name string, cmd *exec.Cmd) {
	err := cmd.Wait()
	delete(runningProcesses, name)
	if err != nil {
		log.Printf("Capture process for %s ended with error: %v", name, err)
	} else {
		log.Printf("Capture process for %s completed successfully", name)
	}
}

func sanitizeFilename(name string) string {
	var result strings.Builder
	for _, r := range name {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			result.WriteRune(r)
		case r == '-', r == '_', r == '.':
			result.WriteRune(r)
		default:
			result.WriteRune('_')
		}
	}
	return result.String()
}
