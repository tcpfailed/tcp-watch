package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	bpfFile = "/tmp/tcpwatch_bpf.txt"
)

var (
	runningProcesses = make(map[string]*exec.Cmd)
)

func main() {
	if err := ensureBPFFileExists(); err != nil {
		fmt.Printf("[!] Could not ensure BPF file exists: %v\n", err)
		return
	}

	_ = os.MkdirAll("bpf_rules", 0755)
	_ = os.MkdirAll("bpf_logs", 0755)

	seen := make(map[string]bool)
	fmt.Println("[BPFMaker] Starting BPF filter processor...")

	for {
		processBPFFile(seen)
		time.Sleep(5 * time.Second)
	}
}

func processBPFFile(seen map[string]bool) {
	file, err := os.Open(bpfFile)
	if err != nil {
		fmt.Printf("[!] Failed to open BPF file: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || seen[line] {
			continue
		}

		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			fmt.Printf("[!] Invalid line format: %s\n", line)
			continue
		}

		pattern := strings.TrimSpace(parts[0])
		bpf := strings.TrimSpace(parts[1])
		seen[line] = true

		fmt.Printf("[BPFMaker] New BPF for %s\n", pattern)
		fmt.Printf("  Filter: %s\n", bpf)

		saveBPFRule(pattern, bpf)
		applyBPFFilter(pattern, bpf)
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("[!] Error reading BPF file: %v\n", err)
	}
}

func ensureBPFFileExists() error {
	if _, err := os.Stat(bpfFile); os.IsNotExist(err) {
		f, err := os.Create(bpfFile)
		if err != nil {
			return fmt.Errorf("failed to create BPF file: %w", err)
		}
		defer f.Close()
		fmt.Println("[*] Created missing BPF input file:", bpfFile)
	}
	return nil
}

func saveBPFRule(name, rule string) {
	filename := filepath.Join("bpf_rules", sanitizeFilename(name)+".bpf")
	f, err := os.Create(filename)
	if err != nil {
		fmt.Printf("[!] Failed to save BPF rule: %v\n", err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(rule); err != nil {
		fmt.Printf("[!] Failed to write BPF rule: %v\n", err)
	} else {
		fmt.Printf("[+] Saved BPF rule to %s\n", filename)
	}
}

func applyBPFFilter(name, rule string) {
	if cmd, exists := runningProcesses[name]; exists {
		if err := cmd.Process.Kill(); err != nil {
			fmt.Printf("[!] Failed to kill existing process for %s: %v\n", name, err)
		}
		delete(runningProcesses, name)
	}

	outFile := filepath.Join("bpf_logs", sanitizeFilename(name)+".pcap")
	
	cmd := exec.Command("tcpdump", "-i", "any", "-w", outFile, rule)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Printf("[!] Failed to start tcpdump: %v\n", err)
		return
	}

	runningProcesses[name] = cmd
	fmt.Printf("[+] Started tcpdump for '%s' (PID: %d)\n", name, cmd.Process.Pid)
	fmt.Printf("    Output: %s\n", outFile)
	fmt.Printf("    Filter: %s\n", rule)
}

func sanitizeFilename(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-':
		case r == '_':
		case r == '.':
			return r
		default:
			return '_'
		}
		return r
	}, name)
}
