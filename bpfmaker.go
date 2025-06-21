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

func main() {
    if err := ensureBPFFileExists(); err != nil {
        fmt.Printf("[!] Could not ensure BPF file exists: %v\n", err)
        return
    }

    seen := make(map[string]bool)

    for {
        file, err := os.Open(bpfFile)
        if err != nil {
            fmt.Printf("[!] Failed to open file: %v\n", err)
            time.Sleep(2 * time.Second)
            continue
        }

        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
            line := scanner.Text()
            if seen[line] {
                continue
            }
            seen[line] = true

            parts := strings.SplitN(line, "|", 2)
            if len(parts) != 2 {
                fmt.Println("[!] Invalid line format")
                continue
            }

            pattern := parts[0]
            bpf := parts[1]

            fmt.Printf("[BPFMaker] New BPF for %s:\n  %s\n", pattern, bpf)
            saveBPFRule(pattern, bpf)
            applyBPFFilter(pattern, bpf)
        }

        file.Close()
        time.Sleep(5 * time.Second)
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
    _ = os.MkdirAll("bpf_rules", 0755)
    filename := filepath.Join("bpf_rules", strings.ReplaceAll(name, " ", "_")+".bpf")
    f, err := os.Create(filename)
    if err != nil {
        fmt.Printf("[!] Failed to save BPF rule: %v\n", err)
        return
    }
    defer f.Close()
    _, _ = f.WriteString(rule)
}

func applyBPFFilter(name, rule string) {
    outFile := filepath.Join("bpf_logs", strings.ReplaceAll(name, " ", "_")+".pcap")
    _ = os.MkdirAll("bpf_logs", 0755)

    cmd := exec.Command("tcpdump", "-i", "any", "-w", outFile, rule)
    err := cmd.Start()
    if err != nil {
        fmt.Printf("[!] Failed to start tcpdump: %v\n", err)
        return
    }
    fmt.Printf("[+] tcpdump started for '%s', writing to %s\n", name, outFile)
}
