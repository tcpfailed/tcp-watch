package main

import (
    "bufio"
    "fmt"
    "os"
    "strings"
    "time"
)

const (
    bpfFile = "/tmp/tcpwatch_bpf.txt"
)

func main() {
    seen := make(map[string]bool)

    for {
        file, err := os.Open(bpfFile)
        if err != nil {
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
                continue
            }

            pattern := parts[0]
            bpf := parts[1]

            fmt.Printf("[BPFMaker] New BPF for %s:\n  %s\n", pattern, bpf)
            saveBPFRule(pattern, bpf)
        }

        file.Close()
        time.Sleep(5 * time.Second)
    }
}

func saveBPFRule(name, rule string) {
    filename := fmt.Sprintf("bpf_rules/%s.bpf", strings.ReplaceAll(name, " ", "_"))
    _ = os.MkdirAll("bpf_rules", 0755)
    f, err := os.Create(filename)
    if err != nil {
        fmt.Printf("[!] Failed to save BPF rule: %v\n", err)
        return
    }
    defer f.Close()

    _, _ = f.WriteString(rule)
}
