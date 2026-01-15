package prober

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

type ProbeType string

const (
	ProbeTypeSMTP       ProbeType = "smtp"
	ProbeTypeDNS        ProbeType = "dns"
	ProbeTypeLDAP       ProbeType = "ldap"
	ProbeTypeCredential ProbeType = "credential"
	ProbeTypePortScan   ProbeType = "port_scan"
)

type ProbeResult struct {
	Type        ProbeType              `json:"type"`
	Target      string                 `json:"target"`
	Vulnerable  bool                   `json:"vulnerable"`
	Confidence  int                    `json:"confidence"`
	Verdict     string                 `json:"verdict"`
	Evidence    string                 `json:"evidence"`
	Details     map[string]interface{} `json:"details"`
	Findings    []string               `json:"findings"`
	ExecutionMs int64                  `json:"executionMs"`
	Timestamp   string                 `json:"timestamp"`
}

type ProbeConfig struct {
	Host    string   `json:"host"`
	Port    int      `json:"port"`
	Timeout int      `json:"timeout"` // milliseconds
	Probes  []string `json:"probes"`
}

type Prober struct {
	config ProbeConfig
}

func New(config ProbeConfig) *Prober {
	if config.Timeout == 0 {
		config.Timeout = 5000
	}
	return &Prober{config: config}
}

func (p *Prober) RunProbes(ctx context.Context) []ProbeResult {
	var results []ProbeResult

	for _, probeType := range p.config.Probes {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		var result ProbeResult
		switch ProbeType(probeType) {
		case ProbeTypeSMTP:
			result = p.probeSMTP(ctx)
		case ProbeTypeDNS:
			result = p.probeDNS(ctx)
		case ProbeTypeLDAP:
			result = p.probeLDAP(ctx)
		case ProbeTypePortScan:
			result = p.probePortScan(ctx)
		default:
			result = ProbeResult{
				Type:       ProbeType(probeType),
				Target:     p.config.Host,
				Vulnerable: false,
				Evidence:   "Unknown probe type: " + probeType,
				Timestamp:  time.Now().Format(time.RFC3339),
			}
		}
		results = append(results, result)
	}

	return results
}

func (p *Prober) probeSMTP(ctx context.Context) ProbeResult {
	start := time.Now()
	port := p.config.Port
	if port == 0 {
		port = 25
	}

	result := ProbeResult{
		Type:      ProbeTypeSMTP,
		Target:    fmt.Sprintf("%s:%d", p.config.Host, port),
		Details:   make(map[string]interface{}),
		Timestamp: time.Now().Format(time.RFC3339),
	}

	timeout := time.Duration(p.config.Timeout) * time.Millisecond
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", p.config.Host, port), timeout)
	if err != nil {
		result.Evidence = "Connection failed: " + err.Error()
		result.ExecutionMs = time.Since(start).Milliseconds()
		return result
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		banner := string(buf[:n])
		result.Details["banner"] = strings.TrimSpace(banner)

		if strings.HasPrefix(banner, "220") {
			conn.Write([]byte("EHLO test.local\r\n"))
			n, _ = conn.Read(buf)
			ehloResponse := string(buf[:n])
			result.Details["ehloResponse"] = strings.TrimSpace(ehloResponse)

			conn.Write([]byte("VRFY postmaster\r\n"))
			n, _ = conn.Read(buf)
			vrfyResponse := string(buf[:n])
			vrfyEnabled := strings.HasPrefix(vrfyResponse, "250") || strings.HasPrefix(vrfyResponse, "252")
			result.Details["vrfyEnabled"] = vrfyEnabled

			if vrfyEnabled {
				result.Vulnerable = true
				result.Confidence = 60
				result.Findings = append(result.Findings, "VRFY command enabled - allows user enumeration")
			}

			if !strings.Contains(ehloResponse, "AUTH") {
				result.Vulnerable = true
				result.Confidence = max(result.Confidence, 40)
				result.Findings = append(result.Findings, "No authentication required")
			}

			conn.Write([]byte("QUIT\r\n"))
		}
	}

	if result.Vulnerable {
		result.Verdict = "likely"
		result.Evidence = strings.Join(result.Findings, "; ")
	} else {
		result.Verdict = "false_positive"
		result.Evidence = "SMTP server appears properly configured"
	}

	result.ExecutionMs = time.Since(start).Milliseconds()
	return result
}

func (p *Prober) probeDNS(ctx context.Context) ProbeResult {
	start := time.Now()
	port := p.config.Port
	if port == 0 {
		port = 53
	}

	result := ProbeResult{
		Type:      ProbeTypeDNS,
		Target:    fmt.Sprintf("%s:%d", p.config.Host, port),
		Details:   make(map[string]interface{}),
		Timestamp: time.Now().Format(time.RFC3339),
	}

	timeout := time.Duration(p.config.Timeout) * time.Millisecond
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", p.config.Host, port), timeout)
	if err != nil {
		result.Evidence = "Connection failed: " + err.Error()
		result.ExecutionMs = time.Since(start).Milliseconds()
		return result
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	query := []byte{
		0x12, 0x34,
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01,
		0x00, 0x01,
	}

	conn.Write(query)
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err == nil && n > 12 {
		flags := uint16(buf[2])<<8 | uint16(buf[3])
		ra := (flags & 0x0080) != 0
		rcode := flags & 0x000F

		if ra && rcode == 0 {
			result.Vulnerable = true
			result.Confidence = 60
			result.Findings = append(result.Findings, "DNS recursion enabled - potential amplification attack vector")
			result.Details["recursionEnabled"] = true
		}
	}

	if result.Vulnerable {
		result.Verdict = "likely"
		result.Evidence = strings.Join(result.Findings, "; ")
	} else {
		result.Verdict = "false_positive"
		result.Evidence = "DNS server appears properly configured"
	}

	result.ExecutionMs = time.Since(start).Milliseconds()
	return result
}

func (p *Prober) probeLDAP(ctx context.Context) ProbeResult {
	start := time.Now()
	port := p.config.Port
	if port == 0 {
		port = 389
	}

	result := ProbeResult{
		Type:      ProbeTypeLDAP,
		Target:    fmt.Sprintf("%s:%d", p.config.Host, port),
		Details:   make(map[string]interface{}),
		Timestamp: time.Now().Format(time.RFC3339),
	}

	timeout := time.Duration(p.config.Timeout) * time.Millisecond
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", p.config.Host, port), timeout)
	if err != nil {
		result.Evidence = "Connection failed: " + err.Error()
		result.ExecutionMs = time.Since(start).Milliseconds()
		return result
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	anonymousBind := []byte{
		0x30, 0x0c,
		0x02, 0x01, 0x01,
		0x60, 0x07,
		0x02, 0x01, 0x03,
		0x04, 0x00,
		0x80, 0x00,
	}

	conn.Write(anonymousBind)
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		if n >= 10 && buf[0] == 0x30 {
			for i := 0; i < n-2; i++ {
				if buf[i] == 0x61 {
					if i+4 < n && buf[i+2] == 0x0a && buf[i+3] == 0x01 {
						resultCode := buf[i+4]
						if resultCode == 0 {
							result.Vulnerable = true
							result.Confidence = 80
							result.Findings = append(result.Findings, "Anonymous LDAP bind allowed")
							result.Details["anonymousBindAllowed"] = true
						}
					}
					break
				}
			}
		}
	}

	if result.Vulnerable {
		result.Verdict = "likely"
		result.Evidence = strings.Join(result.Findings, "; ")
	} else {
		result.Verdict = "false_positive"
		result.Evidence = "LDAP server requires authentication"
	}

	result.ExecutionMs = time.Since(start).Milliseconds()
	return result
}

func (p *Prober) probePortScan(ctx context.Context) ProbeResult {
	start := time.Now()

	result := ProbeResult{
		Type:      ProbeTypePortScan,
		Target:    p.config.Host,
		Details:   make(map[string]interface{}),
		Timestamp: time.Now().Format(time.RFC3339),
	}

	commonPorts := []int{22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443}
	var openPorts []int
	timeout := time.Duration(p.config.Timeout/10) * time.Millisecond
	if timeout < 100*time.Millisecond {
		timeout = 100 * time.Millisecond
	}

	for _, port := range commonPorts {
		select {
		case <-ctx.Done():
			break
		default:
		}

		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", p.config.Host, port), timeout)
		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}

	result.Details["openPorts"] = openPorts
	result.Details["scannedPorts"] = len(commonPorts)

	if len(openPorts) > 0 {
		result.Evidence = fmt.Sprintf("Found %d open ports: %v", len(openPorts), openPorts)
		result.Findings = append(result.Findings, result.Evidence)

		for _, port := range openPorts {
			if port == 23 || port == 21 {
				result.Vulnerable = true
				result.Confidence = 50
				result.Findings = append(result.Findings, fmt.Sprintf("Insecure protocol detected on port %d", port))
			}
		}
	} else {
		result.Evidence = "No common ports open or host unreachable"
	}

	if result.Vulnerable {
		result.Verdict = "likely"
	} else {
		result.Verdict = "false_positive"
	}

	result.ExecutionMs = time.Since(start).Milliseconds()
	return result
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
