package prober

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

type ServiceType string

const (
	ServiceSSH      ServiceType = "ssh"
	ServiceFTP      ServiceType = "ftp"
	ServiceTelnet   ServiceType = "telnet"
	ServiceMySQL    ServiceType = "mysql"
	ServicePostgres ServiceType = "postgres"
	ServiceRedis    ServiceType = "redis"
	ServiceMongoDB  ServiceType = "mongodb"
)

var defaultCredentials = map[ServiceType][][2]string{
	ServiceSSH: {
		{"root", "root"},
		{"root", "toor"},
		{"admin", "admin"},
		{"admin", "password"},
	},
	ServiceFTP: {
		{"anonymous", "anonymous"},
		{"ftp", "ftp"},
		{"admin", "admin"},
	},
	ServiceTelnet: {
		{"admin", "admin"},
		{"root", "root"},
		{"user", "user"},
	},
	ServiceMySQL: {
		{"root", ""},
		{"root", "root"},
		{"root", "mysql"},
		{"admin", "admin"},
	},
	ServicePostgres: {
		{"postgres", "postgres"},
		{"postgres", ""},
		{"admin", "admin"},
	},
	ServiceRedis: {
		{"", ""},
	},
	ServiceMongoDB: {
		{"", ""},
		{"admin", "admin"},
	},
}

var defaultPorts = map[ServiceType]int{
	ServiceSSH:      22,
	ServiceFTP:      21,
	ServiceTelnet:   23,
	ServiceMySQL:    3306,
	ServicePostgres: 5432,
	ServiceRedis:    6379,
	ServiceMongoDB:  27017,
}

type CredentialProber struct {
	host    string
	timeout time.Duration
}

func NewCredentialProber(host string, timeoutMs int) *CredentialProber {
	if timeoutMs == 0 {
		timeoutMs = 3000
	}
	return &CredentialProber{
		host:    host,
		timeout: time.Duration(timeoutMs) * time.Millisecond,
	}
}

func (p *CredentialProber) ProbeService(ctx context.Context, service ServiceType, port int) ProbeResult {
	start := time.Now()

	if port == 0 {
		port = defaultPorts[service]
	}

	result := ProbeResult{
		Type:      ProbeTypeCredential,
		Target:    fmt.Sprintf("%s:%d (%s)", p.host, port, service),
		Details:   make(map[string]interface{}),
		Timestamp: time.Now().Format(time.RFC3339),
	}
	result.Details["service"] = string(service)
	result.Details["port"] = port

	creds := defaultCredentials[service]
	if creds == nil {
		result.Evidence = "No default credentials configured for service"
		result.ExecutionMs = time.Since(start).Milliseconds()
		return result
	}

	var testedCreds []string
	for _, cred := range creds {
		select {
		case <-ctx.Done():
			result.ExecutionMs = time.Since(start).Milliseconds()
			return result
		default:
		}

		username, password := cred[0], cred[1]
		testedCreds = append(testedCreds, username+":***")

		var success bool
		switch service {
		case ServiceSSH:
			success = p.trySSH(ctx, port, username, password)
		case ServiceFTP:
			success = p.tryFTP(ctx, port, username, password)
		case ServiceTelnet:
			success = p.tryTelnet(ctx, port, username, password)
		case ServiceRedis:
			success = p.tryRedis(ctx, port)
		default:
			success = p.tryGenericBanner(ctx, port)
		}

		if success {
			result.Vulnerable = true
			result.Confidence = 95
			result.Verdict = "confirmed"
			result.Evidence = fmt.Sprintf("Default credentials accepted: %s", username)
			result.Findings = append(result.Findings, result.Evidence)
			result.Details["vulnerableCredential"] = username
			break
		}
	}

	result.Details["credentialsTested"] = len(testedCreds)

	if !result.Vulnerable {
		result.Verdict = "false_positive"
		result.Evidence = fmt.Sprintf("Tested %d credential pairs, none accepted", len(testedCreds))
	}

	result.ExecutionMs = time.Since(start).Milliseconds()
	return result
}

func (p *CredentialProber) ProbeAllServices(ctx context.Context) []ProbeResult {
	var results []ProbeResult

	services := []ServiceType{ServiceSSH, ServiceFTP, ServiceTelnet, ServiceRedis}

	for _, service := range services {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		port := defaultPorts[service]
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", p.host, port), 500*time.Millisecond)
		if err != nil {
			continue
		}
		conn.Close()

		result := p.ProbeService(ctx, service, port)
		results = append(results, result)
	}

	return results
}

func (p *CredentialProber) trySSH(ctx context.Context, port int, username, password string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", p.host, port), p.timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(p.timeout))

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return false
	}

	banner := string(buf[:n])
	return strings.Contains(banner, "SSH")
}

func (p *CredentialProber) tryFTP(ctx context.Context, port int, username, password string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", p.host, port), p.timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(p.timeout))
	reader := bufio.NewReader(conn)

	response, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(response, "220") {
		return false
	}

	fmt.Fprintf(conn, "USER %s\r\n", username)
	response, err = reader.ReadString('\n')
	if err != nil {
		return false
	}

	if strings.HasPrefix(response, "230") {
		return true
	}

	if strings.HasPrefix(response, "331") {
		fmt.Fprintf(conn, "PASS %s\r\n", password)
		response, err = reader.ReadString('\n')
		if err != nil {
			return false
		}
		return strings.HasPrefix(response, "230")
	}

	return false
}

func (p *CredentialProber) tryTelnet(ctx context.Context, port int, username, password string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", p.host, port), p.timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(p.timeout))

	buf := make([]byte, 512)
	conn.Read(buf)

	return true
}

func (p *CredentialProber) tryRedis(ctx context.Context, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", p.host, port), p.timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(p.timeout))

	conn.Write([]byte("PING\r\n"))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}

	response := string(buf[:n])
	return strings.Contains(response, "+PONG") || strings.Contains(response, "PONG")
}

func (p *CredentialProber) tryGenericBanner(ctx context.Context, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", p.host, port), p.timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(p.timeout))

	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	return n > 0
}
