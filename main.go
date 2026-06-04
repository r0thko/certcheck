package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	ColorReset        = "\033[0m"
	ColorRed          = "\033[31m"
	ColorYellow       = "\033[33m"
	Bold              = "\033[1m"
	CriticalTime      = 10
	WarningTime       = 30
	ConnectionTimeout = 3 * time.Second
)

type Severity string

const (
	SeverityOK       Severity = ""
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

type CertInfo struct {
	Endpoint   string
	CommonName string
	Expires    string
	Status     string
	DaysLeft   int
	Severity   Severity
}

type EndpointError struct {
	Endpoint string
	Error    string
}

func main() {
	var results []CertInfo
	var errors []EndpointError

	if len(os.Args) < 2 {
		fmt.Println("Usage: certcheck <endpoints-file>")
		os.Exit(1)
	}

	file := os.Args[1]

	endpoints, err := LoadEndpoints(file)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	endpoints = NormalizeEndpoints(endpoints)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	for _, endpoint := range endpoints {
		result, err := GetCertificateInfo(endpoint)
		if err != nil {
			errors = append(errors, EndpointError{
				Endpoint: endpoint,
				Error:    ClassifyError(err),
			})
			continue
		}

		results = append(results, result)
	}

	PrintResults(results)
	PrintErrors(errors)
}

func LoadEndpoints(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	endpoints := strings.Split(string(data), "\n")
	return endpoints, nil
}

func NormalizeEndpoints(endpoints []string) []string {
	normalizedEndpoints := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint == "" {
			continue
		}

		if strings.HasPrefix(endpoint, "#") {
			continue
		}

		endpoint = strings.TrimSpace(endpoint)

		if !strings.Contains(endpoint, ":") {
			endpoint += ":443"
		}
		normalizedEndpoints = append(normalizedEndpoints, endpoint)
	}
	return normalizedEndpoints
}

func GetCertificateInfo(endpoint string) (CertInfo, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return CertInfo{}, err
	}

	dialer := &net.Dialer{
		Timeout: ConnectionTimeout,
	}

	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		endpoint,
		&tls.Config{
			ServerName: host,
		},
	)
	if err != nil {
		return CertInfo{}, err
	}

	defer conn.Close()
	cert := conn.ConnectionState().PeerCertificates[0]
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
	status := fmt.Sprintf("%d days left", daysRemaining)

	severity := SeverityOK

	if daysRemaining < CriticalTime {
		severity = SeverityCritical
	} else if daysRemaining < WarningTime {
		severity = SeverityWarning
	}

	return CertInfo{
		Endpoint:   endpoint,
		CommonName: cert.Subject.CommonName,
		Expires:    cert.NotAfter.Format("2006-01-02"),
		Status:     status,
		DaysLeft:   daysRemaining,
		Severity:   severity,
	}, nil

}

func PrintResults(results []CertInfo) {
	endpointWidth := len("ENDPOINT")
	commonNameWidth := len("COMMON NAME")
	expiresWidth := len("EXPIRES")
	statusWidth := len("STATUS")
	remarkWidth := len("REMARK")

	for _, result := range results {
		if len(result.Endpoint) > endpointWidth {
			endpointWidth = len(result.Endpoint)
		}

		if len(result.CommonName) > commonNameWidth {
			commonNameWidth = len(result.CommonName)
		}

		if len(result.Expires) > expiresWidth {
			expiresWidth = len(result.Expires)
		}

		if len(result.Status) > statusWidth {
			statusWidth = len(result.Status)
		}

		if len(result.Severity) > remarkWidth {
			remarkWidth = len(result.Severity)
		}
	}

	format := fmt.Sprintf(
		"%%-%ds | %%-%ds | %%-%ds | %%-%ds | %%-%ds\n",
		endpointWidth,
		commonNameWidth,
		expiresWidth,
		statusWidth,
		remarkWidth,
	)

	fmt.Printf(
		format,
		"ENDPOINT",
		"COMMON NAME",
		"EXPIRES",
		"STATUS",
		"REMARK",
	)

	for _, result := range results {
		rowPrefix := ""
		rowSuffix := ColorReset

		switch result.Severity {
		case SeverityCritical:
			rowPrefix = Bold + ColorRed
		case SeverityWarning:
			rowPrefix = Bold + ColorYellow
		}

		fmt.Printf(
			rowPrefix+format+rowSuffix,
			result.Endpoint,
			result.CommonName,
			result.Expires,
			result.Status,
			result.Severity,
		)
	}
}

func PrintErrors(errors []EndpointError) {
	if len(errors) == 0 {
		return
	}

	endpointWidth := len("ENDPOINT")
	errorWidth := len("ERROR")

	for _, err := range errors {
		if len(err.Endpoint) > endpointWidth {
			endpointWidth = len(err.Endpoint)
		}

		if len(err.Error) > errorWidth {
			errorWidth = len(err.Error)
		}
	}
	format := fmt.Sprintf(
		"%%-%ds | %%-%ds\n",
		endpointWidth,
		errorWidth,
	)
	fmt.Println()
	fmt.Println("FAILED CHECKS")
	fmt.Println("-------------")

	fmt.Printf(
		format,
		"ENDPOINT",
		"ERROR",
	)

	for _, err := range errors {
		fmt.Printf(
			format,
			err.Endpoint,
			err.Error,
		)
	}
}

func ClassifyError(err error) string {
	var dnsErr *net.DNSError

	if errors.As(err, &dnsErr) {
		return "host not found"
	}

	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return "connection timeout"
	}

	return err.Error()
}
