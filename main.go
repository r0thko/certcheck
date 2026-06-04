package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	ColorReset   = "\033[0m"
	ColorRed     = "\033[31m"
	ColorYellow  = "\033[33m"
	Bold         = "\033[1m"
	CriticalTime = 10
	WarningTime  = 30
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

var results []CertInfo

func main() {
	data, err := os.ReadFile("endpoints.list")
	if err != nil {
		panic(err)
	}
	endpoints := strings.Split(string(data), "\n")

	endpoints, err = NormalizeEndpoints(endpoints)
	if err != nil {
		fmt.Println("Could not normalize endpoints.list:", err)
		return
	}

	for _, endpoint := range endpoints {
		result, err := checkCertificate(endpoint)
		if err != nil {
			continue
		}

		results = append(results, result)
	}

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

func NormalizeEndpoints(endpoints []string) ([]string, error) {
	normalizedEndpoints := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint == "" {
			continue
		}

		endpoint = strings.TrimSpace(endpoint)

		if !strings.Contains(endpoint, ":") {
			endpoint += ":443"
		}
		normalizedEndpoints = append(normalizedEndpoints, endpoint)
	}
	return normalizedEndpoints, nil
}

func checkCertificate(endpoint string) (CertInfo, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		fmt.Printf("%s -> ERROR: invalid endpoint\n", endpoint)
		return CertInfo{}, err
	}

	conn, err := tls.Dial("tcp", endpoint, &tls.Config{
		ServerName: host,
	})
	if err != nil {
		fmt.Printf("%s -> ERROR: %v\n", host, err)
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
