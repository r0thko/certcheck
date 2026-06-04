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
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorYellow = "\033[33m"
	Bold        = "\033[1m"
)

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
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			continue
		}
		checkCertificate(endpoint)
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

func checkCertificate(endpoint string) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		fmt.Printf("%s -> ERROR: invalid endpoint\n", endpoint)
		return
	}

	conn, err := tls.Dial("tcp", endpoint, &tls.Config{
		ServerName: host,
	})
	if err != nil {
		fmt.Printf("%s -> ERROR: %v\n", host, err)
		return
	}
	defer conn.Close()
	cert := conn.ConnectionState().PeerCertificates[0]
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
	status := fmt.Sprintf("%d days left", daysRemaining)

	if daysRemaining < 15 {
		status = fmt.Sprintf("%s%s%s%s",
			Bold,
			ColorRed,
			status,
			ColorReset,
		)
	} else if daysRemaining < 30 {
		status = fmt.Sprintf("%s%s%s%s",
			Bold,
			ColorYellow,
			status,
			ColorReset,
		)
	}

	fmt.Printf(
		"%-25s | %-25s | %-12s | %s\n",
		endpoint,
		cert.Subject.CommonName,
		cert.NotAfter.Format("2006-01-02"),
		status,
	)

}
