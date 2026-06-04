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

func main() {
	data, err := os.ReadFile("endpoints.list")
	if err != nil {
		panic(err)
	}
	endpoints := strings.Split(string(data), "\n")

	endpoints, err = NormalizeEndpoints(endpoints)
	if err != nil {
		errors.New("could not normalize endpoints.list: " + err.Error())
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
	normalizedEndpoints := make([]string, len(endpoints))
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
	host, port, err := net.SplitHostPort(endpoint)
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
	fmt.Printf(
		"%s:%s | %s | expires: %s | %d days left\n",
		host,
		port,
		cert.Subject.CommonName,
		cert.NotAfter.Format("2006-01-02"),
		daysRemaining,
	)

}
