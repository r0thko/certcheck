package main

import (
	"crypto/tls"
	"fmt"
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
	for _, endpoint := range endpoints {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			continue
		}
		checkCertificate(endpoint)
	}

}

func checkCertificate(host string) {

	conn, err := tls.Dial("tcp", host+":443", &tls.Config{})
	if err != nil {
		fmt.Printf("%s -> ERROR: %v\n", host, err)
		return
	}
	defer conn.Close()
	cert := conn.ConnectionState().PeerCertificates[0]
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
	fmt.Printf(
		"%s | %s | expires: %s | %d days left\n",
		host,
		cert.Subject.CommonName,
		cert.NotAfter.Format("2006-01-02"),
		daysRemaining,
	)

}
