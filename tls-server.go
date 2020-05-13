package main

import (
	"crypto/rand"
	"crypto/tls"
	//"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {

	cert, err := tls.LoadX509KeyPair("server.pem", "server.key")
	checkError(err)

	//caCertPool, _ := x509.SystemCertPool()
	//caCertPool.AppendCertsFromPEM(cert)

	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

	now := time.Now()
	config.Time = func() time.Time { return now }
	config.Rand = rand.Reader

	service := "0.0.0.0:1200"

	listener, err := tls.Listen("tcp", service, &config)
	checkError(err)
	fmt.Println("Listening")
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err.Error())
			continue
		}
		fmt.Println("Accepted")
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	var buf [512]byte
	for {
		fmt.Println("Trying to read")
		_, err := conn.Read(buf[0:])
		if err != nil {
			fmt.Println(err)
		}
		_, err2 := conn.Write([]byte("LMZ from server\n"))
		if err2 != nil {
			return
		}
	}
}

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}
