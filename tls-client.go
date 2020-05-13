package main

import (
	"crypto/tls"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ", os.Args[0], "host:port")
		os.Exit(1)
	}
	//service := os.Args[1]

	cert, err := tls.LoadX509KeyPair("cliint.pem", "client.key")
	if err != nil {
		fmt.Println("server: loadkeys: %s", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", "127.0.0.1:1200", &config)

	//conn, err := tls.Dial("tcp", service, nil)
	checkError(err)

	for n := 0; n < 3; n++ {
		fmt.Println("Writing...")
		conn.Write([]byte("Hello \n"))

		var buf [512]byte
		n, err := conn.Read(buf[0:])
		checkError(err)

		fmt.Println("Reading .. ", string(buf[0:n]))
	}
	os.Exit(0)
}

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}
