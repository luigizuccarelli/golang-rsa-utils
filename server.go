package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"github.com/microlib/simple"
)

func main() {
	logger := &simple.Logger{Level: "trace"}
	cert, err := tls.LoadX509KeyPair("server.pem", "server.key")
	if err != nil {
		logger.Error(fmt.Sprintf("server: loadkeys: %v\n", err))
		os.Exit(-1)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}}
	config.Rand = rand.Reader
	service := "0.0.0.0:8000"
	listener, err := tls.Listen("tcp", service, &config)
	if err != nil {
		logger.Error(fmt.Sprintf("server: listen: %v\n", err))
		os.Exit(-1)
	}
	logger.Info(fmt.Sprintf("server: listening: %s\n", service))
	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error(fmt.Sprintf("server: accept: %v\n", err))
			break
		}
		defer conn.Close()
		logger.Info(fmt.Sprintf("server: accepted from : %s\n", conn.RemoteAddr()))
		tlscon, ok := conn.(*tls.Conn)
		if ok {
			logger.Info("ok == true")
			state := tlscon.ConnectionState()
			for _, v := range state.PeerCertificates {
				key, _ := x509.MarshalPKIXPublicKey(v.PublicKey)
				logger.Debug(fmt.Sprintf("server: keys : %v\n", key))
			}
		}
		go handleClient(conn, logger)
	}
}

func handleClient(conn net.Conn, logger *simple.Logger) {
	defer conn.Close()
	buf := make([]byte, 2048)
	pubCert, err := ioutil.ReadFile("/tmp/keys/public.pem")
	if err != nil {
		logger.Error(fmt.Sprintf("file data %v\n", err))
		os.Exit(-1)
	}

	for {
		logger.Info("server: conn: waiting\n")
		n, err := conn.Read(buf)
		if err != nil {
			if err != nil {
				logger.Error(fmt.Sprintf("server: conn: read: %v\n", err))
			}
			break
		}
		logger.Debug(fmt.Sprintf("server: read : %q\n", string(buf[:n])))
		err = ioutil.WriteFile("/tmp/keys/blockhain-receiver-public.pem", buf[:n], 0644)
		if err != nil {
			logger.Error(fmt.Sprintf("server : file write: %v\n", err))
			os.Exit(-1)
		}

		n, err = conn.Write(pubCert[:n])

		n, err = conn.Write(pubCert[:n])
		logger.Debug(fmt.Sprintf("server: conn: wrote %d bytes\n", n))

		if err != nil {
			logger.Error(fmt.Sprintf("server : write: %v\n", err))
			break
		}
	}
	logger.Info("server: conn: closed")
}
