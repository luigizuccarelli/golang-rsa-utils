package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/microlib/simple"
)

func main() {
	logger := &simple.Logger{Level: "trace"}

	cert, err := tls.LoadX509KeyPair("client.pem", "client.key")
	if err != nil {
		logger.Error(fmt.Sprintf("client: loadkeys: %v", err))
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", "127.0.0.1:8000", &config)
	if err != nil {
		logger.Error(fmt.Sprintf("client: dial: %s", err))
	}
	defer conn.Close()
	logger.Info(fmt.Sprintf("client: connected to: %s\n", conn.RemoteAddr()))

	state := conn.ConnectionState()
	for _, v := range state.PeerCertificates {
		fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
		fmt.Println(v.Subject)
	}
	logger.Info(fmt.Sprintf("client: handshake: %v\n", state.HandshakeComplete))
	logger.Info(fmt.Sprintf("client: mutual: %v\n", state.NegotiatedProtocolIsMutual))

	// this is a one shot action
	// if it fails the re-try will come from the server

	pubCert, err := ioutil.ReadFile("/tmp/keys/receiver-public.pem")
	if err != nil {
		logger.Error(fmt.Sprintf("file data %v\n", err))
		os.Exit(-1)
	}

	//message := "Hello\n"
	n, err := conn.Write(pubCert[:len(pubCert)])
	if err != nil {
		logger.Error(fmt.Sprintf("client : write: %v\n", err))
		os.Exit(-1)
	}
	logger.Info(fmt.Sprintf("client: wrote: %q (%d bytes)\n", pubCert, n))

	reply := make([]byte, 2048)
	n, err = conn.Read(reply)
	err = ioutil.WriteFile("/tmp/keys/blockhain-server-public.pem", reply[:n], 0644)
	if err != nil {
		logger.Error(fmt.Sprintf("client : write: %v\n", err))
		os.Exit(-1)
	}

	logger.Info(fmt.Sprintf("client: read: %q (%d bytes)\n", string(reply[:n]), n))
	logger.Info("client: exiting")
}
