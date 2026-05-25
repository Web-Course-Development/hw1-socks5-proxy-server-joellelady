package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	method, err := negotiateAuth(conn)
	if err != nil {
		log.Printf("auth negotiation error: %v", err)
		return
	}

	log.Printf("selected auth method: 0x%02x", method)

	if method == 0x02 {
		err = authenticateUserPass(conn)
		if err != nil {
			log.Printf("authentication failed: %v", err)
			return
		}
	}

	targetAddress, err := readConnectRequest(conn)
	if err != nil {
		log.Printf("CONNECT request error: %v", err)
		sendSocksReply(conn, 0x01)
		return
	}

	log.Printf("target address: %s", targetAddress)

	targetConn, err := net.Dial("tcp", targetAddress)
	if err != nil {
		log.Printf("failed to connect to target: %v", err)
		sendSocksReply(conn, 0x01)
		return
	}
	defer targetConn.Close()

	err = sendSocksReply(conn, 0x00)
	if err != nil {
		log.Printf("failed to send success reply: %v", err)
		return
	}

	relay(conn, targetConn)
}

func negotiateAuth(conn net.Conn) (byte, error) {
	header := make([]byte, 2)

	_, err := io.ReadFull(conn, header)
	if err != nil {
		return 0, err
	}

	version := header[0]
	nMethods := int(header[1])

	if version != 0x05 {
		return 0, fmt.Errorf("unsupported SOCKS version: %d", version)
	}

	methods := make([]byte, nMethods)

	_, err = io.ReadFull(conn, methods)
	if err != nil {
		return 0, err
	}

	authRequired := os.Getenv("PROXY_USER") != ""

	var selectedMethod byte = 0xFF

	for i := 0; i < len(methods); i++ {
		if authRequired && methods[i] == 0x02 {
			selectedMethod = 0x02
		}

		if !authRequired && methods[i] == 0x00 {
			selectedMethod = 0x00
		}
	}

	_, err = conn.Write([]byte{0x05, selectedMethod})
	if err != nil {
		return 0, err
	}

	if selectedMethod == 0xFF {
		return 0, fmt.Errorf("no acceptable authentication method")
	}

	return selectedMethod, nil
}

func authenticateUserPass(conn net.Conn) error {
	header := make([]byte, 2)

	_, err := io.ReadFull(conn, header)
	if err != nil {
		return err
	}

	version := header[0]
	usernameLength := int(header[1])

	if version != 0x01 {
		return fmt.Errorf("unsupported auth version: %d", version)
	}

	usernameBytes := make([]byte, usernameLength)

	_, err = io.ReadFull(conn, usernameBytes)
	if err != nil {
		return err
	}

	passwordLengthBytes := make([]byte, 1)

	_, err = io.ReadFull(conn, passwordLengthBytes)
	if err != nil {
		return err
	}

	passwordLength := int(passwordLengthBytes[0])
	passwordBytes := make([]byte, passwordLength)

	_, err = io.ReadFull(conn, passwordBytes)
	if err != nil {
		return err
	}

	username := string(usernameBytes)
	password := string(passwordBytes)

	expectedUsername := os.Getenv("PROXY_USER")
	expectedPassword := os.Getenv("PROXY_PASS")

	if username == expectedUsername && password == expectedPassword {
		_, err = conn.Write([]byte{0x01, 0x00})
		return err
	}

	_, err = conn.Write([]byte{0x01, 0x01})
	if err != nil {
		return err
	}

	return fmt.Errorf("invalid username or password")
}

func readConnectRequest(conn net.Conn) (string, error) {
	header := make([]byte, 4)

	_, err := io.ReadFull(conn, header)
	if err != nil {
		return "", err
	}

	version := header[0]
	command := header[1]
	reserved := header[2]
	addressType := header[3]

	if version != 0x05 {
		return "", fmt.Errorf("unsupported SOCKS version in request: %d", version)
	}

	if command != 0x01 {
		return "", fmt.Errorf("unsupported command: %d", command)
	}

	if reserved != 0x00 {
		return "", fmt.Errorf("invalid reserved byte: %d", reserved)
	}

	var host string

	if addressType == 0x01 {
		addressBytes := make([]byte, 4)

		_, err = io.ReadFull(conn, addressBytes)
		if err != nil {
			return "", err
		}

		host = net.IP(addressBytes).String()
	} else if addressType == 0x03 {
		lengthBytes := make([]byte, 1)

		_, err = io.ReadFull(conn, lengthBytes)
		if err != nil {
			return "", err
		}

		domainLength := int(lengthBytes[0])
		domainBytes := make([]byte, domainLength)

		_, err = io.ReadFull(conn, domainBytes)
		if err != nil {
			return "", err
		}

		host = string(domainBytes)
	} else {
		return "", fmt.Errorf("unsupported address type: %d", addressType)
	}

	portBytes := make([]byte, 2)

	_, err = io.ReadFull(conn, portBytes)
	if err != nil {
		return "", err
	}

	port := binary.BigEndian.Uint16(portBytes)

	return fmt.Sprintf("%s:%d", host, port), nil
}

func sendSocksReply(conn net.Conn, replyCode byte) error {
	reply := []byte{
		0x05,
		replyCode,
		0x00,
		0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	_, err := conn.Write(reply)
	return err
}

func relay(client net.Conn, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(target, client)

		if tcpConn, ok := target.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, target)

		if tcpConn, ok := client.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
}
