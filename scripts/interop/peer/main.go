// Interop peer for the polymorph:tls rigs: an independent TLS 1.3 and QUIC
// implementation (Go crypto/tls and quic-go) on the other side of the
// wire from the wasm guests.
//
// All modes speak the rigs' echo protocol: one LF-terminated request
// line, one LF-terminated response line. Servers bind 127.0.0.1:0,
// print "listening on port N" on stdout, and serve exactly one
// connection.
//
//	peer tls-server -cert leaf.pem -key key.pem [-close clean|fin|rst]
//	peer tls-client -port N -ca ca.pem -payload TEXT
//	peer quic-server -cert leaf.pem -key key.pem
//	peer quic-client -port N -ca ca.pem -payload TEXT
//
// tls-server close modes: "clean" waits for the client's close_notify
// and answers with its own; "fin" half-closes the TCP write direction
// after the response without sending close_notify; "rst" closes with
// SO_LINGER set to zero so the close emits a reset.
//
// tls-client verifies the server against -ca, sends close_notify after
// the response arrives, and requires the server's own close_notify in
// return: it exits nonzero on truncation.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	tlsALPN    = "tls-interop/1"
	quicALPN   = "quic-interop/1"
	serverName = "localhost"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: peer <tls-server|tls-client|quic-server|quic-client> [flags]")
	}
	mode, args := os.Args[1], os.Args[2:]

	flags := flag.NewFlagSet(mode, flag.ExitOnError)
	certFile := flags.String("cert", "", "server certificate (PEM)")
	keyFile := flags.String("key", "", "server private key (PEM)")
	closeMode := flags.String("close", "clean", "tls-server close mode: clean|fin|rst")
	port := flags.Int("port", 0, "server port to connect to")
	caFile := flags.String("ca", "", "root CA to verify the server against (PEM)")
	payload := flags.String("payload", "hello-from-go", "request line to send")
	if err := flags.Parse(args); err != nil {
		fatalf("%v", err)
	}

	var err error
	switch mode {
	case "tls-server":
		err = tlsServer(*certFile, *keyFile, *closeMode)
	case "tls-client":
		err = tlsClient(*port, *caFile, *payload)
	case "quic-server":
		err = quicServer(*certFile, *keyFile)
	case "quic-client":
		err = quicClient(*port, *caFile, *payload)
	default:
		err = fmt.Errorf("unknown mode %q", mode)
	}
	if err != nil {
		fatalf("%s: %v", mode, err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "peer: "+format+"\n", args...)
	os.Exit(1)
}

func serverTLSConfig(certFile, keyFile string, alpn string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpn},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func clientTLSConfig(caFile string, alpn string) (*tls.Config, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates in %s", caFile)
	}
	return &tls.Config{
		RootCAs:    roots,
		ServerName: serverName,
		NextProtos: []string{alpn},
		MinVersion: tls.VersionTLS13,
	}, nil
}

func announce(port int) {
	fmt.Printf("listening on port %d\n", port)
}

func tlsServer(certFile, keyFile, closeMode string) error {
	switch closeMode {
	case "clean", "fin", "rst":
	default:
		return fmt.Errorf("unknown close mode %q", closeMode)
	}
	config, err := serverTLSConfig(certFile, keyFile, tlsALPN)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	announce(listener.Addr().(*net.TCPAddr).Port)

	tcpConn, err := listener.Accept()
	if err != nil {
		return err
	}
	conn := tls.Server(tcpConn, config)

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	fmt.Printf("request: %s", line)
	if _, err := conn.Write([]byte(line)); err != nil {
		return fmt.Errorf("write response: %w", err)
	}

	switch closeMode {
	case "clean":
		// Wait for the client's close_notify, then answer with ours.
		if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
			return fmt.Errorf("expected client close_notify, got %v", err)
		}
		fmt.Println("client close: clean close_notify")
		return conn.Close()
	case "fin":
		// Skip close_notify: half-close the TCP write direction, then
		// drain the client's remaining bytes so its own shutdown does
		// not land on a closed socket (which would turn into a reset).
		fmt.Println("closing without close_notify (FIN)")
		if err := tcpConn.(*net.TCPConn).CloseWrite(); err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, tcpConn)
		return tcpConn.Close()
	case "rst":
		// Skip close_notify and discard the send queue: reset.
		fmt.Println("closing without close_notify (RST)")
		if err := tcpConn.(*net.TCPConn).SetLinger(0); err != nil {
			return err
		}
		return tcpConn.Close()
	}
	return nil
}

func tlsClient(port int, caFile, payload string) error {
	config, err := clientTLSConfig(caFile, tlsALPN)
	if err != nil {
		return err
	}
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), config)
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Printf("handshake complete (ALPN %s)\n", conn.ConnectionState().NegotiatedProtocol)

	if _, err := fmt.Fprintf(conn, "%s\n", payload); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	fmt.Printf("response: %s", line)
	if line != payload+"\n" {
		return fmt.Errorf("response does not echo request %q", payload)
	}

	// Close our write direction, then demand a clean close in return:
	// io.EOF is close_notify, anything else is truncation or failure.
	if err := conn.CloseWrite(); err != nil {
		return err
	}
	switch _, err := reader.ReadByte(); {
	case errors.Is(err, io.EOF):
		fmt.Println("server close: clean close_notify")
		return nil
	default:
		return fmt.Errorf("server close: not close_notify: %v", err)
	}
}

func quicServer(certFile, keyFile string) error {
	config, err := serverTLSConfig(certFile, keyFile, quicALPN)
	if err != nil {
		return err
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", config, nil)
	if err != nil {
		return err
	}
	defer listener.Close()
	announce(listener.Addr().(*net.UDPAddr).Port)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := listener.Accept(ctx)
	if err != nil {
		return err
	}
	fmt.Println("connection accepted")

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	request, err := io.ReadAll(stream)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	fmt.Printf("request: %s\n", request)
	if _, err := stream.Write(request); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	if err := stream.Close(); err != nil {
		return err
	}

	// The client closes the connection once it has the echo.
	<-conn.Context().Done()
	fmt.Println("connection closed by client")
	return nil
}

func quicClient(port int, caFile, payload string) error {
	config, err := clientTLSConfig(caFile, quicALPN)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", port), config, nil)
	if err != nil {
		return err
	}
	fmt.Printf("handshake complete (ALPN %s)\n", conn.ConnectionState().TLS.NegotiatedProtocol)

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	if _, err := stream.Write([]byte(payload)); err != nil {
		return err
	}
	if err := stream.Close(); err != nil {
		return err
	}
	response, err := io.ReadAll(stream)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	fmt.Printf("response: %s\n", response)
	if string(response) != payload {
		return fmt.Errorf("response does not echo request %q", payload)
	}
	return conn.CloseWithError(0, "done")
}
