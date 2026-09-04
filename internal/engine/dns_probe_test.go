package engine

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProbeDNSRequiresMatchingValidResponse(t *testing.T) {
	t.Parallel()
	valid := startFakeDNSResponder(t, func(query []byte) []byte {
		response := append([]byte(nil), query...)
		binary.BigEndian.PutUint16(response[2:4], 0x8180)
		return response
	})
	if err := probeDNSWithTimeout(context.Background(), valid, 500*time.Millisecond); err != nil {
		t.Fatalf("probeDNSWithTimeout() error = %v", err)
	}

	wrongID := startFakeDNSResponder(t, func(query []byte) []byte {
		response := append([]byte(nil), query...)
		binary.BigEndian.PutUint16(response[0:2], binary.BigEndian.Uint16(response[0:2])+1)
		binary.BigEndian.PutUint16(response[2:4], 0x8180)
		return response
	})
	if err := probeDNSWithTimeout(context.Background(), wrongID, 500*time.Millisecond); err == nil || !strings.Contains(err.Error(), "transaction ID") {
		t.Fatalf("mismatched response error = %v", err)
	}
}

func TestProbeDNSDisabledAndNonresponsive(t *testing.T) {
	t.Parallel()
	if err := probeDNSWithTimeout(context.Background(), DNSEndpoint{}, time.Nanosecond); err != nil {
		t.Fatalf("disabled DNS probe returned %v", err)
	}

	nonresponsive := startFakeDNSResponder(t, func([]byte) []byte { return nil })
	started := time.Now()
	err := probeDNSWithTimeout(context.Background(), nonresponsive, 40*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "read DNS probe response") {
		t.Fatalf("nonresponsive DNS error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("DNS probe exceeded its bound: %s", elapsed)
	}
}

func TestValidateDNSResponseRejectsMalformedRecord(t *testing.T) {
	t.Parallel()
	query, id, err := rootDNSQuery()
	if err != nil {
		t.Fatal(err)
	}
	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response, 0xc0, 0x0c, 0, 1)
	if err := validateDNSResponse(response, id); err == nil {
		t.Fatal("truncated resource record was accepted")
	}
}

func startFakeDNSResponder(t *testing.T, respond func([]byte) []byte) DNSEndpoint {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			read, peer, err := listener.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			response := respond(append([]byte(nil), buffer[:read]...))
			if len(response) > 0 {
				_, _ = listener.WriteToUDP(response, peer)
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	address := listener.LocalAddr().(*net.UDPAddr)
	return DNSEndpoint{Enabled: true, Host: "127.0.0.1", Port: uint16(address.Port)}
}
