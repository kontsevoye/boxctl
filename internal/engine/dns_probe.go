package engine

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const defaultDNSProbeTimeout = time.Second

// ProbeDNS verifies that the local listener can complete a fresh recursive DNS
// request, rather than only checking that a UDP socket can be connected. A
// random name below the reserved .invalid TLD avoids both cache-only success
// and queries for real hostnames. NOERROR and NXDOMAIN prove a usable response;
// resolver failure codes do not.
func ProbeDNS(ctx context.Context, endpoint DNSEndpoint) error {
	return probeDNSWithTimeout(ctx, endpoint, defaultDNSProbeTimeout)
}

func probeDNSWithTimeout(ctx context.Context, endpoint DNSEndpoint, timeout time.Duration) error {
	if !endpoint.Enabled {
		return nil
	}
	if endpoint.Port == 0 {
		return errors.New("DNS probe endpoint has no port")
	}
	if timeout <= 0 {
		return errors.New("DNS probe timeout must be positive")
	}

	host := strings.TrimSpace(endpoint.Host)
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	address := net.JoinHostPort(host, fmt.Sprintf("%d", endpoint.Port))
	probeContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	connection, err := (&net.Dialer{}).DialContext(probeContext, "udp", address)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", address, err)
	}
	defer connection.Close()
	if deadline, ok := probeContext.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return fmt.Errorf("set DNS probe deadline: %w", err)
		}
	}

	query, queryID, queryName, err := dnsProbeQuery()
	if err != nil {
		return err
	}
	if _, err := connection.Write(query); err != nil {
		return fmt.Errorf("send DNS probe: %w", err)
	}
	response := make([]byte, 4096)
	read, err := connection.Read(response)
	if err != nil {
		return fmt.Errorf("read DNS probe response: %w", err)
	}
	if err := validateDNSResponse(response[:read], queryID, queryName); err != nil {
		return fmt.Errorf("invalid DNS probe response: %w", err)
	}
	return nil
}

func dnsProbeQuery() ([]byte, uint16, string, error) {
	const randomLabelBytes = 8
	const probeLabelLength = byte(len("boxctl-") + 2*randomLabelBytes)

	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, 0, "", fmt.Errorf("generate DNS probe ID: %w", err)
	}
	var labelBytes [randomLabelBytes]byte
	if _, err := rand.Read(labelBytes[:]); err != nil {
		return nil, 0, "", fmt.Errorf("generate DNS probe name: %w", err)
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	label := "boxctl-" + hex.EncodeToString(labelBytes[:])
	queryName := label + ".invalid."
	query := make([]byte, 12, 12+1+len(label)+1+len("invalid")+1+4)
	binary.BigEndian.PutUint16(query[0:2], id)
	binary.BigEndian.PutUint16(query[2:4], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(query[4:6], 1)      // one question
	query = append(query, probeLabelLength)
	query = append(query, label...)
	query = append(query, byte(len("invalid")))
	query = append(query, "invalid"...)
	query = append(query, 0, 0, 1, 0, 1) // root terminator, A, IN
	return query, id, queryName, nil
}

func validateDNSResponse(message []byte, queryID uint16, queryName string) error {
	if len(message) < 12 {
		return errors.New("header is truncated")
	}
	if binary.BigEndian.Uint16(message[0:2]) != queryID {
		return errors.New("transaction ID does not match")
	}
	flags := binary.BigEndian.Uint16(message[2:4])
	if flags&0x8000 == 0 {
		return errors.New("message is not a response")
	}
	if flags&0x7800 != 0 {
		return errors.New("response opcode does not match the query")
	}
	if flags&0x0200 != 0 {
		return errors.New("response is truncated")
	}
	responseCode := flags & 0x000f
	if responseCode != 0 && responseCode != 3 {
		return fmt.Errorf("DNS server returned failure response code %d", responseCode)
	}
	if binary.BigEndian.Uint16(message[4:6]) != 1 {
		return errors.New("response does not contain the matching question")
	}

	name, offset, err := readDNSName(message, 12)
	if err != nil {
		return fmt.Errorf("parse question name: %w", err)
	}
	if name != queryName {
		return errors.New("response question name does not match")
	}
	if offset+4 > len(message) {
		return errors.New("question is truncated")
	}
	if binary.BigEndian.Uint16(message[offset:offset+2]) != 1 || binary.BigEndian.Uint16(message[offset+2:offset+4]) != 1 {
		return errors.New("response question type or class does not match")
	}
	offset += 4

	records := uint32(binary.BigEndian.Uint16(message[6:8])) +
		uint32(binary.BigEndian.Uint16(message[8:10])) +
		uint32(binary.BigEndian.Uint16(message[10:12]))
	for record := uint32(0); record < records; record++ {
		_, next, err := readDNSName(message, offset)
		if err != nil {
			return fmt.Errorf("parse resource record name: %w", err)
		}
		if next+10 > len(message) {
			return errors.New("resource record header is truncated")
		}
		rdataLength := int(binary.BigEndian.Uint16(message[next+8 : next+10]))
		offset = next + 10 + rdataLength
		if offset > len(message) {
			return errors.New("resource record data is truncated")
		}
	}
	if offset != len(message) {
		return errors.New("response contains trailing data")
	}
	return nil
}

func readDNSName(message []byte, offset int) (string, int, error) {
	if offset < 0 || offset >= len(message) {
		return "", 0, errors.New("name starts outside the message")
	}
	position := offset
	next := -1
	visited := make(map[int]struct{})
	labels := make([]string, 0, 4)
	expandedLength := 1
	for {
		if position >= len(message) {
			return "", 0, errors.New("name is truncated")
		}
		length := int(message[position])
		switch length & 0xc0 {
		case 0xc0:
			if position+1 >= len(message) {
				return "", 0, errors.New("compression pointer is truncated")
			}
			if next < 0 {
				next = position + 2
			}
			pointer := ((length & 0x3f) << 8) | int(message[position+1])
			if pointer >= len(message) {
				return "", 0, errors.New("compression pointer is outside the message")
			}
			if _, exists := visited[pointer]; exists {
				return "", 0, errors.New("compression pointer loop")
			}
			visited[pointer] = struct{}{}
			position = pointer
			continue
		case 0x00:
		case 0x40, 0x80:
			return "", 0, errors.New("unsupported label type")
		}
		position++
		if length == 0 {
			if next < 0 {
				next = position
			}
			if len(labels) == 0 {
				return ".", next, nil
			}
			return strings.Join(labels, ".") + ".", next, nil
		}
		if length > 63 || position+length > len(message) {
			return "", 0, errors.New("label is invalid or truncated")
		}
		expandedLength += length + 1
		if expandedLength > 255 {
			return "", 0, errors.New("expanded name exceeds 255 bytes")
		}
		labels = append(labels, string(message[position:position+length]))
		position += length
	}
}
