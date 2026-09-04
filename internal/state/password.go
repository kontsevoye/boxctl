package state

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
)

var ErrUnsupportedPasswordRecord = errors.New("state: unsupported password record")

type PasswordFormat string

const (
	PasswordHex       PasswordFormat = "pbkdf2-sha256-hex"
	PasswordBase64URL PasswordFormat = "pbkdf2-sha256-base64url"
)

// PasswordRecord carries parsed KDF inputs. Verification deliberately belongs
// to the authentication layer; Raw is retained for byte-for-byte persistence.
type PasswordRecord struct {
	Raw        []byte
	Format     PasswordFormat
	Algorithm  string
	Iterations int
	Salt       []byte
	Hash       []byte
}

func ParsePasswordRecord(data []byte) (PasswordRecord, error) {
	raw := append([]byte(nil), data...)
	text := string(bytes.TrimSpace(data))
	parts := strings.Split(text, "$")
	if len(parts) != 4 {
		return PasswordRecord{Raw: raw}, ErrUnsupportedPasswordRecord
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 1 || iterations > 10_000_000 {
		return PasswordRecord{Raw: raw}, fmt.Errorf("state: invalid PBKDF2 iterations")
	}
	record := PasswordRecord{Raw: raw, Algorithm: "sha256", Iterations: iterations}
	switch parts[0] {
	case "pbkdf2":
		if len(parts[1]) != 6 || len(parts[2]) != 32 || len(parts[3]) != 64 {
			return PasswordRecord{Raw: raw}, ErrUnsupportedPasswordRecord
		}
		record.Format = PasswordHex
		record.Salt, err = hex.DecodeString(parts[2])
		if err == nil {
			record.Hash, err = hex.DecodeString(parts[3])
		}
	case "pbkdf2-sha256":
		record.Format = PasswordBase64URL
		record.Salt, err = base64.RawURLEncoding.DecodeString(parts[2])
		if err == nil {
			record.Hash, err = base64.RawURLEncoding.DecodeString(parts[3])
		}
	default:
		return PasswordRecord{Raw: raw}, ErrUnsupportedPasswordRecord
	}
	if err != nil || len(record.Salt) < 16 || len(record.Hash) != 32 {
		return PasswordRecord{Raw: raw}, fmt.Errorf("state: invalid PBKDF2 salt or hash encoding")
	}
	return record, nil
}

func (store Store) ReadPasswordRecord(name string) (PasswordRecord, error) {
	data, err := store.Read(name)
	if err != nil {
		return PasswordRecord{}, err
	}
	return ParsePasswordRecord(data)
}

// ReadPasswordRecordOpaque returns the exact on-disk bytes, including a final
// newline if one exists.
func (store Store) ReadPasswordRecordOpaque(name string) ([]byte, error) {
	return store.Read(name)
}

// WritePasswordRecordOpaque never normalizes or rehashes a stored record.
func (store Store) WritePasswordRecordOpaque(name string, data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return errors.New("state: empty password record")
	}
	return store.Write(name, data, fs.FileMode(0o600))
}
