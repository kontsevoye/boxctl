package state

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestParseHexPasswordRecord(t *testing.T) {
	t.Parallel()
	raw := []byte("pbkdf2$123456$00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n")
	record, err := ParsePasswordRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	if record.Format != PasswordHex || record.Iterations != 123456 || len(record.Salt) != 16 || len(record.Hash) != 32 || !bytes.Equal(record.Raw, raw) {
		t.Fatalf("record = %+v", record)
	}
}

func TestParseVersionedBase64PasswordRecord(t *testing.T) {
	t.Parallel()
	salt := bytes.Repeat([]byte{0x55}, 16)
	hash := bytes.Repeat([]byte{0xaa}, 32)
	text := "pbkdf2-sha256$600000$" + base64.RawURLEncoding.EncodeToString(salt) + "$" + base64.RawURLEncoding.EncodeToString(hash)
	record, err := ParsePasswordRecord([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if record.Format != PasswordBase64URL || record.Iterations != 600000 || !bytes.Equal(record.Salt, salt) || !bytes.Equal(record.Hash, hash) {
		t.Fatalf("record = %+v", record)
	}
}

func TestOpaquePasswordPersistenceNeverNormalizes(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	raw := []byte("future-format$opaque\n")
	if err := store.WritePasswordRecordOpaque(".boxctl/password", raw); err != nil {
		t.Fatal(err)
	}
	got, err := store.ReadPasswordRecordOpaque(".boxctl/password")
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("opaque record = %q, %v", got, err)
	}
	if _, err := store.ReadPasswordRecord(".boxctl/password"); !errors.Is(err, ErrUnsupportedPasswordRecord) {
		t.Fatalf("parse error = %v", err)
	}
	info, err := os.Stat(filepath.Join(store.Root, ".boxctl/password"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("password permissions = %v, %v", info, err)
	}
}
