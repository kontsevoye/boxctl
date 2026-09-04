package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVerifyPBKDF2Record(t *testing.T) {
	t.Parallel()
	record := "pbkdf2$1$" + hex.EncodeToString([]byte("salt")) + "$120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"

	valid, err := VerifyPBKDF2Record(record, "password")
	if err != nil {
		t.Fatalf("VerifyPBKDF2Record: %v", err)
	}
	if !valid {
		t.Fatal("correct password was rejected")
	}
	valid, err = VerifyPBKDF2Record(record, "not-password")
	if err != nil {
		t.Fatalf("VerifyPBKDF2Record wrong password: %v", err)
	}
	if valid {
		t.Fatal("wrong password was accepted")
	}
}

func TestVerifyPBKDF2Base64URLRecord(t *testing.T) {
	t.Parallel()
	salt := []byte("0123456789abcdef")
	hash := pbkdf2SHA256([]byte("correct horse"), salt, 2, 32)
	record := "pbkdf2-sha256$2$" + base64.RawURLEncoding.EncodeToString(salt) + "$" + base64.RawURLEncoding.EncodeToString(hash)
	valid, err := VerifyPBKDF2Record(record, "correct horse")
	if err != nil || !valid {
		t.Fatalf("VerifyPBKDF2Record(base64url) = %v, %v", valid, err)
	}
	valid, err = VerifyPBKDF2Record(record, "wrong")
	if err != nil || valid {
		t.Fatalf("VerifyPBKDF2Record(base64url wrong) = %v, %v", valid, err)
	}
}

func TestVerifyPBKDF2RecordRejectsMalformedAndExpensiveRecords(t *testing.T) {
	t.Parallel()
	for _, record := range []string{
		"",
		"sha256$1$00$00",
		"pbkdf2$0$00$00",
		"pbkdf2$10000001$00$00",
		"pbkdf2$1$not-hex$00",
		"pbkdf2$1$00$not-hex",
		"pbkdf2$1$$00",
	} {
		t.Run(record, func(t *testing.T) {
			if _, err := VerifyPBKDF2Record(record, "password"); !errors.Is(err, errInvalidPasswordRecord) {
				t.Fatalf("got %v, want malformed record error", err)
			}
		})
	}
}

func TestSessionSecretRotationPersistsAndKeepsOldSession(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	clock := now
	store := &memorySecretStore{set: SessionSecretSet{Current: SessionSecret{
		ID:        "initial",
		Key:       bytes.Repeat([]byte{1}, 32),
		CreatedAt: now,
	}}}
	manager, err := newSessionManager(context.Background(), store, 4*time.Hour, time.Hour, func() time.Time { return clock }, nil)
	if err != nil {
		t.Fatalf("newSessionManager: %v", err)
	}

	oldToken, _, err := manager.issue(context.Background(), Credential{UserID: "1"})
	if err != nil {
		t.Fatalf("issue old session: %v", err)
	}
	clock = now.Add(2 * time.Hour)
	newToken, _, err := manager.issue(context.Background(), Credential{UserID: "1"})
	if err != nil {
		t.Fatalf("issue new session: %v", err)
	}
	if oldToken == newToken {
		t.Fatal("rotation did not change the signed token")
	}
	if store.saves != 1 {
		t.Fatalf("rotation saves = %d, want 1", store.saves)
	}
	if store.set.Current.ID == "initial" || len(store.set.Previous) != 1 || store.set.Previous[0].ID != "initial" {
		t.Fatalf("unexpected persisted rotation set: %+v", store.set)
	}
	if _, err := manager.verify(oldToken); err != nil {
		t.Fatalf("old unexpired session rejected after rotation: %v", err)
	}
	if _, err := manager.verify(newToken); err != nil {
		t.Fatalf("new session rejected: %v", err)
	}
}

func TestSessionRejectsTamperingAndExpiry(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	clock := now
	store := &memorySecretStore{set: SessionSecretSet{Current: SessionSecret{
		ID:        "initial",
		Key:       bytes.Repeat([]byte{2}, 32),
		CreatedAt: now,
	}}}
	manager, err := newSessionManager(context.Background(), store, time.Hour, 24*time.Hour, func() time.Time { return clock }, nil)
	if err != nil {
		t.Fatalf("newSessionManager: %v", err)
	}
	token, _, err := manager.issue(context.Background(), Credential{UserID: "1"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	tampered := token[:len(token)-1] + differentLastByte(token[len(token)-1])
	if _, err := manager.verify(tampered); !errors.Is(err, errInvalidSession) {
		t.Fatalf("tampered token error = %v", err)
	}
	clock = now.Add(time.Hour)
	if _, err := manager.verify(token); !errors.Is(err, errExpiredSession) {
		t.Fatalf("expired token error = %v", err)
	}
}

func TestRevokeAllSessionsDropsEveryPreviousSigningKey(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	store := &memorySecretStore{set: SessionSecretSet{Current: SessionSecret{
		ID: "initial", Key: bytes.Repeat([]byte{3}, 32), CreatedAt: now,
	}}}
	manager, err := newSessionManager(context.Background(), store, time.Hour, 24*time.Hour, func() time.Time { return now }, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := manager.issue(context.Background(), Credential{UserID: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.revokeAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.verify(token); !errors.Is(err, errInvalidSession) {
		t.Fatalf("revoked token error = %v", err)
	}
	if store.set.Current.ID == "initial" || len(store.set.Previous) != 0 {
		t.Fatalf("persisted revocation set = %+v", store.set)
	}
}

func TestInitialSessionSecretIsGeneratedAndPersisted(t *testing.T) {
	store := &memorySecretStore{}
	_, err := newSessionManager(context.Background(), store, time.Hour, 24*time.Hour, time.Now, nil)
	if err != nil {
		t.Fatalf("newSessionManager: %v", err)
	}
	if store.saves != 1 || len(store.set.Current.Key) < 32 || store.set.Current.ID == "" {
		t.Fatalf("initial secret was not persisted: %+v", store.set.Current)
	}
}

func TestLoginLimiterUsesInjectedClock(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	limiter := newLoginLimiter(1, time.Minute, func() time.Time { return now })
	allowed, _ := limiter.reserve("client")
	if !allowed {
		t.Fatal("first reservation was rejected")
	}
	allowed, retry := limiter.reserve("client")
	if allowed || retry != time.Minute {
		t.Fatalf("blocked attempt = (%v, %v), want (false, 1m)", allowed, retry)
	}
	now = now.Add(time.Minute)
	allowed, _ = limiter.reserve("client")
	if !allowed {
		t.Fatal("attempt remained blocked after window")
	}
}

func TestLoginLimiterAtomicallyBoundsParallelReservations(t *testing.T) {
	t.Parallel()
	const limit = 4
	limiter := newLoginLimiter(limit, time.Minute, time.Now)
	results := make(chan bool, 64)
	var wait sync.WaitGroup
	for range cap(results) {
		wait.Add(1)
		go func() {
			defer wait.Done()
			allowed, _ := limiter.reserve("one-client")
			results <- allowed
		}()
	}
	wait.Wait()
	close(results)
	allowed := 0
	for result := range results {
		if result {
			allowed++
		}
	}
	if allowed != limit {
		t.Fatalf("parallel reservations allowed = %d, want %d", allowed, limit)
	}
}

func differentLastByte(b byte) string {
	if b == 'A' {
		return "B"
	}
	return "A"
}

type memorySecretStore struct {
	mu      sync.Mutex
	set     SessionSecretSet
	saves   int
	saveErr error
}

func (s *memorySecretStore) LoadSessionSecrets(context.Context) (SessionSecretSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneSecretSet(s.set), nil
}

func (s *memorySecretStore) SaveSessionSecrets(_ context.Context, set SessionSecretSet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveErr != nil {
		return s.saveErr
	}
	s.set = cloneSecretSet(set)
	s.saves++
	return nil
}

func passwordRecord(password string) string {
	salt := []byte("0123456789abcdef")
	hash := pbkdf2SHA256([]byte(password), salt, 2, 32)
	return "pbkdf2$2$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(hash)
}

func containsSecret(value string) bool {
	for _, secret := range []string{"topsecret", "very-secret", "user:pass", "path-secret", "query-secret", "mihomo-private.yaml"} {
		if strings.Contains(value, secret) {
			return true
		}
	}
	return false
}
