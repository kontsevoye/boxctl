package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	legacyPasswordRecordPrefix    = "pbkdf2"
	base64URLPasswordRecordPrefix = "pbkdf2-sha256"
	minSigningKeyBytes            = 32
	maxPBKDF2Iterations           = 10_000_000
	maxPBKDF2OutputBytes          = 128
)

var (
	errInvalidPasswordRecord = errors.New("invalid PBKDF2 password record")
	errInvalidSession        = errors.New("invalid session")
	errExpiredSession        = errors.New("expired session")
)

// VerifyPBKDF2Record verifies the two password formats accepted by state:
// legacy hexadecimal pbkdf2 and versioned unpadded Base64URL pbkdf2-sha256.
// Malformed and unreasonably expensive records are rejected before hashing.
func VerifyPBKDF2Record(record, password string) (bool, error) {
	parts := strings.Split(record, "$")
	if len(parts) != 4 {
		return false, errInvalidPasswordRecord
	}

	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 1 || iterations > maxPBKDF2Iterations {
		return false, errInvalidPasswordRecord
	}
	var salt, want []byte
	switch parts[0] {
	case legacyPasswordRecordPrefix:
		salt, err = hex.DecodeString(parts[2])
		if err == nil {
			want, err = hex.DecodeString(parts[3])
		}
	case base64URLPasswordRecordPrefix:
		salt, err = base64.RawURLEncoding.DecodeString(parts[2])
		if err == nil {
			want, err = base64.RawURLEncoding.DecodeString(parts[3])
		}
	default:
		return false, errInvalidPasswordRecord
	}
	if err != nil || len(salt) == 0 || len(salt) > 128 {
		return false, errInvalidPasswordRecord
	}
	if err != nil || len(want) == 0 || len(want) > maxPBKDF2OutputBytes {
		return false, errInvalidPasswordRecord
	}

	got := pbkdf2SHA256([]byte(password), salt, iterations, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	return pbkdf2Key(password, salt, iterations, keyLen, sha256.New)
}

// pbkdf2Key implements RFC 8018 PBKDF2 without adding a module dependency.
func pbkdf2Key(password, salt []byte, iterations, keyLen int, newHash func() hash.Hash) []byte {
	prf := hmac.New(newHash, password)
	hashLen := prf.Size()
	blocks := (keyLen + hashLen - 1) / hashLen
	output := make([]byte, 0, blocks*hashLen)
	buf := make([]byte, len(salt)+4)
	copy(buf, salt)

	for block := 1; block <= blocks; block++ {
		binary.BigEndian.PutUint32(buf[len(salt):], uint32(block))
		prf.Reset()
		_, _ = prf.Write(buf)
		u := prf.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			prf.Reset()
			_, _ = prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		output = append(output, t...)
	}
	return output[:keyLen]
}

type identity struct {
	UserID      string `json:"id"`
	DisplayName string `json:"displayName,omitempty"`
}

type sessionClaims struct {
	Subject     string `json:"sub"`
	DisplayName string `json:"name,omitempty"`
	SessionID   string `json:"sid"`
	CSRF        string `json:"csrf"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
}

func (c sessionClaims) identity() identity {
	return identity{UserID: c.Subject, DisplayName: c.DisplayName}
}

type sessionManager struct {
	mu             sync.RWMutex
	store          SessionSecretStore
	secrets        SessionSecretSet
	ttl            time.Duration
	rotateInterval time.Duration
	now            func() time.Time
	random         io.Reader
}

func newSessionManager(
	ctx context.Context,
	store SessionSecretStore,
	ttl, rotateInterval time.Duration,
	now func() time.Time,
	random io.Reader,
) (*sessionManager, error) {
	if store == nil {
		return nil, errors.New("web: session secret store is required")
	}
	if now == nil {
		now = time.Now
	}
	if random == nil {
		random = rand.Reader
	}

	set, err := store.LoadSessionSecrets(ctx)
	if err != nil {
		return nil, fmt.Errorf("web: load session secrets: %w", err)
	}
	m := &sessionManager{
		store:          store,
		secrets:        cloneSecretSet(set),
		ttl:            ttl,
		rotateInterval: rotateInterval,
		now:            now,
		random:         random,
	}

	if len(m.secrets.Current.Key) == 0 {
		secret, err := m.generateSecret(m.now())
		if err != nil {
			return nil, err
		}
		m.secrets = SessionSecretSet{Current: secret}
		if err := m.store.SaveSessionSecrets(ctx, cloneSecretSet(m.secrets)); err != nil {
			return nil, fmt.Errorf("web: persist initial session secret: %w", err)
		}
	}
	if err := validateSecretSet(m.secrets); err != nil {
		return nil, err
	}
	return m, nil
}

func validateSecretSet(set SessionSecretSet) error {
	seen := make(map[string]struct{}, 1+len(set.Previous))
	all := append([]SessionSecret{set.Current}, set.Previous...)
	for _, secret := range all {
		if secret.ID == "" || len(secret.Key) < minSigningKeyBytes || secret.CreatedAt.IsZero() {
			return errors.New("web: invalid persisted session secret")
		}
		if _, exists := seen[secret.ID]; exists {
			return errors.New("web: duplicate persisted session secret id")
		}
		seen[secret.ID] = struct{}{}
	}
	return nil
}

func cloneSecretSet(set SessionSecretSet) SessionSecretSet {
	clone := func(secret SessionSecret) SessionSecret {
		secret.Key = append([]byte(nil), secret.Key...)
		return secret
	}
	result := SessionSecretSet{Current: clone(set.Current)}
	result.Previous = make([]SessionSecret, len(set.Previous))
	for i := range set.Previous {
		result.Previous[i] = clone(set.Previous[i])
	}
	return result
}

func (m *sessionManager) generateSecret(createdAt time.Time) (SessionSecret, error) {
	idBytes := make([]byte, 9)
	key := make([]byte, minSigningKeyBytes)
	if _, err := io.ReadFull(m.random, idBytes); err != nil {
		return SessionSecret{}, fmt.Errorf("web: generate session secret id: %w", err)
	}
	if _, err := io.ReadFull(m.random, key); err != nil {
		return SessionSecret{}, fmt.Errorf("web: generate session signing key: %w", err)
	}
	return SessionSecret{
		ID:        base64.RawURLEncoding.EncodeToString(idBytes),
		Key:       key,
		CreatedAt: createdAt.UTC(),
	}, nil
}

func (m *sessionManager) rotateIfDue(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now().UTC()
	if m.rotateInterval <= 0 || now.Before(m.secrets.Current.CreatedAt.Add(m.rotateInterval)) {
		return nil
	}
	next, err := m.generateSecret(now)
	if err != nil {
		return err
	}
	former := m.secrets.Current
	former.RetireAt = now.Add(m.ttl)
	candidate := SessionSecretSet{Current: next, Previous: []SessionSecret{former}}
	for _, previous := range m.secrets.Previous {
		if previous.RetireAt.IsZero() || previous.RetireAt.After(now) {
			candidate.Previous = append(candidate.Previous, previous)
		}
	}
	if err := m.store.SaveSessionSecrets(ctx, cloneSecretSet(candidate)); err != nil {
		return fmt.Errorf("web: persist rotated session secret: %w", err)
	}
	m.secrets = candidate
	return nil
}

// revokeAll replaces the complete signing-key set without retaining previous
// keys. Verification takes the same lock, so no request can validate an old
// cookie after the new key has been durably persisted and published.
func (m *sessionManager) revokeAll(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	next, err := m.generateSecret(m.now().UTC())
	if err != nil {
		return err
	}
	candidate := SessionSecretSet{Current: next}
	if err := m.store.SaveSessionSecrets(ctx, cloneSecretSet(candidate)); err != nil {
		return fmt.Errorf("web: persist revoked session state: %w", err)
	}
	m.secrets = candidate
	return nil
}

func (m *sessionManager) issue(ctx context.Context, user Credential) (string, sessionClaims, error) {
	if err := m.rotateIfDue(ctx); err != nil {
		return "", sessionClaims{}, err
	}
	sessionID, err := randomToken(m.random, 18)
	if err != nil {
		return "", sessionClaims{}, err
	}
	csrf, err := randomToken(m.random, 24)
	if err != nil {
		return "", sessionClaims{}, err
	}
	now := m.now().UTC()
	claims := sessionClaims{
		Subject:     user.UserID,
		DisplayName: user.DisplayName,
		SessionID:   sessionID,
		CSRF:        csrf,
		IssuedAt:    now.Unix(),
		ExpiresAt:   now.Add(m.ttl).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", sessionClaims{}, fmt.Errorf("web: encode session: %w", err)
	}

	m.mu.RLock()
	secret := m.secrets.Current
	m.mu.RUnlock()
	prefix := "v1." + secret.ID + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature := signSession(secret.Key, prefix)
	return prefix + "." + signature, claims, nil
}

func (m *sessionManager) verify(token string) (sessionClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "v1" {
		return sessionClaims{}, errInvalidSession
	}
	m.mu.RLock()
	secret, ok := findSecret(m.secrets, parts[1], m.now())
	m.mu.RUnlock()
	if !ok {
		return sessionClaims{}, errInvalidSession
	}
	prefix := strings.Join(parts[:3], ".")
	want, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || base64.RawURLEncoding.EncodeToString(want) != parts[3] {
		return sessionClaims{}, errInvalidSession
	}
	mac := hmac.New(sha256.New, secret.Key)
	_, _ = mac.Write([]byte(prefix))
	if !hmac.Equal(mac.Sum(nil), want) {
		return sessionClaims{}, errInvalidSession
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != parts[2] {
		return sessionClaims{}, errInvalidSession
	}
	var claims sessionClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return sessionClaims{}, errInvalidSession
	}
	now := m.now().Unix()
	if claims.Subject == "" || claims.SessionID == "" || claims.CSRF == "" || claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt {
		return sessionClaims{}, errInvalidSession
	}
	if claims.IssuedAt > now+300 {
		return sessionClaims{}, errInvalidSession
	}
	if now >= claims.ExpiresAt {
		return sessionClaims{}, errExpiredSession
	}
	return claims, nil
}

func findSecret(set SessionSecretSet, id string, now time.Time) (SessionSecret, bool) {
	if set.Current.ID == id {
		return set.Current, true
	}
	for _, secret := range set.Previous {
		if secret.ID == id && (secret.RetireAt.IsZero() || now.Before(secret.RetireAt)) {
			return secret, true
		}
	}
	return SessionSecret{}, false
}

func signSession(key []byte, value string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func randomToken(source io.Reader, length int) (string, error) {
	b := make([]byte, length)
	if _, err := io.ReadFull(source, b); err != nil {
		return "", fmt.Errorf("web: generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type loginAttempt struct {
	failures int
	resetAt  time.Time
}

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]loginAttempt
	limit    int
	window   time.Duration
	now      func() time.Time
	checks   uint64
}

func newLoginLimiter(limit int, window time.Duration, now func() time.Time) *loginLimiter {
	return &loginLimiter{attempts: make(map[string]loginAttempt), limit: limit, window: window, now: now}
}

// reserve atomically consumes one attempt before the caller starts PBKDF2.
// Failed credentials keep the reservation until the window resets; callers
// release it only for infrastructure errors and remove it after success.
func (l *loginLimiter) reserve(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.checks++
	if l.checks%128 == 0 {
		for candidate, attempt := range l.attempts {
			if !attempt.resetAt.After(now) {
				delete(l.attempts, candidate)
			}
		}
	}
	attempt, ok := l.attempts[key]
	if !ok || !attempt.resetAt.After(now) {
		attempt = loginAttempt{resetAt: now.Add(l.window)}
	}
	if attempt.failures >= l.limit {
		return false, attempt.resetAt.Sub(now)
	}
	attempt.failures++
	l.attempts[key] = attempt
	return true, 0
}

func (l *loginLimiter) cancel(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	attempt, ok := l.attempts[key]
	if !ok {
		return
	}
	attempt.failures--
	if attempt.failures <= 0 {
		delete(l.attempts, key)
	} else {
		l.attempts[key] = attempt
	}
}

func (l *loginLimiter) success(key string) {
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}
