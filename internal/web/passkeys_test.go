package web

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type memoryPasskeys struct {
	mu         sync.Mutex
	state      PasskeyState
	credential Credential
	failSave   bool
}

func (m *memoryPasskeys) LoadPasskeys(context.Context) (PasskeyState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return clonePasskeys(m.state), nil
}
func (m *memoryPasskeys) UpdatePasskeys(_ context.Context, update func(*PasskeyState, Credential) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	copy := clonePasskeys(m.state)
	if err := update(&copy, m.credential); err != nil {
		return err
	}
	if m.failSave {
		return errors.New("storage failed")
	}
	m.state = copy
	return nil
}
func clonePasskeys(state PasskeyState) PasskeyState {
	data, _ := json.Marshal(state)
	var result PasskeyState
	_ = json.Unmarshal(data, &result)
	return result
}

type virtualPasskey struct {
	key    *ecdsa.PrivateKey
	id     []byte
	handle []byte
}
type testCeremony struct {
	CeremonyID string `json:"ceremonyId"`
	Options    struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	} `json:"options"`
}

func decodeCeremony(t *testing.T, response *httptest.ResponseRecorder) testCeremony {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("begin = %d %s", response.Code, response.Body.String())
	}
	var body struct {
		Data testCeremony `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Data
}
func passkeyTestServer(t *testing.T) (*Server, *memoryPasskeys, *http.Cookie, string) {
	t.Helper()
	credential, _ := (fakeCredentials{}).Credential(context.Background())
	store := &memoryPasskeys{credential: credential}
	handler, err := NewHandler(Config{PublicOrigin: "https://example.com", AllowedHosts: []string{"example.com"}}, Services{Credentials: fakeCredentials{}, SessionSecrets: &memorySecretStore{}, Passkeys: store})
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := login(t, handler)
	return handler.(*Server), store, cookie, csrf
}
func passkeyPOST(s http.Handler, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	return performWithHeaders(s, http.MethodPost, path, "application/json", []byte(body), cookie, csrf, map[string]string{"Origin": "https://example.com"})
}
func registrationBegin(t *testing.T, s http.Handler, cookie *http.Cookie, csrf string) testCeremony {
	t.Helper()
	response := passkeyPOST(s, "/api/v1/settings/passkeys/register/begin", `{"name":"MacBook", "password":"correct horse"}`, cookie, csrf)
	for _, option := range []string{`"residentKey":"required"`, `"requireResidentKey":true`, `"userVerification":"required"`} {
		if !strings.Contains(response.Body.String(), option) {
			t.Fatalf("registration options omitted %s: %s", option, response.Body.String())
		}
	}
	return decodeCeremony(t, response)
}
func jsonText(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }
func authData(rp string, flags byte, count uint32) []byte {
	hash := sha256.Sum256([]byte(rp))
	result := append([]byte(nil), hash[:]...)
	result = append(result, flags)
	return binary.BigEndian.AppendUint32(result, count)
}
func newVirtualPasskey(t *testing.T, begin testCeremony) virtualPasskey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := base64.RawURLEncoding.DecodeString(begin.Options.PublicKey.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return virtualPasskey{key, id, handle}
}
func (v virtualPasskey) registration(t *testing.T, begin testCeremony, origin string, flags byte) string {
	t.Helper()
	pub, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: v.key.X.FillBytes(make([]byte, 32)), -3: v.key.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	data := append(authData("example.com", flags, 0), make([]byte, 16)...)
	data = binary.BigEndian.AppendUint16(data, uint16(len(v.id)))
	data = append(append(data, v.id...), pub...)
	attestation, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": data})
	if err != nil {
		t.Fatal(err)
	}
	client := jsonText(t, map[string]any{"type": "webauthn.create", "challenge": begin.Options.PublicKey.Challenge, "origin": origin})
	return jsonText(t, map[string]any{"ceremonyId": begin.CeremonyID, "credential": map[string]any{"id": b64(v.id), "rawId": b64(v.id), "type": "public-key", "clientExtensionResults": map[string]any{"credProps": map[string]bool{"rk": true}}, "response": map[string]any{"clientDataJSON": b64([]byte(client)), "attestationObject": b64(attestation), "transports": []string{"internal"}}}})
}
func (v virtualPasskey) assertion(t *testing.T, begin testCeremony, origin string, flags byte, count uint32) string {
	t.Helper()
	client := jsonText(t, map[string]any{"type": "webauthn.get", "challenge": begin.Options.PublicKey.Challenge, "origin": origin})
	data := authData("example.com", flags, count)
	hash := sha256.Sum256([]byte(client))
	signed := sha256.Sum256(append(append([]byte(nil), data...), hash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, v.key, signed[:])
	if err != nil {
		t.Fatal(err)
	}
	return jsonText(t, map[string]any{"ceremonyId": begin.CeremonyID, "credential": map[string]any{"id": b64(v.id), "rawId": b64(v.id), "type": "public-key", "clientExtensionResults": map[string]any{}, "response": map[string]any{"clientDataJSON": b64([]byte(client)), "authenticatorData": b64(data), "signature": b64(signature), "userHandle": b64(v.handle)}}})
}
func registerVirtualPasskey(t *testing.T, s *Server, cookie *http.Cookie, csrf string) virtualPasskey {
	t.Helper()
	begin := registrationBegin(t, s, cookie, csrf)
	v := newVirtualPasskey(t, begin)
	response := passkeyPOST(s, "/api/v1/settings/passkeys/register/finish", v.registration(t, begin, "https://example.com", 0x45), cookie, csrf)
	if response.Code != http.StatusCreated {
		t.Fatalf("register = %d %s", response.Code, response.Body.String())
	}
	return v
}
func beginPasskeyLogin(t *testing.T, s http.Handler) testCeremony {
	t.Helper()
	return decodeCeremony(t, passkeyPOST(s, "/api/v1/auth/passkeys/begin", "{}", nil, ""))
}

func TestPasskeyPasswordlessLoginAndPasswordProtectedDeletion(t *testing.T) {
	s, store, cookie, csrf := passkeyTestServer(t)
	v := registerVirtualPasskey(t, s, cookie, csrf)
	list := perform(s, http.MethodGet, "/api/v1/settings/passkeys", "", cookie, csrf)
	if list.Code != 200 || !strings.Contains(list.Body.String(), `"name":"MacBook"`) || strings.Contains(list.Body.String(), "publicKey") || strings.Contains(list.Body.String(), "userHandle") {
		t.Fatalf("list = %d %s", list.Code, list.Body.String())
	}
	begin := beginPasskeyLogin(t, s)
	payload := v.assertion(t, begin, "https://example.com", 5, 1)
	result := passkeyPOST(s, "/api/v1/auth/passkeys/finish", payload, nil, "")
	if result.Code != 200 || !strings.Contains(result.Body.String(), `"authenticated":true`) {
		t.Fatalf("login = %d %s", result.Code, result.Body.String())
	}
	if len(result.Result().Cookies()) != 1 || !result.Result().Cookies()[0].Secure || !result.Result().Cookies()[0].HttpOnly {
		t.Fatal("missing secure session cookie")
	}
	if store.state.Passkeys[0].LastUsedAt == nil || store.state.Passkeys[0].Credential.Authenticator.SignCount != 1 {
		t.Fatal("login did not persist credential counters")
	}
	if replay := passkeyPOST(s, "/api/v1/auth/passkeys/finish", payload, nil, ""); replay.Code != 400 {
		t.Fatalf("replayed login = %d", replay.Code)
	}
	for _, password := range []string{"", "wrong"} {
		result = perform(s, http.MethodDelete, "/api/v1/settings/passkeys", jsonText(t, map[string]string{"id": b64(v.id), "password": password}), cookie, csrf)
		if result.Code != 403 || len(store.state.Passkeys) != 1 {
			t.Fatalf("deletion without password = %d", result.Code)
		}
	}
	// A challenge issued before deletion must also fail after deletion.
	begin = beginPasskeyLogin(t, s)
	result = perform(s, http.MethodDelete, "/api/v1/settings/passkeys", jsonText(t, map[string]string{"id": b64(v.id), "password": "correct horse"}), cookie, csrf)
	if result.Code != 204 || len(store.state.Passkeys) != 0 {
		t.Fatalf("delete = %d %s", result.Code, result.Body.String())
	}
	result = passkeyPOST(s, "/api/v1/auth/passkeys/finish", v.assertion(t, begin, "https://example.com", 5, 2), nil, "")
	if result.Code != 400 || len(result.Result().Cookies()) != 0 {
		t.Fatalf("deleted passkey login = %d", result.Code)
	}
}

func TestPasskeyRegistrationRejectsInvalidProofs(t *testing.T) {
	for _, scenario := range []string{"password", "csrf", "unauthenticated", "name", "wrong_origin", "no_verification", "wrong_session", "expired", "password_changed", "state_replaced", "failed_save", "duplicate", "replay"} {
		t.Run(scenario, func(t *testing.T) {
			s, store, cookie, csrf := passkeyTestServer(t)
			if scenario == "password" || scenario == "csrf" || scenario == "unauthenticated" || scenario == "name" {
				body := `{"name":"MacBook","password":"correct horse"}`
				expected := 403
				switch scenario {
				case "password":
					body = `{"name":"MacBook","password":"wrong"}`
				case "csrf":
					csrf = ""
				case "unauthenticated":
					cookie = nil
					expected = 401
				case "name":
					body = `{"name":"  ","password":"correct horse"}`
					expected = 400
				}
				r := passkeyPOST(s, "/api/v1/settings/passkeys/register/begin", body, cookie, csrf)
				if r.Code != expected || len(store.state.UserHandle) != 0 {
					t.Fatalf("begin = %d %s", r.Code, r.Body.String())
				}
				return
			}
			begin := registrationBegin(t, s, cookie, csrf)
			v := newVirtualPasskey(t, begin)
			origin := "https://example.com"
			flags := byte(0x45)
			expected := 400
			switch scenario {
			case "wrong_origin":
				origin = "https://attacker.example"
			case "no_verification":
				flags = 0x41
			case "wrong_session":
				cookie, csrf = login(t, s)
			case "expired":
				s.config.now = func() time.Time { return time.Now().Add(6 * time.Minute) }
			case "password_changed":
				store.credential.PasswordRecord = passwordRecord("replacement password")
			case "state_replaced":
				store.state.UserHandle = bytes.Repeat([]byte{9}, 32)
			case "failed_save":
				store.failSave = true
				expected = 500
			case "duplicate", "replay":
				r := passkeyPOST(s, "/api/v1/settings/passkeys/register/finish", v.registration(t, begin, origin, flags), cookie, csrf)
				if r.Code != 201 {
					t.Fatalf("first register = %d %s", r.Code, r.Body.String())
				}
				if scenario == "duplicate" {
					begin = registrationBegin(t, s, cookie, csrf)
					expected = 409
				}
			}
			r := passkeyPOST(s, "/api/v1/settings/passkeys/register/finish", v.registration(t, begin, origin, flags), cookie, csrf)
			if r.Code != expected {
				t.Fatalf("finish = %d %s", r.Code, r.Body.String())
			}
			want := 0
			if scenario == "duplicate" || scenario == "replay" {
				want = 1
			}
			if len(store.state.Passkeys) != want {
				t.Fatalf("saved %d passkeys", len(store.state.Passkeys))
			}
		})
	}
}

func TestPasskeyLoginRejectsInvalidAssertions(t *testing.T) {
	for _, scenario := range []string{"wrong_origin", "no_verification", "wrong_handle", "bad_signature", "counter_rollback", "failed_save"} {
		t.Run(scenario, func(t *testing.T) {
			s, store, cookie, csrf := passkeyTestServer(t)
			v := registerVirtualPasskey(t, s, cookie, csrf)
			begin := beginPasskeyLogin(t, s)
			origin := "https://example.com"
			flags := byte(5)
			expected := 400
			switch scenario {
			case "wrong_origin":
				origin = "https://evil.example"
			case "no_verification":
				flags = 1
			case "wrong_handle":
				v.handle = []byte("wrong")
			case "bad_signature":
				v.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			case "counter_rollback":
				store.state.Passkeys[0].Credential.Authenticator.SignCount = 2
			case "failed_save":
				store.failSave = true
				expected = 500
			}
			r := passkeyPOST(s, "/api/v1/auth/passkeys/finish", v.assertion(t, begin, origin, flags, 1), nil, "")
			if r.Code != expected || len(r.Result().Cookies()) != 0 || store.state.Passkeys[0].LastUsedAt != nil {
				t.Fatalf("login = %d %s", r.Code, r.Body.String())
			}
		})
	}
}

func TestPasskeyOriginRateLimitsAndFailedDelete(t *testing.T) {
	s, store, cookie, csrf := passkeyTestServer(t)
	v := registerVirtualPasskey(t, s, cookie, csrf)
	for _, headers := range []map[string]string{{"Origin": "https://attacker.example"}, {"Origin": "https://example.com", "Host": "other.example"}} {
		r := performWithHeaders(s, http.MethodPost, "/api/v1/auth/passkeys/begin", "application/json", []byte(`{}`), nil, "", headers)
		if r.Code != 403 {
			t.Fatalf("cross-origin begin = %d", r.Code)
		}
	}
	for i := 0; i < 5; i++ {
		beginPasskeyLogin(t, s)
	}
	if r := passkeyPOST(s, "/api/v1/auth/passkeys/begin", "{}", nil, ""); r.Code != 429 || r.Header().Get("Retry-After") == "" {
		t.Fatalf("unlimited begin = %d", r.Code)
	}
	store.failSave = true
	r := perform(s, http.MethodDelete, "/api/v1/settings/passkeys", jsonText(t, map[string]string{"id": b64(v.id), "password": "correct horse"}), cookie, csrf)
	if r.Code != 500 || len(store.state.Passkeys) != 1 {
		t.Fatalf("failed delete = %d", r.Code)
	}
}

func TestPasskeyRPUsesEffectiveOrigin(t *testing.T) {
	for _, test := range []struct {
		url, public string
		want        bool
		rp          string
	}{
		{"http://192.168.1.1", "", false, ""}, {"https://192.168.1.1", "", false, ""}, {"http://router.lan", "", false, ""},
		{"http://localhost:9091", "", true, "localhost"}, {"https://router.lan:9091", "", true, "router.lan"},
		{"http://router.example:9443", "https://router.example:9443", true, "router.example"}, {"http://evil.example", "https://router.example", false, ""},
	} {
		t.Run(test.url+test.public, func(t *testing.T) {
			s := &Server{}
			s.publicOrigin, _ = parseConfiguredPublicOrigin(test.public)
			rp, _, err := s.passkeyRP(httptest.NewRequest(http.MethodPost, test.url, nil))
			if (err == nil) != test.want || (err == nil && rp.Config.RPID != test.rp) {
				t.Fatalf("RP = %+v %v", rp, err)
			}
		})
	}
}

func TestPasskeyManagementRoutesRequireSessionAndCSRF(t *testing.T) {
	s, _, cookie, _ := passkeyTestServer(t)
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/settings/passkeys"},
		{http.MethodDelete, "/api/v1/settings/passkeys"},
		{http.MethodPost, "/api/v1/settings/passkeys/register/begin"},
		{http.MethodPost, "/api/v1/settings/passkeys/register/finish"},
	} {
		if r := perform(s, route.method, route.path, "{}", nil, ""); r.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s: %d", route.path, r.Code)
		}
		if route.method != http.MethodGet {
			if r := perform(s, route.method, route.path, "{}", cookie, ""); r.Code != http.StatusForbidden {
				t.Fatalf("missing CSRF %s: %d", route.path, r.Code)
			}
		}
	}
}

func TestPasskeyCeremoniesAreBoundedAndExpire(t *testing.T) {
	now := time.Now()
	s := &Server{config: Config{now: func() time.Time { return now }}}
	var first string
	for i := 0; i < maxPasskeyCeremonies; i++ {
		id, err := s.rememberPasskey(passkeyCeremony{Origin: "https://example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = id
		}
	}
	if _, err := s.rememberPasskey(passkeyCeremony{}); err == nil {
		t.Fatal("unbounded pending ceremonies")
	}
	now = now.Add(passkeyLifetime)
	if _, ok := s.consumePasskey(first, "https://example.com", ""); ok {
		t.Fatal("accepted expired login")
	}
	if _, err := s.rememberPasskey(passkeyCeremony{}); err != nil || len(s.passkeyCeremonies.pending) != 1 {
		t.Fatalf("expired ceremonies were not cleaned: %v", err)
	}
}

func TestPasskeyRegistrationLimitAndNameValidation(t *testing.T) {
	s, store, cookie, csrf := passkeyTestServer(t)
	for _, name := range []string{"", " \t ", "line\nbreak", strings.Repeat("я", 65)} {
		r := passkeyPOST(s, "/api/v1/settings/passkeys/register/begin", jsonText(t, map[string]string{"name": name, "password": "correct horse"}), cookie, csrf)
		if r.Code != 400 {
			t.Fatalf("accepted invalid name %q: %d", name, r.Code)
		}
	}
	store.state.Passkeys = make([]StoredPasskey, maxPasskeys)
	r := passkeyPOST(s, "/api/v1/settings/passkeys/register/begin", `{"name":"one too many","password":"correct horse"}`, cookie, csrf)
	if r.Code != 409 || !strings.Contains(r.Body.String(), "passkey_limit") {
		t.Fatalf("limit = %d %s", r.Code, r.Body.String())
	}
}
