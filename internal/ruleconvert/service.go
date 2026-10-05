package ruleconvert

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kontsevoye/boxctl/internal/state"
)

const endpointPrefix = "/internal/rules/"

type Source struct {
	BinaryIdentity string      `json:"binaryIdentity"`
	HTTPVersion    string      `json:"httpVersion,omitempty"`
	LoopMark       uint32      `json:"loopMark,omitempty"`
	URL            string      `json:"url"`
	Target         string      `json:"target"`
	Hint           string      `json:"hint,omitempty"`
	Headers        http.Header `json:"headers,omitempty"`
	ProxyURL       string      `json:"proxyURL,omitempty"`
	Binaries       Binaries    `json:"binaries"`
	// CodecRevision prevents older results from bypassing new validation rules.
	CodecRevision int    `json:"codecRevision"`
	Contract      string `json:"contract,omitempty"`
}
type Record struct {
	SourceDigest   string    `json:"sourceDigest,omitempty"`
	Source         Source    `json:"source"`
	ID             string    `json:"id"`
	Format         string    `json:"format"`
	Behavior       string    `json:"behavior,omitempty"`
	Count          int       `json:"count"`
	Digest         string    `json:"digest"`
	SourceETag     string    `json:"sourceETag,omitempty"`
	SourceModified string    `json:"sourceModified,omitempty"`
	CheckedAt      time.Time `json:"checkedAt"`
	ConvertedAt    time.Time `json:"convertedAt"`
	LastError      string    `json:"lastError,omitempty"`
}
type Status struct {
	Name        string    `json:"name"`
	ID          string    `json:"id"`
	Target      string    `json:"target"`
	Format      string    `json:"format"`
	Behavior    string    `json:"behavior,omitempty"`
	Count       int       `json:"count"`
	CheckedAt   time.Time `json:"checkedAt"`
	ConvertedAt time.Time `json:"convertedAt"`
	LastError   string    `json:"lastError,omitempty"`
}
type listenerState struct {
	MihomoBridges map[string]string `json:"mihomoBridges,omitempty"`
	Address       string            `json:"address"`
	BridgeAddress string            `json:"bridgeAddress"`
	Secret        string            `json:"secret"`
}
type Service struct {
	root     string
	mu       sync.Mutex
	locks    map[string]*sync.Mutex
	listener listenerState
	server   *http.Server
	Client   *http.Client
	Convert  func(context.Context, []byte, Source) (Artifact, error)
}

func New(root string) *Service {
	return &Service{root: filepath.Join(root, ".boxctl", "rule-converter"), locks: map[string]*sync.Mutex{}}
}
func (s *Service) initialize() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener.Address != "" {
		return nil
	}
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return err
	}
	data, err := readRegular(filepath.Join(s.root, "listener.json"), 16384)
	if err == nil {
		if json.Unmarshal(data, &s.listener) != nil || !loopbackAddress(s.listener.Address) || !loopbackAddress(s.listener.BridgeAddress) || len(s.listener.Secret) != 64 {
			return errors.New("invalid converter listener state")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	a, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer a.Close()
	b, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer b.Close()
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return err
	}
	s.listener = listenerState{Address: a.Addr().String(), BridgeAddress: b.Addr().String(), Secret: hex.EncodeToString(secret)}
	//nolint:gosec // Persistent local capability secret, intentionally saved only to a private 0600 state file.
	data, err = json.Marshal(s.listener)
	if err != nil {
		return err
	}
	return state.WriteFileAtomic(filepath.Join(s.root, "listener.json"), data, 0o600)
}
func loopbackAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	n, e := strconv.Atoi(port)
	return err == nil && e == nil && host == "127.0.0.1" && n > 0 && n < 65536
}
func (s *Service) Start() error {
	if err := s.initialize(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.server != nil {
		return nil
	}
	listener, err := net.Listen("tcp4", s.listener.Address)
	if err != nil {
		return fmt.Errorf("listen for converted rules: %w", err)
	}
	s.server = &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	server := s.server
	go func() { _ = server.Serve(listener) }()
	return nil
}
func (s *Service) Close() error {
	s.mu.Lock()
	server := s.server
	s.server = nil
	s.mu.Unlock()
	if server != nil {
		return server.Close()
	}
	return nil
}
func (s *Service) lock(id string) func() {
	s.mu.Lock()
	m := s.locks[id]
	if m == nil {
		m = &sync.Mutex{}
		s.locks[id] = m
	}
	s.mu.Unlock()
	m.Lock()
	return m.Unlock
}
func (s *Service) id(source Source) (string, error) {
	if err := s.initialize(); err != nil {
		return "", err
	}
	data, err := json.Marshal(source)
	if err != nil {
		return "", err
	}
	h := hmac.New(sha256.New, []byte(s.listener.Secret))
	_, _ = h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (s *Service) URL(r Record) string {
	return "http://" + s.listener.Address + endpointPrefix + r.ID + "/rules." + extension(r.Format)
}
func extension(format string) string {
	switch format {
	case "binary":
		return "srs"
	case "mrs":
		return "mrs"
	default:
		return "txt"
	}
}
func (s *Service) InitialPath(r Record) string {
	return filepath.Join(s.root, r.ID, "initial."+extension(r.Format))
}
func (s *Service) Prepare(ctx context.Context, source Source, initial ...string) (Record, error) {
	source.CodecRevision = 1
	source.BinaryIdentity = binaryIdentity(source.Binaries)
	if _, err := parseURL(source.URL); err != nil {
		return Record{}, err
	}
	baseID, err := s.id(source)
	if err != nil {
		return Record{}, err
	}
	unlock := s.lock(baseID)
	defer unlock()
	record := Record{Source: source}
	pointer := filepath.Join(s.root, "sources", baseID)
	if data, readErr := readRegular(pointer, 64); readErr == nil {
		record, err = s.load(string(data))
		if err != nil {
			return Record{}, err
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return Record{}, readErr
	}
	refreshed, err := s.refresh(ctx, record)
	var changed *formatChanged
	if errors.As(err, &changed) {
		// A new endpoint preserves the output contract of the still-running core.
		refreshed, err = s.publish(Record{Source: source}, changed.Artifact, "", "")
	}
	if err != nil && record.Digest != "" {
		if _, readErr := s.artifact(record); readErr == nil {
			return record, nil
		}
	}
	if err != nil && len(initial) > 0 && initial[0] != "" {
		if seed, readErr := readRegular(initial[0], MaxBytes); readErr == nil {
			artifact, decodeErr := s.convert(ctx, seed, source)
			if decodeErr == nil {
				refreshed, decodeErr = s.publish(Record{Source: source}, artifact, "", "")
				if decodeErr == nil {
					refreshed.LastError = err.Error()
					_ = s.save(refreshed)
					err = nil
				}
			}
		}
	}
	if err != nil {
		return refreshed, err
	}
	if err = os.MkdirAll(filepath.Dir(pointer), 0o700); err != nil {
		return Record{}, err
	}
	return refreshed, state.WriteFileAtomic(pointer, []byte(refreshed.ID), 0o600)
}
func (s *Service) convert(ctx context.Context, raw []byte, source Source) (Artifact, error) {
	if s.Convert != nil {
		return s.Convert(ctx, raw, source)
	}
	return (Codec{Binaries: source.Binaries}).Convert(ctx, raw, source.Target, source.Hint)
}

type formatChanged struct{ Artifact Artifact }

func (*formatChanged) Error() string {
	return "source requires a different output format or behavior; re-prepare the profile"
}
func (s *Service) publish(r Record, artifact Artifact, etag, modified string) (Record, error) {
	previous := r.Digest
	if r.Digest == "" {
		r.Source.Contract = artifact.Format + "/" + artifact.Behavior
		var err error
		r.ID, err = s.id(r.Source)
		if err != nil {
			return r, err
		}
	}
	digest := sha256.Sum256(artifact.Data)
	r.Digest = hex.EncodeToString(digest[:])
	r.Format, r.Behavior, r.Count = artifact.Format, artifact.Behavior, artifact.Count
	if err := os.MkdirAll(filepath.Join(s.root, r.ID), 0o700); err != nil {
		return r, err
	}
	if err := state.WriteFileAtomic(filepath.Join(s.root, r.ID, r.Digest), artifact.Data, 0o600); err != nil {
		return r, err
	}
	if err := state.WriteFileAtomic(s.InitialPath(r), artifact.Data, 0o600); err != nil {
		return r, err
	}
	r.SourceETag, r.SourceModified = etag, modified
	r.ConvertedAt, r.CheckedAt = time.Now().UTC(), time.Now().UTC()
	r.LastError = ""
	if err := s.save(r); err != nil {
		return r, err
	}
	// Keep the current and immediately previous artifact. Only immutable blobs
	// owned by this registration are eligible; preserve metadata and seeds.
	entries, _ := os.ReadDir(filepath.Join(s.root, r.ID))
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && validID(name) && name != r.Digest && name != previous {
			_ = os.Remove(filepath.Join(s.root, r.ID, name))
		}
	}
	return r, nil
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	tail := strings.TrimPrefix(r.URL.Path, endpointPrefix)
	id, name, ok := strings.Cut(tail, "/")
	if !ok || !strings.HasPrefix(r.URL.Path, endpointPrefix) || !validID(id) {
		http.NotFound(w, r)
		return
	}
	record, err := s.load(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	started := time.Now()
	source := record.Source
	source.Contract = ""
	key, err := s.id(source)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	unlock := s.lock(key)
	defer unlock()
	record, err = s.load(id)
	if err != nil || name != "rules."+extension(record.Format) {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		if !record.CheckedAt.After(started) {
			record, err = s.refresh(r.Context(), record)
		} else if record.LastError != "" {
			err = errors.New(record.LastError)
		}
		if err != nil {
			http.Error(w, "rule conversion update failed; last good version retained", http.StatusBadGateway)
			return
		}
	}
	content, err := s.artifact(record)
	if err != nil {
		http.Error(w, "converted rule cache unavailable", http.StatusServiceUnavailable)
		return
	}
	etag := "\"" + record.Digest + "\""
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "application/octet-stream")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	if r.Method == http.MethodGet {
		_, _ = w.Write(content)
	}
}
func (s *Service) refresh(ctx context.Context, r Record) (Record, error) {
	raw, etag, modified, unchanged, err := s.fetch(ctx, r)
	if err == nil && unchanged && r.Digest == "" {
		err = errors.New("upstream returned 304 without a cached rule set")
	}
	if err == nil && !unchanged {
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		if r.Digest != "" && digest == r.SourceDigest {
			unchanged = true
		}
		if !unchanged {
			var artifact Artifact
			artifact, err = s.convert(ctx, raw, r.Source)
			if err == nil && r.Digest != "" && (r.Format != artifact.Format || r.Behavior != artifact.Behavior) {
				err = &formatChanged{Artifact: artifact}
			}
			if err == nil {
				r.SourceDigest = digest
				return s.publish(r, artifact, etag, modified)
			}
		}
	}
	r.CheckedAt = time.Now().UTC()
	if err != nil {
		r.LastError = err.Error()
		if r.Digest != "" {
			_ = s.save(r)
		}
		return r, err
	}
	if etag != "" {
		r.SourceETag = etag
	}
	if modified != "" {
		r.SourceModified = modified
	}
	r.LastError = ""
	return r, s.save(r)
}
func (s *Service) save(r Record) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return state.WriteFileAtomic(filepath.Join(s.root, r.ID, "record.json"), data, 0o600)
}
func (s *Service) load(id string) (Record, error) {
	var r Record
	if !validID(id) {
		return r, errors.New("invalid conversion ID")
	}
	data, err := readRegular(filepath.Join(s.root, id, "record.json"), 1<<20)
	if err != nil {
		return r, err
	}
	if json.Unmarshal(data, &r) != nil || r.ID != id || !validID(r.Digest) {
		return r, errors.New("invalid converted rule registration")
	}
	return r, nil
}
func (s *Service) artifact(r Record) ([]byte, error) {
	data, err := readRegular(filepath.Join(s.root, r.ID, r.Digest), MaxBytes)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != r.Digest {
		return nil, errors.New("converted rule checksum mismatch")
	}
	return data, nil
}
func validID(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// Status reports conversion, not application by the core. URLs, headers and
// local capability addresses are deliberately excluded from the panel response.
func (s *Service) Status(ids []string) []Status {
	results := make([]Status, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		unlock := s.lock(id)
		r, err := s.load(id)
		unlock()
		if err != nil {
			continue
		}
		results = append(results, Status{ID: r.ID, Target: r.Source.Target, Format: r.Format, Behavior: r.Behavior, Count: r.Count, CheckedAt: r.CheckedAt, ConvertedAt: r.ConvertedAt, LastError: r.LastError})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].ID < results[j].ID })
	return results
}
func parseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("convert: requires an HTTP(S) URL without credentials or fragment")
	}
	return u, nil
}
func (s *Service) fetch(ctx context.Context, r Record) ([]byte, string, string, bool, error) {
	endpoint, err := parseURL(r.Source.URL)
	if err != nil {
		return nil, "", "", false, err
	}
	if endpoint.Host == s.listener.Address && strings.HasPrefix(endpoint.Path, endpointPrefix) {
		return nil, "", "", false, errors.New("recursive conversion source")
	}
	client := http.Client{Timeout: 45 * time.Second}
	if s.Client != nil {
		client = *s.Client
	}
	if s.Client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		if r.Source.HTTPVersion == "1" {
			transport.ForceAttemptHTTP2 = false
			transport.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
		}
		dialer := &net.Dialer{Timeout: 15 * time.Second, Control: socketControl(r.Source.LoopMark)}
		transport.DialContext = dialer.DialContext
		client.Transport = transport
		defer transport.CloseIdleConnections()
	}
	if r.Source.ProxyURL != "" {
		proxy, err := url.Parse(r.Source.ProxyURL)
		if err != nil || proxy.Scheme != "http" || !s.isBridge(proxy.Host) {
			return nil, "", "", false, errors.New("invalid local download bridge")
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if configured, ok := client.Transport.(*http.Transport); ok {
			transport = configured.Clone()
		}
		transport.Proxy = http.ProxyURL(proxy)
		defer transport.CloseIdleConnections()
		client.Transport = transport
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 4 {
			return errors.New("too many redirects")
		}
		if _, e := parseURL(req.URL.String()); e != nil {
			return e
		}
		if endpoint.Scheme == "https" && req.URL.Scheme != "https" {
			return errors.New("insecure redirect")
		}
		if req.URL.Host != endpoint.Host {
			req.Header.Del("Authorization")
			req.Header.Del("Cookie")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.Source.URL, nil)
	if err != nil {
		return nil, "", "", false, errors.New("invalid rule request")
	}
	req.Header = r.Source.Headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	if host := req.Header.Get("Host"); host != "" {
		req.Host = host
		req.Header.Del("Host")
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "boxctl-rule-converter/1")
	}
	if r.SourceETag != "" {
		req.Header.Set("If-None-Match", r.SourceETag)
	}
	if r.SourceModified != "" {
		req.Header.Set("If-Modified-Since", r.SourceModified)
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, "", "", false, errors.New("download failed (network, TLS or timeout)")
	}
	defer response.Body.Close()
	etag, modified := response.Header.Get("ETag"), response.Header.Get("Last-Modified")
	if len(etag) > 4096 {
		etag = ""
	}
	if len(modified) > 4096 {
		modified = ""
	}
	if response.StatusCode == 304 {
		return nil, etag, modified, true, nil
	}
	if response.StatusCode != 200 {
		return nil, "", "", false, fmt.Errorf("upstream HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxBytes+1))
	if err != nil {
		return nil, "", "", false, errors.New("read rule response")
	}
	if len(data) > MaxBytes {
		return nil, "", "", false, errors.New("rule response exceeds size limit")
	}
	return data, etag, modified, false, nil
}

func (s *Service) isBridge(address string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if address == s.listener.BridgeAddress {
		return true
	}
	for _, candidate := range s.listener.MihomoBridges {
		if address == candidate {
			return true
		}
	}
	return false
}
func (s *Service) mihomoBridge(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if address := s.listener.MihomoBridges[key]; address != "" {
		if !loopbackAddress(address) {
			return "", errors.New("invalid download bridge address")
		}
		return address, nil
	}
	if len(s.listener.MihomoBridges) >= 128 {
		return "", errors.New("too many download bridge registrations")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer listener.Close()
	address := listener.Addr().String()
	if s.listener.MihomoBridges == nil {
		s.listener.MihomoBridges = map[string]string{}
	}
	s.listener.MihomoBridges[key] = address
	//nolint:gosec // The listener capability seed is deliberately persisted only in this private 0600 state file.
	data, err := json.Marshal(s.listener)
	if err != nil {
		return "", err
	}
	if err = state.WriteFileAtomic(filepath.Join(s.root, "listener.json"), data, 0o600); err != nil {
		delete(s.listener.MihomoBridges, key)
		return "", err
	}
	return address, nil
}
