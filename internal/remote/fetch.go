// Package remote downloads complete native core profiles without exposing
// subscription URLs or device headers to logs and API responses.
package remote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultMaxProfileBytes = int64(32 << 20)

// Validator is called before a downloaded profile can be persisted.
type Validator interface {
	ValidateProfile(context.Context, []byte) error
}

// ValidatorFunc adapts a function to Validator.
type ValidatorFunc func(context.Context, []byte) error

func (function ValidatorFunc) ValidateProfile(ctx context.Context, profile []byte) error {
	return function(ctx, profile)
}

// Request describes one conditional profile download.
type Request struct {
	URL               string
	ETag              string
	LastModified      string
	Headers           map[string]string
	RemnawaveFallback bool
	MaxBytes          int64
}

// Result contains profile bytes and safe caching metadata. SourceURL is never
// returned so callers cannot accidentally serialize a subscription token.
type Result struct {
	Content          []byte
	Fingerprint      string
	ETag             string
	LastModified     string
	SuggestedUpdate  time.Duration
	NotModified      bool
	UsedFallback     bool
	SubscriptionInfo string
}

// Fetcher retrieves and validates remote profiles.
type Fetcher struct {
	Client    *http.Client
	Validator Validator
}

// Fetch downloads the requested URL. A Remnawave /sub/{token} URL may be
// retried as /mihomo/{token} when the first response fails or is not a valid
// native profile.
func (f Fetcher) Fetch(ctx context.Context, request Request) (Result, error) {
	if f.Validator == nil {
		return Result{}, errors.New("remote profile validator is required")
	}
	primary, err := parseSourceURL(request.URL)
	if err != nil {
		return Result{}, err
	}
	client := secureClient(f.Client)
	result, primaryErr := f.fetchOne(ctx, client, primary, request, false)
	if primaryErr == nil || result.NotModified || !request.RemnawaveFallback {
		return result, primaryErr
	}
	fallback, ok := remnawaveURL(primary)
	if !ok {
		return Result{}, primaryErr
	}
	result, fallbackErr := f.fetchOne(ctx, client, fallback, request, true)
	if fallbackErr != nil {
		return Result{}, fmt.Errorf("remote profile and Remnawave fallback both failed: primary: %w; fallback: %w", primaryErr, fallbackErr)
	}
	return result, nil
}

func (f Fetcher) fetchOne(ctx context.Context, client *http.Client, endpoint *url.URL, request Request, fallback bool) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return Result{}, errors.New("create remote profile request")
	}
	req.Header.Set("Accept", "application/yaml, text/yaml, text/plain;q=0.9, application/octet-stream;q=0.8")
	req.Header.Set("User-Agent", "boxctl/1")
	if request.ETag != "" {
		req.Header.Set("If-None-Match", cleanHeaderValue(request.ETag))
	}
	if request.LastModified != "" {
		req.Header.Set("If-Modified-Since", cleanHeaderValue(request.LastModified))
	}
	for name, value := range request.Headers {
		if !allowedDeviceHeader(name) {
			return Result{}, fmt.Errorf("unsupported remote profile header %q", name)
		}
		req.Header.Set(name, cleanHeaderValue(value))
	}
	response, err := client.Do(req)
	if err != nil {
		return Result{}, errors.New("download remote profile")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		return Result{
			ETag:             response.Header.Get("ETag"),
			LastModified:     response.Header.Get("Last-Modified"),
			SuggestedUpdate:  parseUpdateInterval(response.Header.Get("Profile-Update-Interval")),
			NotModified:      true,
			UsedFallback:     fallback,
			SubscriptionInfo: response.Header.Get("Subscription-Userinfo"),
		}, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Result{}, fmt.Errorf("remote profile returned HTTP %d", response.StatusCode)
	}
	maxBytes := request.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxProfileBytes
	}
	if response.ContentLength > maxBytes {
		return Result{}, fmt.Errorf("remote profile exceeds %d bytes", maxBytes)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return Result{}, errors.New("read remote profile")
	}
	if int64(len(content)) > maxBytes {
		return Result{}, fmt.Errorf("remote profile exceeds %d bytes", maxBytes)
	}
	if len(strings.TrimSpace(string(content))) == 0 {
		return Result{}, errors.New("remote profile is empty")
	}
	if err := f.Validator.ValidateProfile(ctx, content); err != nil {
		return Result{}, fmt.Errorf("validate remote profile: %w", err)
	}
	digest := sha256.Sum256(content)
	return Result{
		Content:          content,
		Fingerprint:      hex.EncodeToString(digest[:]),
		ETag:             response.Header.Get("ETag"),
		LastModified:     response.Header.Get("Last-Modified"),
		SuggestedUpdate:  parseUpdateInterval(response.Header.Get("Profile-Update-Interval")),
		UsedFallback:     fallback,
		SubscriptionInfo: response.Header.Get("Subscription-Userinfo"),
	}, nil
}

func parseSourceURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("remote profile URL must be an HTTPS URL without user-info or fragment")
	}
	return parsed, nil
}

func remnawaveURL(source *url.URL) (*url.URL, bool) {
	segments := strings.Split(source.EscapedPath(), "/")
	for index, segment := range segments {
		if segment == "sub" && index+1 < len(segments) && segments[index+1] != "" {
			clone := *source
			segments[index] = "mihomo"
			clone.RawPath = strings.Join(segments, "/")
			decoded, err := url.PathUnescape(clone.RawPath)
			if err != nil {
				return nil, false
			}
			clone.Path = decoded
			return &clone, true
		}
	}
	return nil, false
}

func secureClient(base *http.Client) *http.Client {
	if base == nil {
		base = http.DefaultClient
	}
	clone := *base
	if clone.Timeout == 0 {
		clone.Timeout = 45 * time.Second
	}
	priorRedirect := clone.CheckRedirect
	clone.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many remote profile redirects")
		}
		if request.URL.Scheme != "https" || request.URL.User != nil {
			return errors.New("unsafe remote profile redirect")
		}
		if priorRedirect != nil {
			return priorRedirect(request, via)
		}
		return nil
	}
	return &clone
}

func allowedDeviceHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "user-agent", "x-hwid", "x-device-os", "x-ver-os", "x-device-model":
		return true
	default:
		return false
	}
}

func cleanHeaderValue(value string) string {
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	return strings.TrimSpace(value)
}

func parseUpdateInterval(value string) time.Duration {
	hours, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || hours < 1 || hours > 168 {
		return 0
	}
	return time.Duration(hours) * time.Hour
}
