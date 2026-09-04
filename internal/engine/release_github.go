package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultMihomoReleaseAPI = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
	maxReleaseMetadata      = 4 << 20
	maxReleaseAsset         = 512 << 20
)

// GitHubReleaseOptions allows tests and mirrors to provide their own endpoint.
// Insecure HTTP is rejected unless explicitly enabled.
type GitHubReleaseOptions struct {
	APIURL            string
	HTTPClient        *http.Client
	UserAgent         string
	AllowInsecureHTTP bool
}

// GitHubReleaseSource implements ReleaseSource for a GitHub-compatible latest
// release endpoint.
type GitHubReleaseSource struct {
	apiURL            string
	client            *http.Client
	userAgent         string
	allowInsecureHTTP bool
}

func NewMihomoReleaseSource(options GitHubReleaseOptions) (*GitHubReleaseSource, error) {
	if options.APIURL == "" {
		options.APIURL = defaultMihomoReleaseAPI
	}
	if options.UserAgent == "" {
		options.UserAgent = "boxctl"
	}
	if err := validateDownloadURL(options.APIURL, options.AllowInsecureHTTP); err != nil {
		return nil, fmt.Errorf("invalid release API URL: %w", err)
	}
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &GitHubReleaseSource{
		apiURL:            options.APIURL,
		client:            client,
		userAgent:         options.UserAgent,
		allowInsecureHTTP: options.AllowInsecureHTTP,
	}, nil
}

func (s *GitHubReleaseSource) Latest(ctx context.Context) (Release, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.apiURL, nil)
	if err != nil {
		return Release{}, fmt.Errorf("build release request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", s.userAgent)
	response, err := s.client.Do(request)
	if err != nil {
		return Release{}, fmt.Errorf("fetch latest release: %w", err)
	}
	defer response.Body.Close()
	if err := validateDownloadURL(response.Request.URL.String(), s.allowInsecureHTTP); err != nil {
		return Release{}, fmt.Errorf("release API redirected to an unsafe URL: %w", err)
	}
	data, err := readLimited(response.Body, maxReleaseMetadata)
	if err != nil {
		return Release{}, fmt.Errorf("read latest release: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		detail := strings.TrimSpace(string(data))
		if len(detail) > 4096 {
			detail = detail[:4096] + "…"
		}
		return Release{}, fmt.Errorf("release API returned %d: %s", response.StatusCode, detail)
	}
	var wire struct {
		TagName     string `json:"tag_name"`
		Name        string `json:"name"`
		PublishedAt string `json:"published_at"`
		Assets      []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
			Size               int64  `json:"size"`
			ContentType        string `json:"content_type"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return Release{}, fmt.Errorf("decode latest release: %w", err)
	}
	if wire.TagName == "" {
		return Release{}, errors.New("latest release has no tag")
	}
	publishedAt := time.Time{}
	if wire.PublishedAt != "" {
		publishedAt, err = time.Parse(time.RFC3339, wire.PublishedAt)
		if err != nil {
			return Release{}, fmt.Errorf("parse release publication time: %w", err)
		}
	}
	release := Release{Tag: wire.TagName, Name: wire.Name, PublishedAt: publishedAt}
	for _, asset := range wire.Assets {
		if asset.Name == "" || asset.BrowserDownloadURL == "" {
			continue
		}
		if err := validateDownloadURL(asset.BrowserDownloadURL, s.allowInsecureHTTP); err != nil {
			return Release{}, fmt.Errorf("release asset %q has unsafe URL: %w", asset.Name, err)
		}
		release.Assets = append(release.Assets, ReleaseAsset{
			Name:        asset.Name,
			URL:         asset.BrowserDownloadURL,
			Size:        asset.Size,
			ContentType: asset.ContentType,
		})
	}
	return release, nil
}

func (s *GitHubReleaseSource) Open(ctx context.Context, asset ReleaseAsset) (io.ReadCloser, error) {
	if err := validateDownloadURL(asset.URL, s.allowInsecureHTTP); err != nil {
		return nil, err
	}
	if asset.Size < 0 || asset.Size > maxReleaseAsset {
		return nil, fmt.Errorf("release asset size %d is outside the allowed range", asset.Size)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("build release asset request: %w", err)
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("User-Agent", s.userAgent)
	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("download release asset: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		defer response.Body.Close()
		data, _ := readLimited(response.Body, 4096)
		return nil, fmt.Errorf("release asset returned %d: %s", response.StatusCode, strings.TrimSpace(string(data)))
	}
	if err := validateDownloadURL(response.Request.URL.String(), s.allowInsecureHTTP); err != nil {
		_ = response.Body.Close()
		return nil, fmt.Errorf("release asset redirected to an unsafe URL: %w", err)
	}
	if response.ContentLength > maxReleaseAsset {
		_ = response.Body.Close()
		return nil, errors.New("release asset exceeds size limit")
	}
	return &boundedReadCloser{reader: response.Body, closer: response.Body, remaining: maxReleaseAsset}, nil
}

func validateDownloadURL(raw string, allowHTTP bool) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("URL must have a host and no credentials or fragment")
	}
	if parsed.Scheme != "https" && (!allowHTTP || parsed.Scheme != "http") {
		return errors.New("URL must use HTTPS")
	}
	return nil
}

func readLimited(reader io.Reader, maximum int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("response exceeds size limit")
	}
	return data, nil
}

type boundedReadCloser struct {
	reader    io.Reader
	closer    io.Closer
	remaining int64
}

func (r *boundedReadCloser) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if r.remaining > 0 {
		if int64(len(buffer)) > r.remaining {
			buffer = buffer[:r.remaining]
		}
		count, err := r.reader.Read(buffer)
		r.remaining -= int64(count)
		return count, err
	}
	var probe [1]byte
	count, err := r.reader.Read(probe[:])
	if count > 0 {
		return 0, errors.New("release asset exceeds size limit")
	}
	return 0, err
}

func (r *boundedReadCloser) Close() error {
	return r.closer.Close()
}

// FindReleaseAsset returns one exact asset and rejects duplicate names.
func FindReleaseAsset(release Release, name string) (ReleaseAsset, error) {
	var found *ReleaseAsset
	for index := range release.Assets {
		if release.Assets[index].Name != name {
			continue
		}
		if found != nil {
			return ReleaseAsset{}, fmt.Errorf("release contains duplicate asset %q", name)
		}
		asset := release.Assets[index]
		found = &asset
	}
	if found == nil {
		return ReleaseAsset{}, fmt.Errorf("release asset %q was not found", name)
	}
	return *found, nil
}

var _ ReleaseSource = (*GitHubReleaseSource)(nil)
