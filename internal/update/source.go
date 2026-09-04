// Package update implements verified binary release discovery and installation.
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const defaultAPIBase = "https://api.github.com"

// Channel controls whether pre-release artifacts are eligible.
type Channel string

const (
	ChannelStable Channel = "stable"
	ChannelAlpha  Channel = "alpha"
)

// Asset is a downloadable release artifact with a GitHub-attested digest.
type Asset struct {
	Name      string `json:"name"`
	URL       string `json:"browser_download_url"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	UpdatedAt string `json:"updated_at"`
}

// Release is the subset of the GitHub release schema required by boxctl.
type Release struct {
	Tag        string  `json:"tag_name"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
}

// Source discovers release metadata using the public GitHub API.
type Source struct {
	Client  *http.Client
	APIBase string
	Repo    string
}

// NewMihomoSource returns a source for official MetaCubeX/mihomo releases.
func NewMihomoSource(client *http.Client) *Source {
	return &Source{Client: client, APIBase: defaultAPIBase, Repo: "MetaCubeX/mihomo"}
}

// NewBoxctlSource returns a source for boxctl manager releases. Repository may
// be overridden for mirrors and tests; production uses kontsevoye/boxctl.
func NewBoxctlSource(client *http.Client, repository string) *Source {
	if strings.TrimSpace(repository) == "" {
		repository = "kontsevoye/boxctl"
	}
	return &Source{Client: client, APIBase: defaultAPIBase, Repo: repository}
}

// Latest returns the newest eligible release in GitHub's release order.
func (s *Source) Latest(ctx context.Context, channel Channel) (Release, error) {
	if channel != ChannelStable && channel != ChannelAlpha {
		return Release{}, fmt.Errorf("unsupported update channel %q", channel)
	}
	if s.Client == nil {
		s.Client = http.DefaultClient
	}
	base := strings.TrimRight(s.APIBase, "/")
	if base == "" {
		base = defaultAPIBase
	}
	repo := strings.Trim(s.Repo, "/")
	if !githubRepository.MatchString(repo) || strings.Contains(repo, "..") {
		return Release{}, errors.New("invalid GitHub repository")
	}
	endpoint := base + "/repos/" + repo + "/releases/latest"
	if channel == ChannelAlpha {
		endpoint = base + "/repos/" + repo + "/releases?per_page=30"
	}
	if channel == ChannelStable {
		var release Release
		if err := s.fetchReleaseMetadata(ctx, endpoint, &release); err != nil {
			return Release{}, err
		}
		if release.Draft || release.Prerelease {
			return Release{}, errors.New("latest GitHub release is not stable")
		}
		return release, nil
	}

	var releases []Release
	if err := s.fetchReleaseMetadata(ctx, endpoint, &releases); err != nil {
		return Release{}, err
	}
	for _, release := range releases {
		if release.Draft {
			continue
		}
		return release, nil
	}
	return Release{}, fmt.Errorf("no %s release found", channel)
}

func (s *Source) fetchReleaseMetadata(ctx context.Context, endpoint string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("create release request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "boxctl")
	resp, err := s.Client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch releases: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch releases: HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > 4<<20 {
		return errors.New("release metadata exceeds 4194304 bytes")
	}
	limited := &io.LimitedReader{R: resp.Body, N: (4 << 20) + 1}
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode releases: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("decode releases: trailing data")
	}
	if limited.N <= 0 {
		return errors.New("release metadata exceeds 4194304 bytes")
	}
	return nil
}

var versionTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$`)
var githubRepository = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// LinuxARM64 selects the generic gzip-compressed AArch64 artifact. Variants,
// packages and assets whose version does not match the release are rejected.
func (r Release) LinuxARM64() (Asset, error) {
	if !versionTag.MatchString(r.Tag) {
		return Asset{}, fmt.Errorf("unsafe release tag %q", r.Tag)
	}
	want := "mihomo-linux-arm64-" + r.Tag + ".gz"
	for _, asset := range r.Assets {
		if asset.Name != want {
			continue
		}
		if asset.URL == "" || asset.Size <= 0 {
			return Asset{}, fmt.Errorf("release asset %s has incomplete metadata", want)
		}
		parsed, err := url.Parse(asset.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return Asset{}, fmt.Errorf("release asset %s has unsafe URL", want)
		}
		if _, err := ParseDigest(asset.Digest); err != nil {
			return Asset{}, fmt.Errorf("release asset %s: %w", want, err)
		}
		return asset, nil
	}
	return Asset{}, fmt.Errorf("release %s has no %s asset", r.Tag, want)
}

// BoxctlLinuxARM64 selects the raw AArch64 manager binary associated with a
// strict vYYYY.MM.N CalVer release tag, where N is the monthly release number.
func (r Release) BoxctlLinuxARM64() (Asset, error) {
	version, err := ParseBoxctlCalVerTag(r.Tag)
	if err != nil {
		return Asset{}, err
	}
	want := "boxctl-linux-arm64-" + version
	for _, asset := range r.Assets {
		if asset.Name != want {
			continue
		}
		if asset.URL == "" || asset.Size <= 0 {
			return Asset{}, fmt.Errorf("release asset %s has incomplete metadata", want)
		}
		parsed, err := url.Parse(asset.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return Asset{}, fmt.Errorf("release asset %s has unsafe URL", want)
		}
		if _, err := ParseDigest(asset.Digest); err != nil {
			return Asset{}, fmt.Errorf("release asset %s: %w", want, err)
		}
		return asset, nil
	}
	return Asset{}, fmt.Errorf("release %s has no %s asset", r.Tag, want)
}

// ParseBoxctlCalVerTag validates and normalizes the tag used by boxctl release
// assets. The month is zero-padded and the monthly release number is positive.
func ParseBoxctlCalVerTag(tag string) (string, error) {
	if !strings.HasPrefix(tag, "v") {
		return "", fmt.Errorf("unsafe boxctl release tag %q", tag)
	}
	version := strings.TrimPrefix(tag, "v")
	parts := strings.Split(version, ".")
	if len(parts) != 3 || len(parts[0]) != 4 || len(parts[1]) != 2 {
		return "", fmt.Errorf("unsafe boxctl release tag %q", tag)
	}
	year, yearErr := strconv.ParseUint(parts[0], 10, 16)
	month, monthErr := strconv.ParseUint(parts[1], 10, 8)
	sequence, sequenceErr := strconv.ParseUint(parts[2], 10, 64)
	if yearErr != nil || year < 1000 || strconv.FormatUint(year, 10) != parts[0] ||
		monthErr != nil || month < 1 || month > 12 || fmt.Sprintf("%02d", month) != parts[1] ||
		sequenceErr != nil || sequence == 0 || strconv.FormatUint(sequence, 10) != parts[2] {
		return "", fmt.Errorf("unsafe boxctl release tag %q", tag)
	}
	return version, nil
}

// CompareBoxctlCalVer compares normalized CalVer values without a leading v.
// It returns -1, 0 or 1 when left is older, equal or newer than right.
func CompareBoxctlCalVer(left, right string) (int, error) {
	leftParts, err := boxctlCalVerParts(left)
	if err != nil {
		return 0, err
	}
	rightParts, err := boxctlCalVerParts(right)
	if err != nil {
		return 0, err
	}
	for index := range leftParts {
		if leftParts[index] < rightParts[index] {
			return -1, nil
		}
		if leftParts[index] > rightParts[index] {
			return 1, nil
		}
	}
	return 0, nil
}

func boxctlCalVerParts(version string) ([3]uint64, error) {
	var result [3]uint64
	normalized, err := ParseBoxctlCalVerTag("v" + strings.TrimPrefix(version, "v"))
	if err != nil {
		return result, err
	}
	for index, value := range strings.Split(normalized, ".") {
		parsed, parseErr := strconv.ParseUint(value, 10, 64)
		if parseErr != nil {
			return result, parseErr
		}
		result[index] = parsed
	}
	return result, nil
}
