package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"github.com/kontsevoye/boxctl/internal/state"
)

const hwidRelativePath = ".boxctl/hwid"

var validHWID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// DeviceIdentity provides the stable, private headers expected by Remnawave
// compatible proxy providers. The random HWID is persisted inside protected
// boxctl state and is never returned through the web API.
type DeviceIdentity struct {
	State         state.Store
	ReleasePath   string
	ModelPath     string
	BoardNamePath string
	Random        io.Reader
}

func NewDeviceIdentity(store state.Store) *DeviceIdentity {
	return &DeviceIdentity{
		State: store, ReleasePath: "/etc/openwrt_release",
		ModelPath: "/tmp/sysinfo/model", BoardNamePath: "/tmp/sysinfo/board_name",
		Random: rand.Reader,
	}
}

func (identity *DeviceIdentity) Headers(ctx context.Context) (map[string]string, error) {
	if identity == nil || identity.State.Root == "" {
		return nil, errors.New("device identity is not initialized")
	}
	hwid, err := identity.loadOrCreateHWID(ctx)
	if err != nil {
		return nil, err
	}
	version := openWrtRelease(identity.ReleasePath)
	if version == "" {
		version = "unknown"
	}
	model := boundedIdentityFile(identity.ModelPath)
	if model == "" {
		model = boundedIdentityFile(identity.BoardNamePath)
	}
	if model == "" {
		model = "OpenWrt router"
	}
	version = cleanDeviceHeader(version, 64)
	model = cleanDeviceHeader(model, 128)
	return map[string]string{
		"User-Agent":     cleanDeviceHeader("boxctl/1 (OpenWrt "+version+"; "+model+")", 220),
		"x-hwid":         hwid,
		"x-device-os":    "OpenWrt",
		"x-ver-os":       version,
		"x-device-model": model,
	}, nil
}

func (identity *DeviceIdentity) loadOrCreateHWID(ctx context.Context) (string, error) {
	var result string
	err := identity.State.WithLock(ctx, "device-identity", func() error {
		content, err := identity.State.Read(hwidRelativePath)
		if err == nil {
			candidate := strings.ToLower(strings.TrimSpace(string(content)))
			if !validHWID.MatchString(candidate) {
				return errors.New("stored device identity is invalid")
			}
			result = candidate
			return nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		random := identity.Random
		if random == nil {
			random = rand.Reader
		}
		var raw [16]byte
		if _, err := io.ReadFull(random, raw[:]); err != nil {
			return fmt.Errorf("generate device identity: %w", err)
		}
		raw[6] = (raw[6] & 0x0f) | 0x40
		raw[8] = (raw[8] & 0x3f) | 0x80
		encoded := hex.EncodeToString(raw[:])
		result = encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
		return identity.State.Write(hwidRelativePath, []byte(result+"\n"), 0o600)
	})
	return result, err
}

func openWrtRelease(path string) string {
	content := boundedIdentityFileRaw(path)
	for _, line := range strings.Split(content, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found || strings.TrimSpace(key) != "DISTRIB_RELEASE" {
			continue
		}
		return strings.Trim(strings.TrimSpace(value), "'\"")
	}
	return ""
}

func boundedIdentityFile(path string) string {
	return strings.TrimSpace(boundedIdentityFileRaw(path))
}

func boundedIdentityFileRaw(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 8<<10 {
		return ""
	}
	content, err := os.ReadFile(path)
	if err != nil || len(content) > 8<<10 || strings.IndexByte(string(content), 0) >= 0 {
		return ""
	}
	return string(content)
}

func cleanDeviceHeader(value string, maximum int) string {
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, strings.TrimSpace(value))
	value = strings.Join(strings.Fields(value), " ")
	characters := []rune(value)
	if len(characters) > maximum {
		value = string(characters[:maximum])
	}
	return value
}
