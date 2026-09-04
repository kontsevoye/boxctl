package state

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"slices"
	"strings"
)

type Settings map[string]string

var settingKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func ParseSettings(data []byte) (Settings, error) {
	result := make(Settings)
	reader := bufio.NewReader(bytes.NewReader(data))
	for lineNumber := 1; ; lineNumber++ {
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("state: read settings line %d: %w", lineNumber, err)
		}
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			key, value, found := strings.Cut(line, "=")
			if !found || !settingKey.MatchString(key) {
				return nil, fmt.Errorf("state: invalid settings line %d", lineNumber)
			}
			if _, duplicate := result[key]; duplicate {
				return nil, fmt.Errorf("state: duplicate setting %s", key)
			}
			if strings.ContainsRune(value, 0) {
				return nil, fmt.Errorf("state: NUL in setting %s", key)
			}
			result[key] = value
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	return result, nil
}

func MarshalSettings(settings Settings) ([]byte, error) {
	keys := make([]string, 0, len(settings))
	for key, value := range settings {
		if !settingKey.MatchString(key) {
			return nil, fmt.Errorf("state: invalid setting key %q", key)
		}
		if strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("state: invalid newline or NUL in setting %s", key)
		}
		keys = append(keys, key)
	}
	slices.Sort(keys)
	var output strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&output, "%s=%s\n", key, settings[key])
	}
	return []byte(output.String()), nil
}

func (store Store) LoadSettings(name string) (Settings, error) {
	data, err := store.Read(name)
	if err != nil {
		return nil, err
	}
	return ParseSettings(data)
}

func (store Store) SaveSettings(name string, settings Settings) error {
	data, err := MarshalSettings(settings)
	if err != nil {
		return err
	}
	return store.Write(name, data, fs.FileMode(0o600))
}
