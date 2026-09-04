package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strings"
)

const EngineMihomo = "mihomo"
const EngineSingBox = "sing-box"

type ActiveProfile struct {
	Name   string `json:"name"`
	Engine string `json:"engine"`
}

var profileName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

// ParseActiveProfile accepts a plain profile name or JSON metadata. A missing
// engine means Mihomo.
func ParseActiveProfile(data []byte) (ActiveProfile, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return ActiveProfile{}, errors.New("state: empty active profile")
	}
	var profile ActiveProfile
	if trimmed[0] == '{' {
		decoder := json.NewDecoder(bytes.NewReader(trimmed))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&profile); err != nil {
			return ActiveProfile{}, fmt.Errorf("state: parse active profile JSON: %w", err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return ActiveProfile{}, errors.New("state: trailing active profile JSON")
		}
	} else {
		profile.Name = string(trimmed)
	}
	if profile.Engine == "" {
		profile.Engine = EngineMihomo
	}
	if err := validateActiveProfile(profile); err != nil {
		return ActiveProfile{}, err
	}
	return profile, nil
}

func validateActiveProfile(profile ActiveProfile) error {
	if !profileName.MatchString(profile.Name) {
		return fmt.Errorf("state: invalid profile name %q", profile.Name)
	}
	switch profile.Engine {
	case EngineMihomo, EngineSingBox:
		return nil
	default:
		return fmt.Errorf("state: unsupported profile engine %q", profile.Engine)
	}
}

func MarshalActiveProfile(profile ActiveProfile) ([]byte, error) {
	if profile.Engine == "" {
		profile.Engine = EngineMihomo
	}
	if err := validateActiveProfile(profile); err != nil {
		return nil, err
	}
	data, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func (store Store) LoadActiveProfile(name string) (ActiveProfile, error) {
	data, err := store.Read(name)
	if err != nil {
		return ActiveProfile{}, err
	}
	return ParseActiveProfile(data)
}

func (store Store) SaveActiveProfile(name string, profile ActiveProfile) error {
	data, err := MarshalActiveProfile(profile)
	if err != nil {
		return err
	}
	return store.Write(name, data, fs.FileMode(0o600))
}

func ProfileConfigName(profile ActiveProfile) string {
	extension := ".yaml"
	if strings.EqualFold(profile.Engine, EngineSingBox) {
		extension = ".json"
	}
	return profile.Name + extension
}
