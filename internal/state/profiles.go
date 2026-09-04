package state

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const maxProfileSize = 16 << 20

type ProfileStore struct {
	Layout Layout
	Store  Store
}

func NewProfileStore(root string) (ProfileStore, error) {
	layout, err := NewLayout(root)
	if err != nil {
		return ProfileStore{}, err
	}
	store, err := NewStore(layout.Root)
	if err != nil {
		return ProfileStore{}, err
	}
	return ProfileStore{Layout: layout, Store: store}, nil
}

type ProfileEntry struct {
	ActiveProfile
	Path string
	Size int64
}

func (profiles ProfileStore) List() ([]ProfileEntry, error) {
	if err := profiles.Store.checkDirectory(profiles.Layout.ProfilesDir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(profiles.Layout.ProfilesDir)
	if errors.Is(err, fs.ErrNotExist) {
		return []ProfileEntry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("state: list profiles: %w", err)
	}
	result := make([]ProfileEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		name, engine, ok := profileFromFileName(entry.Name())
		if !ok {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		result = append(result, ProfileEntry{
			ActiveProfile: ActiveProfile{Name: name, Engine: engine},
			Path:          filepath.Join(profiles.Layout.ProfilesDir, entry.Name()),
			Size:          info.Size(),
		})
	}
	slices.SortFunc(result, func(left, right ProfileEntry) int {
		if left.Name != right.Name {
			return strings.Compare(left.Name, right.Name)
		}
		return strings.Compare(left.Engine, right.Engine)
	})
	return result, nil
}

func profileFromFileName(fileName string) (name, engine string, ok bool) {
	switch {
	case strings.HasSuffix(fileName, ".yaml"):
		name, engine = strings.TrimSuffix(fileName, ".yaml"), EngineMihomo
	case strings.HasSuffix(fileName, ".json"):
		name, engine = strings.TrimSuffix(fileName, ".json"), EngineSingBox
	default:
		return "", "", false
	}
	if !profileName.MatchString(name) {
		return "", "", false
	}
	return name, engine, true
}

func (profiles ProfileStore) Get(profile ActiveProfile) ([]byte, error) {
	relative, err := profiles.profileRelativePath(profile)
	if err != nil {
		return nil, err
	}
	return profiles.Store.Read(relative)
}

func (profiles ProfileStore) Create(ctx context.Context, profile ActiveProfile, content []byte) error {
	return profiles.write(ctx, profile, content, false)
}

func (profiles ProfileStore) Update(ctx context.Context, profile ActiveProfile, content []byte) error {
	return profiles.write(ctx, profile, content, true)
}

func (profiles ProfileStore) write(ctx context.Context, profile ActiveProfile, content []byte, overwrite bool) error {
	if profile.Engine == "" {
		profile.Engine = EngineMihomo
	}
	relative, err := profiles.profileRelativePath(profile)
	if err != nil {
		return err
	}
	if len(content) == 0 || len(content) > maxProfileSize {
		return fmt.Errorf("state: invalid profile size %d", len(content))
	}
	return profiles.Store.WithLock(ctx, "profiles", func() error {
		_, statErr := os.Lstat(filepath.Join(profiles.Layout.Root, relative))
		exists := statErr == nil
		if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
			return statErr
		}
		if !overwrite && exists {
			return fs.ErrExist
		}
		if overwrite && !exists {
			return fs.ErrNotExist
		}
		return profiles.Store.Write(relative, content, 0o600)
	})
}

func (profiles ProfileStore) Delete(ctx context.Context, profile ActiveProfile) error {
	if profile.Engine == "" {
		profile.Engine = EngineMihomo
	}
	relative, err := profiles.profileRelativePath(profile)
	if err != nil {
		return err
	}
	return profiles.Store.WithLock(ctx, "profiles", func() error {
		active, err := profiles.currentUnlocked()
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err == nil && active == profile {
			return errors.New("state: cannot delete active profile")
		}
		path := filepath.Join(profiles.Layout.Root, relative)
		if err := profiles.Store.checkParents(path); err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("state: refusing to delete non-regular profile")
		}
		return os.Remove(path)
	})
}

func (profiles ProfileStore) Current() (ActiveProfile, error) {
	return profiles.currentUnlocked()
}

func (profiles ProfileStore) currentUnlocked() (ActiveProfile, error) {
	relative, err := filepath.Rel(profiles.Layout.Root, profiles.Layout.ActiveProfile)
	if err != nil {
		return ActiveProfile{}, err
	}
	return profiles.Store.LoadActiveProfile(relative)
}

// Activate publishes the validated profile bytes to the active-config
// mirror first and metadata last. A failed metadata write restores the mirror.
func (profiles ProfileStore) Activate(ctx context.Context, profile ActiveProfile) error {
	if profile.Engine == "" {
		profile.Engine = EngineMihomo
	}
	if err := validateActiveProfile(profile); err != nil {
		return err
	}
	return profiles.Store.WithLock(ctx, "profiles", func() error {
		content, err := profiles.Get(profile)
		if err != nil {
			return err
		}
		target := profiles.Layout.MihomoConfig
		if profile.Engine == EngineSingBox {
			target = profiles.Layout.SingBoxConfig
		}
		oldContent, oldMode, existed, err := readRegularOptional(target)
		if err != nil {
			return err
		}
		if err := WriteFileAtomic(target, content, 0o600); err != nil {
			return err
		}
		metadataRelative, err := filepath.Rel(profiles.Layout.Root, profiles.Layout.ActiveProfile)
		if err == nil {
			err = profiles.Store.SaveActiveProfile(metadataRelative, profile)
		}
		if err == nil {
			return nil
		}
		rollbackErr := rollbackMirror(target, oldContent, oldMode, existed)
		return errors.Join(err, rollbackErr)
	})
}

func readRegularOptional(path string) (data []byte, mode fs.FileMode, exists bool, err error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, false, fmt.Errorf("state: active config mirror is not regular: %s", path)
	}
	data, err = os.ReadFile(path)
	return data, info.Mode().Perm(), true, err
}

func rollbackMirror(path string, content []byte, mode fs.FileMode, existed bool) error {
	if existed {
		return WriteFileAtomic(path, content, mode)
	}
	err := os.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (profiles ProfileStore) profileRelativePath(profile ActiveProfile) (string, error) {
	if profile.Engine == "" {
		profile.Engine = EngineMihomo
	}
	if err := validateActiveProfile(profile); err != nil {
		return "", err
	}
	return filepath.Join("configs", ProfileConfigName(profile)), nil
}
