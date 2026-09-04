// Package rulelist manages user-owned local rule lists with optimistic locking.
package rulelist

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

const maxListBytes = 4 << 20

var (
	validName   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	ErrNotFound = errors.New("rule list not found")
	ErrConflict = errors.New("rule list revision conflict")
)

// Item is safe to expose through the authenticated API.
type Item struct {
	Name     string `json:"name"`
	Content  string `json:"content,omitempty"`
	Revision string `json:"revision"`
	Size     int64  `json:"size"`
}

// Store manages .txt lists in a single directory without following symlinks.
type Store struct {
	Directory string
	mu        sync.RWMutex
}

// List returns metadata in lexical order.
func (s *Store) List() ([]Item, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	directory, err := s.directory()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return []Item{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list local rules: %w", err)
	}
	items := make([]Item, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(entry.Name()) != ".txt" {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".txt")
		if !validName.MatchString(name) {
			continue
		}
		item, err := s.get(name)
		if err != nil {
			return nil, err
		}
		item.Content = ""
		items = append(items, item)
	}
	sort.Slice(items, func(left, right int) bool { return items[left].Name < items[right].Name })
	return items, nil
}

// Get reads one list and computes its revision.
func (s *Store) Get(name string) (Item, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.get(name)
}

func (s *Store) get(name string) (Item, error) {
	pathOnDisk, normalized, err := s.path(name)
	if err != nil {
		return Item{}, err
	}
	info, err := os.Lstat(pathOnDisk)
	if errors.Is(err, os.ErrNotExist) {
		return Item{}, ErrNotFound
	}
	if err != nil {
		return Item{}, fmt.Errorf("inspect local rule list: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return Item{}, errors.New("local rule list is not a regular file")
	}
	if info.Size() > maxListBytes {
		return Item{}, errors.New("local rule list exceeds size limit")
	}
	content, err := os.ReadFile(pathOnDisk)
	if err != nil {
		return Item{}, fmt.Errorf("read local rule list: %w", err)
	}
	if !utf8.Valid(content) || strings.IndexByte(string(content), 0) >= 0 {
		return Item{}, errors.New("local rule list is not valid text")
	}
	return Item{Name: normalized, Content: string(content), Revision: revision(content), Size: int64(len(content))}, nil
}

// Put creates or updates a list. If ifMatch is non-empty, it must match the
// current revision. Use "*" to require that a list already exists.
func (s *Store) Put(name, content, ifMatch string) (Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putLocked(name, content, ifMatch, false)
}

// Create writes a new list and returns ErrConflict if it already exists. This
// prevents an API create from racing a preflight read and replacing data.
func (s *Store) Create(name, content string) (Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putLocked(name, content, "", true)
}

func (s *Store) putLocked(name, content, ifMatch string, createOnly bool) (Item, error) {
	pathOnDisk, normalized, err := s.path(name)
	if err != nil {
		return Item{}, err
	}
	content = normalizeContent(content)
	if len(content) > maxListBytes || !utf8.ValidString(content) || strings.IndexByte(content, 0) >= 0 {
		return Item{}, errors.New("local rule list is invalid or exceeds size limit")
	}
	current, currentErr := s.get(normalized)
	if currentErr != nil && !errors.Is(currentErr, ErrNotFound) {
		return Item{}, currentErr
	}
	if createOnly && currentErr == nil {
		return Item{}, ErrConflict
	}
	if ifMatch != "" {
		if errors.Is(currentErr, ErrNotFound) || (ifMatch != "*" && current.Revision != ifMatch) {
			return Item{}, ErrConflict
		}
	}
	directory := filepath.Dir(pathOnDisk)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return Item{}, fmt.Errorf("create local rule directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".rule-list-*")
	if err != nil {
		return Item{}, fmt.Errorf("create local rule list: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return Item{}, fmt.Errorf("protect local rule list: %w", err)
	}
	if _, err := temporary.WriteString(content); err != nil {
		return Item{}, fmt.Errorf("write local rule list: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return Item{}, fmt.Errorf("sync local rule list: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return Item{}, fmt.Errorf("close local rule list: %w", err)
	}
	if err := os.Rename(temporaryPath, pathOnDisk); err != nil {
		return Item{}, fmt.Errorf("publish local rule list: %w", err)
	}
	committed = true
	if err := syncDirectory(directory); err != nil {
		return Item{}, fmt.Errorf("sync local rule directory: %w", err)
	}
	return Item{Name: normalized, Content: content, Revision: revision([]byte(content)), Size: int64(len(content))}, nil
}

// Delete removes a list only when its revision still matches.
func (s *Store) Delete(name, ifMatch string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pathOnDisk, normalized, err := s.path(name)
	if err != nil {
		return err
	}
	current, err := s.get(normalized)
	if err != nil {
		return err
	}
	if ifMatch == "" || (ifMatch != "*" && current.Revision != ifMatch) {
		return ErrConflict
	}
	if err := os.Remove(pathOnDisk); err != nil {
		return fmt.Errorf("delete local rule list: %w", err)
	}
	return syncDirectory(filepath.Dir(pathOnDisk))
}

func (s *Store) path(name string) (string, string, error) {
	directory, err := s.directory()
	if err != nil {
		return "", "", err
	}
	normalized := strings.ToLower(strings.TrimSpace(name))
	if !validName.MatchString(normalized) {
		return "", "", fmt.Errorf("invalid rule list name %q", name)
	}
	return filepath.Join(directory, normalized+".txt"), normalized, nil
}

func (s *Store) directory() (string, error) {
	directory, err := filepath.Abs(s.Directory)
	if err != nil || directory == string(filepath.Separator) || directory == "." {
		return "", errors.New("invalid local rule directory")
	}
	if info, err := os.Lstat(directory); err == nil && info.Mode()&fs.ModeSymlink != 0 {
		return "", errors.New("local rule directory must not be a symbolic link")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect local rule directory: %w", err)
	}
	return directory, nil
}

func normalizeContent(content string) string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	content = strings.TrimRight(content, " \t\n")
	if content == "" {
		return ""
	}
	return content + "\n"
}

func revision(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
