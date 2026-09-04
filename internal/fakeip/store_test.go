package fakeip

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestReadMissingReturnsEmptyDocumentWithoutCreatingDirectory(t *testing.T) {
	t.Parallel()
	directory := filepath.Join(t.TempDir(), "local-rules")
	store := Store{Directory: directory}

	document, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if document.Content != "" || document.ManualContent != "" || document.Count != 0 {
		t.Fatalf("unexpected empty document: %#v", document)
	}
	if document.Revision != revision(nil) {
		t.Fatalf("revision = %q, want empty-content revision", document.Revision)
	}
	if document.Manual == nil || document.Generated == nil || document.Effective == nil {
		t.Fatalf("empty prefix collections must be non-nil: %#v", document)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Read created its directory: %v", err)
	}
}

func TestReplaceGeneratedCanonicalizesSortsAndDoesNotCollapseSubnets(t *testing.T) {
	t.Parallel()
	store := Store{Directory: filepath.Join(t.TempDir(), "local-rules")}
	empty, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	manual, err := store.SaveManual("# manual\r\n192.0.2.42\r\n10.1.2.3/8\r\n", empty.Revision)
	if err != nil {
		t.Fatal(err)
	}
	generatedAt := time.Date(2026, time.August, 25, 19, 46, 20, 0, time.FixedZone("offset", 3*60*60))
	document, err := store.ReplaceGenerated([]netip.Prefix{
		mustPrefix(t, "192.0.2.99/24"),
		mustPrefix(t, "10.1.9.9/16"),
		mustPrefix(t, "10.1.0.0/16"),
		mustPrefix(t, "10.9.8.7/8"),
		mustPrefix(t, "2.4.5.6/8"),
	}, manual.Revision, generatedAt)
	if err != nil {
		t.Fatal(err)
	}

	wantGenerated := []string{"10.0.0.0/8", "10.1.0.0/16", "192.0.2.0/24", "2.0.0.0/8"}
	if got := prefixStrings(document.Generated); !reflect.DeepEqual(got, wantGenerated) {
		t.Fatalf("generated = %v, want %v", got, wantGenerated)
	}
	wantEffective := []string{"10.0.0.0/8", "10.1.0.0/16", "192.0.2.0/24", "192.0.2.42/32", "2.0.0.0/8"}
	if got := prefixStrings(document.Effective); !reflect.DeepEqual(got, wantEffective) {
		t.Fatalf("effective = %v, want %v", got, wantEffective)
	}
	if document.ManualCount != 2 || document.GeneratedCount != 4 || document.EffectiveCount != 5 || document.Count != 5 {
		t.Fatalf("unexpected counts: %#v", document)
	}
	if !document.GeneratedAt.Equal(generatedAt) || document.GeneratedAt.Location() != time.UTC {
		t.Fatalf("generatedAt = %v", document.GeneratedAt)
	}
	wantPrefix := AutoBeginMarker + "\n" +
		"# Generated: 2026-08-25T16:46:20Z\n" +
		"10.0.0.0/8\n10.1.0.0/16\n192.0.2.0/24\n2.0.0.0/8\n" +
		AutoEndMarker + "\n"
	if !strings.HasPrefix(document.Content, wantPrefix) {
		t.Fatalf("content = %q, want prefix %q", document.Content, wantPrefix)
	}
	if document.ManualContent != "# manual\n192.0.2.42\n10.1.2.3/8\n" {
		t.Fatalf("manual content = %q", document.ManualContent)
	}
	if document.Revision == manual.Revision {
		t.Fatal("revision did not change")
	}

	pathOnDisk := filepath.Join(store.Directory, FileName)
	info, err := os.Stat(pathOnDisk)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
	partials, err := filepath.Glob(filepath.Join(store.Directory, ".fakeip-whitelist-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(partials) != 0 {
		t.Fatalf("temporary files left behind: %v", partials)
	}
}

func TestReplaceGeneratedWithScopePersistsProvenance(t *testing.T) {
	t.Parallel()
	store := Store{Directory: filepath.Join(t.TempDir(), "local-rules")}
	empty, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if empty.HasGenerated || empty.GeneratedScope != "" {
		t.Fatalf("empty document provenance = hasGenerated %t scope %q", empty.HasGenerated, empty.GeneratedScope)
	}
	generatedAt := time.Date(2026, time.August, 26, 7, 0, 0, 0, time.UTC)
	document, err := store.ReplaceGeneratedWithScope(
		[]netip.Prefix{mustPrefix(t, "192.0.2.0/24")},
		empty.Revision,
		generatedAt,
		AutoScopeLocalOnly,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !document.HasGenerated || document.GeneratedScope != AutoScopeLocalOnly {
		t.Fatalf("document provenance = hasGenerated %t scope %q", document.HasGenerated, document.GeneratedScope)
	}
	if !strings.Contains(document.Content, AutoScopeMarker+AutoScopeLocalOnly+"\n") {
		t.Fatalf("AUTO block does not contain source scope: %q", document.Content)
	}

	saved, err := store.SaveManual("# manual\n203.0.113.9\n", document.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !saved.HasGenerated || saved.GeneratedScope != AutoScopeLocalOnly {
		t.Fatalf("SaveManual lost provenance = hasGenerated %t scope %q", saved.HasGenerated, saved.GeneratedScope)
	}
	if _, err := store.ReplaceGeneratedWithScope(nil, saved.Revision, generatedAt, "invalid\nscope"); err == nil {
		t.Fatal("invalid AUTO source scope was accepted")
	}
	unchanged, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Revision != saved.Revision || unchanged.Content != saved.Content {
		t.Fatal("invalid scope changed the document")
	}
}

func TestReplaceGeneratedPreservesManualTextBeforeAndAfterBlock(t *testing.T) {
	t.Parallel()
	store := Store{Directory: filepath.Join(t.TempDir(), "local-rules")}
	if err := os.MkdirAll(store.Directory, 0o700); err != nil {
		t.Fatal(err)
	}
	before := "# before\r\n203.0.113.9\r\n"
	oldBlock := AutoBeginMarker + "\r\n# Generated: 2025-01-02T03:04:05Z\r\n10.0.0.0/8\r\n" + AutoEndMarker + "\r\n"
	after := "# after\r\n198.51.100.7/32\r\n"
	pathOnDisk := filepath.Join(store.Directory, FileName)
	if err := os.WriteFile(pathOnDisk, []byte(before+oldBlock+after), 0o600); err != nil {
		t.Fatal(err)
	}

	current, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	document, err := store.ReplaceGenerated(
		[]netip.Prefix{mustPrefix(t, "172.16.4.5/12")},
		current.Revision,
		time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(document.Content, before) || !strings.HasSuffix(document.Content, after) {
		t.Fatalf("manual framing changed: %q", document.Content)
	}
	if document.ManualContent != before+after {
		t.Fatalf("manual content = %q, want %q", document.ManualContent, before+after)
	}
	if strings.Count(document.Content, AutoBeginMarker) != 1 || strings.Count(document.Content, AutoEndMarker) != 1 {
		t.Fatalf("unexpected AUTO markers: %q", document.Content)
	}
	if got := prefixStrings(document.Generated); !reflect.DeepEqual(got, []string{"172.16.0.0/12"}) {
		t.Fatalf("generated = %v", got)
	}
}

func TestSaveManualValidatesAndPreservesGeneratedBlock(t *testing.T) {
	t.Parallel()
	store := Store{Directory: filepath.Join(t.TempDir(), "local-rules")}
	empty, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	generated, err := store.ReplaceGenerated(
		[]netip.Prefix{mustPrefix(t, "100.64.9.8/10")},
		empty.Revision,
		time.Date(2026, time.February, 3, 4, 5, 6, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	sections, err := splitSections(generated.Content)
	if err != nil {
		t.Fatal(err)
	}
	originalBlock := sections.generatedBlock

	document, err := store.SaveManual("# manually maintained\r\n203.0.113.7\r\n\r\n", generated.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(document.Content, originalBlock) {
		t.Fatalf("generated block changed: %q", document.Content)
	}
	if document.ManualContent != "# manually maintained\n203.0.113.7\n\n" {
		t.Fatalf("manual content = %q", document.ManualContent)
	}
	if got := prefixStrings(document.Generated); !reflect.DeepEqual(got, []string{"100.64.0.0/10"}) {
		t.Fatalf("generated = %v", got)
	}
	if got := prefixStrings(document.Manual); !reflect.DeepEqual(got, []string{"203.0.113.7/32"}) {
		t.Fatalf("manual = %v", got)
	}

	for name, invalid := range map[string]string{
		"domain":       "example.com\n",
		"ipv6 address": "2001:db8::1\n",
		"ipv6 cidr":    "2001:db8::/32\n",
		"inline note":  "192.0.2.1 # comment\n",
		"bad mask":     "192.0.2.1/33\n",
		"begin marker": AutoBeginMarker + "\n",
		"end marker":   AutoEndMarker + "\n",
		"NUL":          "192.0.2.1\x00\n",
		"UTF-8":        string([]byte{0xff, '\n'}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.SaveManual(invalid, document.Revision); !errors.Is(err, ErrInvalidManual) {
				t.Fatalf("SaveManual error = %v, want ErrInvalidManual", err)
			}
			unchanged, readErr := store.Read()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if unchanged.Revision != document.Revision || unchanged.Content != document.Content {
				t.Fatal("invalid manual write changed the document")
			}
		})
	}
}

func TestMutationsRequireCurrentRevision(t *testing.T) {
	t.Parallel()
	store := Store{Directory: filepath.Join(t.TempDir(), "local-rules")}
	current, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveManual("192.0.2.1\n", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("empty SaveManual revision = %v", err)
	}
	if _, err := store.ReplaceGenerated(nil, "stale", time.Now()); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale ReplaceGenerated revision = %v", err)
	}
	saved, err := store.SaveManual("192.0.2.1\n", current.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveManual("192.0.2.2\n", current.Revision); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale SaveManual revision = %v", err)
	}

	pathOnDisk := filepath.Join(store.Directory, FileName)
	if err := os.WriteFile(pathOnDisk, []byte("198.51.100.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReplaceGenerated(nil, saved.Revision, time.Now()); !errors.Is(err, ErrConflict) {
		t.Fatalf("externally stale ReplaceGenerated revision = %v", err)
	}
}

func TestReadRejectsMalformedMarkersWithoutClobbering(t *testing.T) {
	t.Parallel()
	fixtures := map[string]string{
		"begin only":   AutoBeginMarker + "\n192.0.2.0/24\n",
		"end only":     AutoEndMarker + "\n",
		"end first":    AutoEndMarker + "\n" + AutoBeginMarker + "\n",
		"second begin": AutoBeginMarker + "\n" + AutoBeginMarker + "\n" + AutoEndMarker + "\n",
		"second end":   AutoBeginMarker + "\n" + AutoEndMarker + "\n" + AutoEndMarker + "\n",
		"second block": AutoBeginMarker + "\n" + AutoEndMarker + "\n" + AutoBeginMarker + "\n" + AutoEndMarker + "\n",
	}
	for name, content := range fixtures {
		name, content := name, content
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := Store{Directory: filepath.Join(t.TempDir(), "local-rules")}
			if err := os.MkdirAll(store.Directory, 0o700); err != nil {
				t.Fatal(err)
			}
			pathOnDisk := filepath.Join(store.Directory, FileName)
			if err := os.WriteFile(pathOnDisk, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Read(); !errors.Is(err, ErrMalformedMarkers) {
				t.Fatalf("Read error = %v, want ErrMalformedMarkers", err)
			}
			got, err := os.ReadFile(pathOnDisk)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != content {
				t.Fatal("malformed document was modified")
			}
		})
	}
}

func TestReadPreservesButIgnoresUnknownLegacyLines(t *testing.T) {
	t.Parallel()
	store := Store{Directory: filepath.Join(t.TempDir(), "local-rules")}
	if err := os.MkdirAll(store.Directory, 0o700); err != nil {
		t.Fatal(err)
	}
	content := "# kept\nexample.com\n2001:db8::/32\n192.0.2.9\n"
	if err := os.WriteFile(filepath.Join(store.Directory, FileName), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	document, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if document.Content != content || document.ManualContent != content {
		t.Fatalf("legacy content was not preserved: %#v", document)
	}
	if got := prefixStrings(document.Effective); !reflect.DeepEqual(got, []string{"192.0.2.9/32"}) {
		t.Fatalf("effective = %v", got)
	}
}

func TestSizeAndEntryLimits(t *testing.T) {
	t.Parallel()
	store := Store{Directory: filepath.Join(t.TempDir(), "local-rules")}
	current, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	tooMany := make([]netip.Prefix, MaxEntries+1)
	for index := range tooMany {
		tooMany[index] = mustPrefix(t, "192.0.2.0/24")
	}
	if _, err := store.ReplaceGenerated(tooMany, current.Revision, time.Now()); !errors.Is(err, ErrTooManyEntries) {
		t.Fatalf("ReplaceGenerated error = %v, want ErrTooManyEntries", err)
	}
	manualTooMany := strings.Repeat("192.0.2.1\n", MaxEntries+1)
	if _, err := store.SaveManual(manualTooMany, current.Revision); !errors.Is(err, ErrTooManyEntries) {
		t.Fatalf("SaveManual error = %v, want ErrTooManyEntries", err)
	}
	if _, err := store.SaveManual(strings.Repeat("#", MaxDocumentBytes+1), current.Revision); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("large SaveManual error = %v, want ErrTooLarge", err)
	}

	if err := os.MkdirAll(store.Directory, 0o700); err != nil {
		t.Fatal(err)
	}
	pathOnDisk := filepath.Join(store.Directory, FileName)
	file, err := os.OpenFile(pathOnDisk, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(MaxDocumentBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("large Read error = %v, want ErrTooLarge", err)
	}
}

func TestRejectsSymlinkAndNonRegularPaths(t *testing.T) {
	t.Parallel()
	t.Run("symlink file", func(t *testing.T) {
		root := t.TempDir()
		store := Store{Directory: filepath.Join(root, "local-rules")}
		if err := os.MkdirAll(store.Directory, 0o700); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(root, "outside")
		if err := os.WriteFile(outside, []byte("192.0.2.1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(store.Directory, FileName)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Read(); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("Read error = %v, want ErrUnsafePath", err)
		}
	})
	t.Run("symlink directory", func(t *testing.T) {
		root := t.TempDir()
		realDirectory := filepath.Join(root, "real")
		if err := os.Mkdir(realDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		linkedDirectory := filepath.Join(root, "linked")
		if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
			t.Fatal(err)
		}
		store := Store{Directory: linkedDirectory}
		if _, err := store.Read(); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("Read error = %v, want ErrUnsafePath", err)
		}
	})
	t.Run("directory as target", func(t *testing.T) {
		store := Store{Directory: filepath.Join(t.TempDir(), "local-rules")}
		if err := os.MkdirAll(filepath.Join(store.Directory, FileName), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Read(); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("Read error = %v, want ErrUnsafePath", err)
		}
	})
	t.Run("regular file as directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "not-a-directory")
		if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
		store := Store{Directory: path}
		if _, err := store.Read(); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("Read error = %v, want ErrUnsafePath", err)
		}
	})
}

func TestSaveReplacesPermissiveFileWithMode0600(t *testing.T) {
	t.Parallel()
	store := Store{Directory: filepath.Join(t.TempDir(), "local-rules")}
	if err := os.MkdirAll(store.Directory, 0o700); err != nil {
		t.Fatal(err)
	}
	pathOnDisk := filepath.Join(store.Directory, FileName)
	if err := os.WriteFile(pathOnDisk, []byte("192.0.2.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveManual("198.51.100.1\n", current.Revision); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(pathOnDisk)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
}

func mustPrefix(t *testing.T, value string) netip.Prefix {
	t.Helper()
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		t.Fatal(err)
	}
	return prefix
}

func prefixStrings(prefixes []netip.Prefix) []string {
	result := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		result[index] = prefix.String()
	}
	return result
}
