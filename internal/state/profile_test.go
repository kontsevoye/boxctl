package state

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestActiveProfileLegacyDefaultsToMihomo(t *testing.T) {
	t.Parallel()
	profile, err := ParseActiveProfile([]byte("default\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := ActiveProfile{Name: "default", Engine: EngineMihomo}
	if profile != want {
		t.Fatalf("profile = %+v", profile)
	}
	profile, err = ParseActiveProfile([]byte(`{"name":"mobile"}`))
	if err != nil || profile != (ActiveProfile{Name: "mobile", Engine: EngineMihomo}) {
		t.Fatalf("JSON legacy profile = %+v, %v", profile, err)
	}
}

func TestActiveProfileStrictJSON(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		`{"name":"default","engine":"unknown"}`,
		`{"name":"../escape","engine":"mihomo"}`,
		`{"name":"default","extra":true}`,
		`{"name":"default"} trailing`,
	} {
		if _, err := ParseActiveProfile([]byte(input)); err == nil {
			t.Errorf("ParseActiveProfile(%s) succeeded", input)
		}
	}
}

func TestProfileStoreCRUDAndActivation(t *testing.T) {
	t.Parallel()
	profiles, err := NewProfileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	mihomo := ActiveProfile{Name: "default"}
	singBox := ActiveProfile{Name: "travel", Engine: EngineSingBox}
	if err := profiles.Create(ctx, mihomo, []byte("mixed-port: 7890\n")); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Create(ctx, singBox, []byte("{\"log\":{}}\n")); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Create(ctx, mihomo, []byte("duplicate")); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("duplicate create error = %v", err)
	}
	entries, err := profiles.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name != "default" || entries[1].Name != "travel" {
		t.Fatalf("entries = %+v", entries)
	}
	if err := profiles.Activate(ctx, mihomo); err != nil {
		t.Fatal(err)
	}
	active, err := profiles.Current()
	if err != nil || active != (ActiveProfile{Name: "default", Engine: EngineMihomo}) {
		t.Fatalf("active = %+v, %v", active, err)
	}
	mirror, err := os.ReadFile(profiles.Layout.MihomoConfig)
	if err != nil || string(mirror) != "mixed-port: 7890\n" {
		t.Fatalf("mihomo mirror = %q, %v", mirror, err)
	}
	if err := profiles.Delete(ctx, ActiveProfile{Name: "default"}); err == nil {
		t.Fatal("active profile deletion succeeded")
	}
	if err := profiles.Update(ctx, singBox, []byte("{\"log\":{\"level\":\"warn\"}}\n")); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Activate(ctx, singBox); err != nil {
		t.Fatal(err)
	}
	singMirror, err := os.ReadFile(profiles.Layout.SingBoxConfig)
	if err != nil || string(singMirror) != "{\"log\":{\"level\":\"warn\"}}\n" {
		t.Fatalf("sing-box mirror = %q, %v", singMirror, err)
	}
	if err := profiles.Delete(ctx, ActiveProfile{Name: "default"}); err != nil {
		t.Fatal(err)
	}
	if _, err := profiles.Get(ActiveProfile{Name: "default"}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("deleted Get error = %v", err)
	}
}

func TestProfileActivationRollsBackMirrorWhenMetadataFails(t *testing.T) {
	t.Parallel()
	profiles, err := NewProfileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	profile := ActiveProfile{Name: "default", Engine: EngineMihomo}
	if err := profiles.Create(ctx, profile, []byte("new\n")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(profiles.Layout.MihomoConfig, []byte("old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(profiles.Layout.ActiveProfile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(profiles.Layout.MihomoConfig, profiles.Layout.ActiveProfile); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Activate(ctx, profile); err == nil {
		t.Fatal("activation with unsafe metadata target succeeded")
	}
	data, err := os.ReadFile(profiles.Layout.MihomoConfig)
	if err != nil || string(data) != "old\n" {
		t.Fatalf("mirror was not rolled back: %q, %v", data, err)
	}
	info, err := os.Stat(profiles.Layout.MihomoConfig)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("mirror mode was not rolled back: %v, %v", info, err)
	}
}

func TestProfileListIgnoresUnknownAndSymlinkFiles(t *testing.T) {
	t.Parallel()
	profiles, err := NewProfileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(profiles.Layout.ProfilesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profiles.Layout.ProfilesDir, "legacy.yml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profiles.Layout.ProfilesDir, "valid.yaml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(profiles.Layout.ProfilesDir, "valid.yaml"), filepath.Join(profiles.Layout.ProfilesDir, "linked.yaml")); err != nil {
		t.Fatal(err)
	}
	entries, err := profiles.List()
	if err != nil {
		t.Fatal(err)
	}
	want := []ProfileEntry{{ActiveProfile: ActiveProfile{Name: "valid", Engine: EngineMihomo}, Path: filepath.Join(profiles.Layout.ProfilesDir, "valid.yaml"), Size: 1}}
	if !reflect.DeepEqual(entries, want) {
		t.Fatalf("entries = %#v", entries)
	}
}
