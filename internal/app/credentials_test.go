package app

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

func TestCredentialStorePasswordAndSessionState(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "clash")
	store, err := NewCredentialStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetPassword("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	credential, err := store.Credential(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ok, err := web.VerifyPBKDF2Record(credential.PasswordRecord, "correct horse battery staple")
	if err != nil || !ok {
		t.Fatalf("password verification failed: ok=%v err=%v", ok, err)
	}
	secrets := web.SessionSecretSet{Current: web.SessionSecret{ID: "current", Key: bytes.Repeat([]byte{1}, 32)}}
	if err := store.SaveSessionSecrets(context.Background(), secrets); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadSessionSecrets(context.Background())
	if err != nil || loaded.Current.ID != "current" || len(loaded.Current.Key) != 32 {
		t.Fatalf("unexpected loaded secrets %#v, %v", loaded, err)
	}
	info, err := fs.Stat(osDirFS(t, root), ".boxctl/session-secrets.v1.json")
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected session state mode %v, %v", info, err)
	}
}

func TestReadAndSetPasswordRequiresConfirmation(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "clash")
	store, err := NewCredentialStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReadAndSetPassword(bytes.NewBufferString("first password\nother password\n"), &bytes.Buffer{}); err == nil {
		t.Fatal("mismatched confirmation was accepted")
	}
	if _, err := state.NewStore(root); err != nil {
		t.Fatal(err)
	}
}

func TestSetPasswordRevokesPersistedSessionState(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "clash")
	store, err := NewCredentialStore(root)
	if err != nil {
		t.Fatal(err)
	}
	secrets := web.SessionSecretSet{Current: web.SessionSecret{ID: "current", Key: bytes.Repeat([]byte{1}, 32)}}
	if err := store.SaveSessionSecrets(context.Background(), secrets); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPassword("replacement password"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, sessionStatePath)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("persisted session state still exists: %v", err)
	}
	loaded, err := store.LoadSessionSecrets(context.Background())
	if err != nil || loaded.Current.ID != "" || len(loaded.Current.Key) != 0 || len(loaded.Previous) != 0 {
		t.Fatalf("loaded revoked session state = %#v, %v", loaded, err)
	}
	credential, err := store.Credential(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	valid, err := web.VerifyPBKDF2Record(credential.PasswordRecord, "replacement password")
	if err != nil || !valid {
		t.Fatalf("replacement password verification failed: valid=%v err=%v", valid, err)
	}
}

func TestInitializeAdminIsOneTimeAndRaceSafe(t *testing.T) {
	root := filepath.Join(t.TempDir(), "clash")
	store, err := NewCredentialStore(root)
	if err != nil {
		t.Fatal(err)
	}
	status, err := store.AdminSetupStatus(context.Background())
	if err != nil || !status.Required {
		t.Fatalf("initial setup status = %+v, %v", status, err)
	}

	passwords := []string{"first secure password", "second secure password"}
	results := make(chan error, len(passwords))
	var ready sync.WaitGroup
	ready.Add(len(passwords))
	start := make(chan struct{})
	for _, password := range passwords {
		password := password
		go func() {
			ready.Done()
			<-start
			results <- store.InitializeAdmin(context.Background(), password)
		}()
	}
	ready.Wait()
	close(start)
	successes := 0
	conflicts := 0
	for range passwords {
		result := <-results
		if result == nil {
			successes++
			continue
		}
		var public *web.PublicError
		if errors.As(result, &public) && public.Status == 409 && public.Code == "setup_complete" {
			conflicts++
			continue
		}
		t.Fatalf("unexpected setup error: %v", result)
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("setup race results: successes=%d conflicts=%d", successes, conflicts)
	}
	status, err = store.AdminSetupStatus(context.Background())
	if err != nil || status.Required {
		t.Fatalf("completed setup status = %+v, %v", status, err)
	}
	credential, err := store.Credential(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	validWinner := false
	for _, password := range passwords {
		valid, verifyErr := web.VerifyPBKDF2Record(credential.PasswordRecord, password)
		if verifyErr != nil {
			t.Fatal(verifyErr)
		}
		validWinner = validWinner || valid
	}
	if !validWinner {
		t.Fatal("neither submitted password was published")
	}
}

func TestInitializeAdminRejectsInvalidPasswordWithoutClaimingSetup(t *testing.T) {
	store, err := NewCredentialStore(filepath.Join(t.TempDir(), "clash"))
	if err != nil {
		t.Fatal(err)
	}
	err = store.InitializeAdmin(context.Background(), "short")
	var public *web.PublicError
	if !errors.As(err, &public) || public.Status != 400 || public.Code != "invalid_password" {
		t.Fatalf("invalid password error = %v", err)
	}
	status, statusErr := store.AdminSetupStatus(context.Background())
	if statusErr != nil || !status.Required {
		t.Fatalf("status after rejected setup = %+v, %v", status, statusErr)
	}
}

func TestInitializeAdminChecksCompletedSetupBeforePasswordWork(t *testing.T) {
	store, err := NewCredentialStore(filepath.Join(t.TempDir(), "clash"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.InitializeAdmin(context.Background(), "first secure password"); err != nil {
		t.Fatal(err)
	}

	// An invalid candidate would be rejected by createPasswordRecord. Once the
	// password exists, setup must short-circuit at the persisted one-time check
	// and never reach hashing/validation of attacker-controlled input.
	err = store.InitializeAdmin(context.Background(), "short")
	var public *web.PublicError
	if !errors.As(err, &public) || public.Status != 409 || public.Code != "setup_complete" {
		t.Fatalf("completed setup error = %v", err)
	}
}

func TestReadAndSetPasswordReportsInMemoryRestartBoundary(t *testing.T) {
	t.Parallel()
	store, err := NewCredentialStore(filepath.Join(t.TempDir(), "clash"))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := store.ReadAndSetPassword(bytes.NewBufferString("replacement password\nreplacement password\n"), &output); err != nil {
		t.Fatal(err)
	}
	if message := output.String(); !strings.Contains(message, "persisted sessions were revoked") || !strings.Contains(message, "Restart the management service") {
		t.Fatalf("password update message = %q", message)
	}
}

func osDirFS(t *testing.T, root string) fs.FS {
	t.Helper()
	return os.DirFS(root)
}
