package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plu-nz/mono.passport/internal/vault"
)

func TestMetadataBatchCommitsOnceAndRetries(t *testing.T) {
	for _, name := range []string{"git", "gpg", "pass"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skip(name + " unavailable")
		}
	}
	root := t.TempDir()
	gnupg := filepath.Join(root, "gnupg")
	if err := os.Mkdir(gnupg, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", gnupg)
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(root, "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	store := filepath.Join(root, "store")
	t.Setenv("PASSWORD_STORE_DIR", store)
	runBatchCommand(t, "", "gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", "Passport Batch Test <batch@example.invalid>", "default", "default", "1d")
	keys := runBatchCommand(t, "", "gpg", "--with-colons", "--fingerprint", "--list-secret-keys")
	fingerprint := ""
	for _, line := range strings.Split(keys, "\n") {
		if strings.HasPrefix(line, "fpr:") {
			fingerprint = strings.Split(line, ":")[9]
			break
		}
	}
	if fingerprint == "" {
		t.Fatal("missing fingerprint")
	}
	runBatchCommand(t, "", "pass", "init", fingerprint)
	v, err := vault.Open(store)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := v.CreateLogin("login", "password", "user", "https://example.test", "")
	if err != nil {
		t.Fatal(err)
	}
	runBatchCommand(t, store, "git", "init", "-q", "-b", "main")
	runBatchCommand(t, store, "git", "config", "user.name", "Passport Test")
	runBatchCommand(t, store, "git", "config", "user.email", "batch@example.invalid")
	runBatchCommand(t, store, "git", "add", ".gpg-id", "login.gpg")
	runBatchCommand(t, store, "git", "commit", "-q", "-m", "Initial vault")
	remote := filepath.Join(root, "remote.git")
	runBatchCommand(t, "", "git", "init", "-q", "--bare", "-b", "main", remote)
	runBatchCommand(t, store, "git", "remote", "add", "origin", remote)
	runBatchCommand(t, store, "git", "push", "-q", "-u", "origin", "main")
	if err := markPending(); err != nil {
		t.Fatal(err)
	}
	favorite, err := v.SetFlag("login", "favorite", true, initial.CiphertextHash)
	if err != nil {
		t.Fatal(err)
	}
	if err := markPending(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.SetFlag("login", "archived", true, favorite.CiphertextHash); err != nil {
		t.Fatal(err)
	}
	if count := strings.TrimSpace(runBatchCommand(t, store, "git", "rev-list", "--count", "HEAD")); count != "1" {
		t.Fatalf("metadata edits created %s commits before the batch", count)
	}
	if err := flushPending(); err != nil {
		t.Fatal(err)
	}
	if count := strings.TrimSpace(runBatchCommand(t, store, "git", "rev-list", "--count", "HEAD")); count != "2" {
		t.Fatalf("batch created %s commits; want 2 total", count)
	}
	offline := remote + ".offline"
	if err := os.Rename(remote, offline); err != nil {
		t.Fatal(err)
	}
	if state := syncOnce(); state.State != "offline" {
		t.Fatalf("unavailable remote state = %+v", state)
	}
	if err := os.Rename(offline, remote); err != nil {
		t.Fatal(err)
	}
	if state := syncOnce(); state.State != "synced" {
		t.Fatalf("sync state = %+v", state)
	}
	if remoteHead := strings.TrimSpace(runBatchCommand(t, "", "git", "--git-dir", remote, "rev-parse", "main")); remoteHead != strings.TrimSpace(runBatchCommand(t, store, "git", "rev-parse", "HEAD")) {
		t.Fatal("batch was not saved to the remote")
	}
	current, err := v.Read("login")
	if err != nil {
		t.Fatal(err)
	}
	if err := markPending(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.SetFlag("login", "favorite", false, current.CiphertextHash); err != nil {
		t.Fatal(err)
	}
	runBatchCommand(t, store, "git", "config", "--unset", "user.name")
	runBatchCommand(t, store, "git", "config", "--unset", "user.email")
	if err := flushPending(); err == nil {
		t.Fatal("commit failure was ignored")
	}
	runBatchCommand(t, store, "git", "config", "user.name", "Passport Test")
	runBatchCommand(t, store, "git", "config", "user.email", "batch@example.invalid")
	if err := flushPending(); err != nil {
		t.Fatalf("pending batch did not retry: %v", err)
	}
}

func runBatchCommand(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v %s", name, args, err, out)
	}
	return string(out)
}
