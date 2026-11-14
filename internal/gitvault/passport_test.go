package gitvault

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// twoClones publishes a minimal vault to a bare remote and clones it, as two
// computers sharing one GitHub repository.
func twoClones(t *testing.T) (first, second *GitVault, remote string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	root := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(root, "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	store := filepath.Join(root, "store")
	os.Mkdir(store, 0o700)
	os.WriteFile(filepath.Join(store, ".gpg-id"), []byte("0CBF4CAA80A81A887EBBE33E2ED3004C145B215F\n"), 0o600)
	remote = filepath.Join(root, "remote.git")
	run(t, "", "git", "init", "-q", "--bare", "-b", "main", remote)
	if _, err := Initialize(store); err != nil {
		t.Fatal(err)
	}
	first, err := Open(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.ConfigurePassport("/opt/Pass age/passport", "Octo", "42+octo@users.noreply.github.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.SetRemote(remote); err != nil {
		t.Fatal(err)
	}
	if _, err := first.PublishNewVault(); err != nil {
		t.Fatal(err)
	}
	peer := filepath.Join(root, "peer")
	run(t, "", "git", "clone", "-q", "--single-branch", "--branch", "main", remote, peer)
	second, err = Open(peer)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.ConfigurePassport("/opt/passport", "Octo", "42+octo@users.noreply.github.com"); err != nil {
		t.Fatal(err)
	}
	return first, second, remote
}

func commitFile(t *testing.T, g *GitVault, name, content string) {
	t.Helper()
	os.WriteFile(filepath.Join(g.Root(), name), []byte(content), 0o600)
	run(t, g.Root(), "git", "add", name)
	run(t, g.Root(), "git", "commit", "-q", "-m", "change "+name)
}

func TestConfigurePassportHelper(t *testing.T) {
	first, _, _ := twoClones(t)
	helpers := run(t, first.Root(), "git", "config", "--local", "--get-all", "credential.https://github.com.helper")
	if helpers != "\n!'/opt/Pass age/passport' git-credential\n" {
		t.Fatalf("helpers = %q; want a reset followed by the quoted Passport helper", helpers)
	}
	if got, ok := first.UsesPassportHelper(); !ok || got != "!'/opt/Pass age/passport' git-credential" {
		t.Fatalf("UsesPassportHelper() = %q, %v", got, ok)
	}
	if email := strings.TrimSpace(run(t, first.Root(), "git", "config", "--local", "user.email")); email != "42+octo@users.noreply.github.com" {
		t.Fatalf("user.email = %q", email)
	}
	// Reconfiguring (a new install path) replaces the helper instead of adding one.
	first.ConfigurePassport("/usr/bin/passport", "Octo", "42+octo@users.noreply.github.com")
	if helpers := run(t, first.Root(), "git", "config", "--local", "--get-all", "credential.https://github.com.helper"); helpers != "\n!'/usr/bin/passport' git-credential\n" {
		t.Fatalf("after reconfigure helpers = %q", helpers)
	}
	if HelperCommand("/a'b") != `!'/a'\''b' git-credential` {
		t.Fatalf("HelperCommand quoting = %q", HelperCommand("/a'b"))
	}
	if err := first.ConfigurePassport("/x\n", "a", "b"); err == nil {
		t.Fatal("newline accepted in Git configuration")
	}
}

func TestRecoveryBranchKeepsOneCommitOutsideMain(t *testing.T) {
	first, second, remote := twoClones(t)
	if _, err := second.FetchRecovery(); !errors.Is(err, ErrNoRecovery) {
		t.Fatalf("FetchRecovery() before publish = %v; want ErrNoRecovery", err)
	}
	if err := first.PublishRecovery([]byte(`{"v":1,"old":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := first.PublishRecovery([]byte(`{"v":1,"new":true}`)); err != nil {
		t.Fatal(err)
	}
	got, err := second.FetchRecovery()
	if err != nil || !bytes.Equal(got, []byte(`{"v":1,"new":true}`)) {
		t.Fatalf("FetchRecovery() = %q, %v", got, err)
	}
	if count := strings.TrimSpace(run(t, "", "git", "--git-dir", remote, "rev-list", "--count", RecoveryBranch)); count != "1" {
		t.Fatalf("recovery branch has %s commits; want 1", count)
	}
	if files := strings.TrimSpace(run(t, "", "git", "--git-dir", remote, "ls-tree", "--name-only", "main")); files != ".gpg-id" {
		t.Fatalf("main holds %q; the recovery copy must stay off main", files)
	}
	if status, _ := first.Status(); status.Dirty {
		t.Fatal("publishing the recovery copy changed the working tree")
	}
	if err := first.PublishRecovery(nil); err == nil {
		t.Fatal("empty recovery copy accepted")
	}
}

func TestSync(t *testing.T) {
	first, second, _ := twoClones(t)
	// Nothing to do.
	if s, err := first.Sync(); err != nil || s.Ahead != 0 || s.Behind != 0 {
		t.Fatalf("idle Sync() = %+v, %v", s, err)
	}
	// Only this computer moved: push.
	commitFile(t, first, "a.gpg", "one")
	if s, err := first.Sync(); err != nil || s.Ahead != 0 {
		t.Fatalf("Sync() after local commit = %+v, %v", s, err)
	}
	// Only the remote moved: fast-forward.
	if s, err := second.Sync(); err != nil || s.Behind != 0 {
		t.Fatalf("Sync() on the other computer = %+v, %v", s, err)
	}
	if _, err := os.Stat(filepath.Join(second.Root(), "a.gpg")); err != nil {
		t.Fatal("fast-forward did not bring the new entry")
	}
	// Both moved: refuse and report.
	commitFile(t, first, "b.gpg", "two")
	commitFile(t, second, "c.gpg", "three")
	if _, err := first.Sync(); err != nil {
		t.Fatal(err)
	}
	s, err := second.Sync()
	if !errors.Is(err, ErrDiverged) || s.Ahead != 1 || s.Behind != 1 {
		t.Fatalf("diverged Sync() = %+v, %v", s, err)
	}
}
