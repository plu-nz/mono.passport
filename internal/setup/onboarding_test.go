package setup

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plu-nz/mono.passport/internal/ghauth"
	"github.com/plu-nz/mono.passport/internal/gitvault"
	"github.com/plu-nz/mono.passport/internal/gpgkey"
)

const cloneURL = "https://github.com/octo/.passport.git"

// computer isolates HOME, XDG config and GnuPG, as one machine.
func computer(t *testing.T, root, name string) {
	t.Helper()
	home := filepath.Join(root, name)
	gnupg := filepath.Join(home, ".gnupg")
	if err := os.MkdirAll(gnupg, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("GNUPGHOME", gnupg)
	os.Unsetenv("PASSWORD_STORE_DIR")
	t.Cleanup(func() {
		cmd := exec.Command("gpgconf", "--kill", "gpg-agent")
		cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupg)
		cmd.Run()
	})
}

// fakeGitHub creates repositories whose clone URL Git rewrites to a local bare repository.
func fakeGitHub(t *testing.T, root string) (*ghauth.Client, *int) {
	t.Helper()
	remote := filepath.Join(root, "remote.git")
	if out, err := exec.Command("git", "init", "-q", "--bare", "-b", "main", remote).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	global := filepath.Join(root, "gitconfig")
	os.WriteFile(global, []byte("[url \""+remote+"\"]\n\tinsteadOf = "+cloneURL+"\n"), 0o600)
	t.Setenv("GIT_CONFIG_GLOBAL", global)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	created := 0
	mux := http.NewServeMux()
	mux.HandleFunc("POST /user/repos", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["name"] != RepoName || body["private"] != true {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		created++
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"name": RepoName, "full_name": "octo/" + RepoName, "clone_url": cloneURL, "private": true})
	})
	mux.HandleFunc("PUT /repos/octo/.passport/topics", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"names": []string{VaultTopic}})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return &ghauth.Client{HTTP: server.Client(), APIBase: server.URL, WebBase: server.URL}, &created
}

func requireTools(t *testing.T) {
	for _, tool := range []string{"git", "gpg", "pass", "gpgconf"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " unavailable")
		}
	}
}

var account = ghauth.Account{Login: "octo", ID: 42, Name: "Octo Cat", Token: "gho_test"}

func TestCreateOnOneComputerRestoreOnAnother(t *testing.T) {
	requireTools(t)
	if testing.Short() {
		t.Skip("runs GnuPG and Argon2id end to end")
	}
	root := t.TempDir()
	client, created := fakeGitHub(t, root)
	password := []byte("correct horse battery staple")
	var steps []string
	progress := func(step string) { steps = append(steps, step) }

	computer(t, root, "first")
	if _, err := CreateWithGitHub(context.Background(), client, account, []byte("short"), "", "/opt/passport", progress); err == nil {
		t.Fatal("a short master password was accepted")
	}
	info, err := CreateWithGitHub(context.Background(), client, account, password, "", "/opt/passport", progress)
	if err != nil {
		t.Fatal(err)
	}
	if *created != 1 || !info.Initialized || info.Path != filepath.Join(root, "first", ".password-store") {
		t.Fatalf("created=%d info=%+v", *created, info)
	}
	if strings.Join(steps, ",") != "key,vault,repository,publish,recovery,unlock" {
		t.Fatalf("steps = %v", steps)
	}
	if pending, _ := OnboardingPending(); pending != "" {
		t.Fatalf("onboarding still pending: %q", pending)
	}
	if on, _ := AutoSync(); !on {
		t.Fatal("auto sync not enabled")
	}
	if repo, _ := GitHubRepo(); repo != "octo/.passport" {
		t.Fatalf("GitHubRepo() = %q", repo)
	}
	fp, err := VaultFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if unlocked, _ := gpgkey.Unlocked(fp); !unlocked {
		t.Fatal("key not unlocked after create")
	}
	email := strings.TrimSpace(run(t, info.Path, "git", "config", "--local", "user.email"))
	if email != "42+octo@users.noreply.github.com" {
		t.Fatalf("user.email = %q", email)
	}
	// An entry written with pass on the first computer, then synced.
	insert := exec.Command("pass", "insert", "-m", "-f", "mail")
	insert.Env = append(os.Environ(), "PASSWORD_STORE_DIR="+info.Path)
	insert.Stdin = strings.NewReader("s3cret\nlogin: octo\n")
	if out, err := insert.CombinedOutput(); err != nil {
		t.Fatalf("pass insert: %v %s", err, out)
	}
	git, _ := gitvault.Open(info.Path)
	if _, err := git.Sync(); err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(root, "remote.git")
	if files := run(t, "", "git", "--git-dir", remote, "ls-tree", "-r", "--name-only", "main"); files != ".gpg-id\nmail.gpg\n" {
		t.Fatalf("main holds %q", files)
	}

	// A second computer with nothing but the GitHub account and the password.
	computer(t, root, "second")
	repo := ghauth.Repo{FullName: "octo/.passport", CloneURL: cloneURL, Private: true}
	if _, err := RestoreFromGitHub(context.Background(), account, repo, []byte("wrong password!"), "/opt/passport", func(string) {}); !errors.Is(err, gpgkey.ErrBadPassphrase) {
		t.Fatalf("restore with a wrong password = %v; want ErrBadPassphrase", err)
	}
	if pending, _ := OnboardingPending(); pending != "restore" {
		t.Fatalf("pending after wrong password = %q; want restore to resume", pending)
	}
	steps = nil
	restored, err := RestoreFromGitHub(context.Background(), account, repo, password, "/opt/passport", progress)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(steps, ",") != "clone,recovery,import,unlock" {
		t.Fatalf("restore steps = %v", steps)
	}
	show := exec.Command("pass", "show", "mail")
	show.Env = append(os.Environ(), "PASSWORD_STORE_DIR="+restored.Path)
	out, err := show.Output()
	if err != nil || string(out) != "s3cret\nlogin: octo\n" {
		t.Fatalf("pass show on the second computer = %q, %v", out, err)
	}
	// pass can add entries on the second computer: the imported key is trusted.
	insert = exec.Command("pass", "insert", "-m", "-f", "bank")
	insert.Env = append(os.Environ(), "PASSWORD_STORE_DIR="+restored.Path)
	insert.Stdin = strings.NewReader("other\n")
	if out, err := insert.CombinedOutput(); err != nil {
		t.Fatalf("pass insert on the second computer: %v %s", err, out)
	}
	if _, err := CreateWithGitHub(context.Background(), client, account, password, "", "/opt/passport", progress); err == nil {
		t.Fatal("create overwrote an existing vault")
	}

	// The password changes on the first computer.
	computer(t, root, "first")
	newPassword := []byte("a different master password")
	if err := ChangeMasterPassword([]byte("not the password"), newPassword); !errors.Is(err, gpgkey.ErrBadPassphrase) {
		t.Fatalf("change with a wrong current password = %v", err)
	}
	if err := ChangeMasterPassword(password, newPassword); err != nil {
		t.Fatal(err)
	}
	if err := UnlockVault(password); !errors.Is(err, gpgkey.ErrBadPassphrase) {
		t.Fatalf("old password after change = %v", err)
	}
	// Offline, a change is undone so the key and the recovery copy agree.
	os.Rename(remote, remote+".away")
	if err := ChangeMasterPassword(newPassword, []byte("yet another master password")); err == nil {
		t.Fatal("password changed although the recovery copy could not be uploaded")
	}
	os.Rename(remote+".away", remote)
	if err := UnlockVault(newPassword); err != nil {
		t.Fatalf("password after an undone change: %v", err)
	}

	// The second computer picks the new password up from the recovery copy.
	computer(t, root, "second")
	secondFP, _ := VaultFingerprint()
	gpgkey.Lock(secondFP)
	if err := UnlockVault(newPassword); err != nil {
		t.Fatalf("new password on the second computer: %v", err)
	}
	gpgkey.Lock(secondFP)
	if err := UnlockVault(password); !errors.Is(err, gpgkey.ErrBadPassphrase) {
		t.Fatalf("old password on the second computer after the update = %v", err)
	}

	exported := filepath.Join(root, "exported.asc")
	if err := ExportKey(newPassword, exported); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(exported); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("exported key file: %v, %v", info, err)
	}
	if err := ExportKey([]byte("wrong password!"), exported); !errors.Is(err, gpgkey.ErrBadPassphrase) {
		t.Fatalf("export with a wrong password = %v", err)
	}
}

func run(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v %s", name, args, err, out)
	}
	return string(out)
}

func TestCustomRepoNameAndTopicDiscovery(t *testing.T) {
	var tagged []string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /user/repos", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		name := body["name"].(string)
		if name == "taken" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"name": name, "full_name": "octo/" + name, "clone_url": "https://github.com/octo/" + name + ".git", "private": true})
	})
	mux.HandleFunc("PUT /repos/octo/{repo}/topics", func(w http.ResponseWriter, r *http.Request) {
		tagged = append(tagged, r.PathValue("repo"))
		json.NewEncoder(w).Encode(map[string]any{"names": []string{VaultTopic}})
	})
	mux.HandleFunc("GET /user/repos", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{
			{"name": "secrets", "full_name": "octo/secrets", "private": true, "topics": []string{VaultTopic}},
			{"name": "notes", "full_name": "octo/notes", "private": true},
			{"name": "old-passport", "full_name": "octo/old-passport", "private": true},
		})
	})
	mux.HandleFunc("GET /repos/octo/{repo}/branches/passport-recovery", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("repo") == "notes" {
			t.Error("checked a repository that is neither tagged nor named passport")
		}
		if r.PathValue("repo") == "old-passport" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"name": "passport-recovery"})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client := &ghauth.Client{HTTP: server.Client(), APIBase: server.URL, WebBase: server.URL}
	ctx := context.Background()

	repo, err := createRepo(ctx, client, "token", "secrets")
	if err != nil || repo.FullName != "octo/secrets" || len(tagged) != 1 || tagged[0] != "secrets" {
		t.Fatalf("createRepo(secrets) = %+v, %v; tagged %v", repo, err, tagged)
	}
	if _, err := createRepo(ctx, client, "token", "taken"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("createRepo(taken) = %v", err)
	}
	found, err := FindGitHubVaults(ctx, client, "token")
	if err != nil || len(found) != 1 || found[0].FullName != "octo/secrets" {
		t.Fatalf("FindGitHubVaults() = %+v, %v", found, err)
	}
	for _, name := range []string{"", ".", "..", "a b", "x.git", strings.Repeat("a", 101), "a/b"} {
		if ghauth.ValidRepoName(name) {
			t.Errorf("ValidRepoName(%q) = true", name)
		}
	}
	for _, name := range []string{".passport", "my-vault_2", "Vault.backup"} {
		if !ghauth.ValidRepoName(name) {
			t.Errorf("ValidRepoName(%q) = false", name)
		}
	}
	if _, err := CreateWithGitHub(ctx, client, account, []byte("correct horse battery staple"), "bad name", "/opt/passport", func(string) {}); err == nil || !strings.Contains(err.Error(), "repository name") {
		t.Fatalf("CreateWithGitHub(bad name) = %v", err)
	}
}
