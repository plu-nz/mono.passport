package ghauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

// fakeGitHub serves the device flow and the REST endpoints Passage uses.
func fakeGitHub(t *testing.T, tokenReplies []string) (*Client, *atomic.Int32) {
	t.Helper()
	polls := &atomic.Int32{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/device/code", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("client_id") != "test-client" || r.Form.Get("scope") != "repo" {
			json.NewEncoder(w).Encode(map[string]string{"error": "incorrect_client_credentials"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"device_code": "dev-123", "user_code": "ABCD-1234", "verification_uri": "https://github.com/login/device", "expires_in": 900, "interval": 5})
	})
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("device_code") != "dev-123" || r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			json.NewEncoder(w).Encode(map[string]string{"error": "incorrect_device_code"})
			return
		}
		n := int(polls.Add(1)) - 1
		reply := tokenReplies[min(n, len(tokenReplies)-1)]
		if reply == "token" {
			json.NewEncoder(w).Encode(map[string]string{"access_token": "gho_secret", "token_type": "bearer", "scope": "repo"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"error": reply})
	})
	authorized := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer gho_secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		if authorized(w, r) {
			json.NewEncoder(w).Encode(map[string]any{"login": "octo", "id": 42, "name": "Octo Cat"})
		}
	})
	mux.HandleFunc("GET /user/repos", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(w, r) {
			return
		}
		if r.URL.Query().Get("affiliation") != "owner" {
			t.Errorf("affiliation = %q", r.URL.Query().Get("affiliation"))
		}
		repos := []map[string]any{}
		if r.URL.Query().Get("page") == "1" {
			for i := 0; i < 100; i++ {
				repos = append(repos, map[string]any{"name": "r", "full_name": "octo/r", "clone_url": "https://github.com/octo/r.git", "private": false})
			}
		} else {
			repos = append(repos, map[string]any{"name": "passage-vault", "full_name": "octo/passage-vault", "clone_url": "https://github.com/octo/passage-vault.git", "private": true, "default_branch": "main"})
		}
		json.NewEncoder(w).Encode(repos)
	})
	mux.HandleFunc("GET /repos/octo/passage-vault/branches/passage-recovery", func(w http.ResponseWriter, r *http.Request) {
		if authorized(w, r) {
			json.NewEncoder(w).Encode(map[string]string{"name": "passage-recovery"})
		}
	})
	mux.HandleFunc("POST /user/repos", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(w, r) {
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["private"] != true {
			t.Errorf("repository requested with private=%v", body["private"])
		}
		if body["name"] == "taken" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"name": body["name"], "full_name": "octo/" + body["name"].(string), "clone_url": "https://github.com/octo/" + body["name"].(string) + ".git", "private": true})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return &Client{HTTP: server.Client(), WebBase: server.URL, APIBase: server.URL, ClientID: "test-client"}, polls
}

func fastDevice(t *testing.T, c *Client) *Device {
	t.Helper()
	d, err := c.StartDevice(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d.UserCode != "ABCD-1234" || d.VerificationURI != "https://github.com/login/device" || d.interval != 5*time.Second {
		t.Fatalf("StartDevice() = %+v", d)
	}
	d.interval = time.Millisecond
	return d
}

func TestDeviceFlowWaitsThroughPendingAndSlowDown(t *testing.T) {
	old := slowDownStep
	slowDownStep = time.Millisecond
	t.Cleanup(func() { slowDownStep = old })
	c, polls := fakeGitHub(t, []string{"authorization_pending", "slow_down", "authorization_pending", "token"})
	token, err := c.Wait(context.Background(), fastDevice(t, c))
	if err != nil || token != "gho_secret" {
		t.Fatalf("Wait() = %q, %v", token, err)
	}
	if polls.Load() != 4 {
		t.Fatalf("polled %d times; want 4", polls.Load())
	}
}

func TestDeviceFlowEndings(t *testing.T) {
	for reply, want := range map[string]error{"access_denied": ErrDenied, "expired_token": ErrExpired} {
		c, _ := fakeGitHub(t, []string{"authorization_pending", reply})
		if _, err := c.Wait(context.Background(), fastDevice(t, c)); !errors.Is(err, want) {
			t.Errorf("%s: Wait() = %v; want %v", reply, err, want)
		}
	}
	c, _ := fakeGitHub(t, []string{"authorization_pending"})
	d := fastDevice(t, c)
	d.Expires = time.Now().Add(-time.Second)
	if _, err := c.Wait(context.Background(), d); !errors.Is(err, ErrExpired) {
		t.Errorf("past expiry: Wait() = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Wait(ctx, fastDevice(t, c)); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: Wait() = %v", err)
	}
	c.ClientID = "other"
	if _, err := c.StartDevice(context.Background()); err == nil {
		t.Error("StartDevice accepted a refusal")
	}
}

func TestREST(t *testing.T) {
	c, _ := fakeGitHub(t, []string{"token"})
	ctx := context.Background()
	user, err := c.User(ctx, "gho_secret")
	if err != nil || user.Login != "octo" || user.NoreplyEmail() != "42+octo@users.noreply.github.com" || user.DisplayName() != "Octo Cat" {
		t.Fatalf("User() = %+v, %v", user, err)
	}
	if _, err := c.User(ctx, "revoked"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("User(revoked) = %v", err)
	}
	repos, err := c.OwnedRepos(ctx, "gho_secret")
	if err != nil || len(repos) != 101 || repos[100].FullName != "octo/passage-vault" || !repos[100].Private {
		t.Fatalf("OwnedRepos() = %d repos, %v", len(repos), err)
	}
	if ok, err := c.HasBranch(ctx, "gho_secret", "octo/passage-vault", "passage-recovery"); !ok || err != nil {
		t.Fatalf("HasBranch(existing) = %v, %v", ok, err)
	}
	if ok, err := c.HasBranch(ctx, "gho_secret", "octo/other", "passage-recovery"); ok || err != nil {
		t.Fatalf("HasBranch(missing) = %v, %v", ok, err)
	}
	repo, err := c.CreatePrivateRepo(ctx, "gho_secret", "passage-vault", "Passage vault")
	if err != nil || repo.CloneURL != "https://github.com/octo/passage-vault.git" || !repo.Private {
		t.Fatalf("CreatePrivateRepo() = %+v, %v", repo, err)
	}
	if _, err := c.CreatePrivateRepo(ctx, "gho_secret", "taken", ""); !errors.Is(err, ErrRepoExists) {
		t.Fatalf("CreatePrivateRepo(taken) = %v", err)
	}
	if (User{Login: "octo", Name: "Evil <x@y>"}).DisplayName() != "octo" {
		t.Error("DisplayName accepted characters that break a GPG user ID")
	}
}

func isolateConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	return filepath.Join(dir, "passage", "github.json")
}

func TestStoreUsesSecretService(t *testing.T) {
	keyring.MockInit()
	file := isolateConfig(t)
	if _, err := Load(); !errors.Is(err, ErrSignedOut) {
		t.Fatalf("Load() before sign-in = %v", err)
	}
	saved, err := Save(Account{Login: "octo", ID: 42, Token: "gho_secret"})
	if err != nil || saved.Insecure {
		t.Fatalf("Save() = %+v, %v", saved, err)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("token written to a file although Secret Service works")
	}
	got, err := Load()
	if err != nil || got.Token != "gho_secret" || got.Login != "octo" || got.Insecure {
		t.Fatalf("Load() = %+v, %v", got, err)
	}
	if err := Delete(); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); !errors.Is(err, ErrSignedOut) {
		t.Fatalf("Load() after Delete = %v", err)
	}
}

func TestStoreFallsBackToPrivateFile(t *testing.T) {
	keyring.MockInitWithError(errors.New("no Secret Service"))
	t.Cleanup(keyring.MockInit)
	file := isolateConfig(t)
	saved, err := Save(Account{Login: "octo", ID: 42, Token: "gho_secret"})
	if err != nil || !saved.Insecure {
		t.Fatalf("Save() = %+v, %v", saved, err)
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("fallback file: %v, %v", info, err)
	}
	got, err := Load()
	if err != nil || got.Token != "gho_secret" || !got.Insecure {
		t.Fatalf("Load() = %+v, %v", got, err)
	}
	if err := Delete(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Delete left the fallback file")
	}
}

func TestCredentialHelper(t *testing.T) {
	keyring.MockInit()
	isolateConfig(t)
	run := func(args []string, input string) string {
		var out bytes.Buffer
		if code := CredentialHelper(args, strings.NewReader(input), &out); code != 0 {
			t.Fatalf("exit %d", code)
		}
		return out.String()
	}
	request := "protocol=https\nhost=github.com\npath=octo/passage-vault.git\n\n"
	if got := run([]string{"get"}, request); got != "" {
		t.Fatalf("answered while signed out: %q", got)
	}
	Save(Account{Login: "octo", ID: 42, Token: "gho_secret"})
	if got := run([]string{"get"}, request); got != "username=x-access-token\npassword=gho_secret\n" {
		t.Fatalf("get = %q", got)
	}
	for _, other := range []string{"protocol=https\nhost=gitlab.com\n\n", "protocol=http\nhost=github.com\n\n", "host=github.com\n\n"} {
		if got := run([]string{"get"}, other); got != "" {
			t.Errorf("token sent for %q", other)
		}
	}
	if got := run([]string{"store"}, request); got != "" {
		t.Errorf("store printed %q", got)
	}
}
