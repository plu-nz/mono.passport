package vault

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAndPreserveFields(t *testing.T) {
	for _, id := range []string{"../x", "x/../y", "-x", "x//y", "x.gpg", "x\ny"} {
		if ValidateID(id) == nil {
			t.Errorf("accepted %q", id)
		}
	}
	original := "old\ncustom: before\nlogin: alice\notpauth: test\nurl: https://first.example\ncustom: after\n"
	secret := ParseSecret(original)
	if secret.OtherDetails != "custom: before\notpauth: test\ncustom: after\n" {
		t.Fatalf("other details: %q", secret.OtherDetails)
	}
	updated, err := replaceKnown(original, "new", "bob", "https://new.example")
	if err != nil {
		t.Fatal(err)
	}
	if updated != "new\ncustom: before\nlogin: bob\notpauth: test\nurl: https://new.example\ncustom: after\n" {
		t.Fatalf("ordering lost: %q", updated)
	}
	content, err := composeFields("password", "alice", []string{"https://one.test/login", "https://two.test/sign-in"}, "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP", "note: keep\n")
	if err != nil {
		t.Fatal(err)
	}
	parsed := ParseSecret(content)
	if len(parsed.URLs) != 2 || parsed.URLs[1] != "https://two.test/sign-in" || parsed.TOTPURI != "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP" || parsed.OtherDetails != "note: keep\n" {
		t.Fatalf("multiple URLs and authenticator were not parsed: %+v", parsed)
	}
}

func TestTOTPPeriodForEntryList(t *testing.T) {
	for _, test := range []struct {
		uri  string
		want uint64
	}{
		{"", 0},
		{"otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP", 30},
		{"otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=45", 45},
		{"otpauth://totp/Test?period=0", 0},
	} {
		if got := totpPeriod(test.uri); got != test.want {
			t.Errorf("totpPeriod(%q) = %d, want %d", test.uri, got, test.want)
		}
	}
}

func TestAndroidAppWebsiteURI(t *testing.T) {
	content, err := composeFields("password", "user", []string{"androidapp://com.google.android.gm", "https://mail.google.com"}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	urls := ParseSecret(content).URLs
	if len(urls) != 2 || urls[0] != "androidapp://com.google.android.gm" || urls[1] != "https://mail.google.com" {
		t.Fatalf("URLs changed: %q", urls)
	}
	for _, invalid := range []string{"androidapp://", "androidapp://com.google.android.gm/path", "androidapp://com.google.android.gm?x=1", "androidapp://com.google.android.gm:80", "androidapp://other@com.google.android.gm"} {
		if _, err := composeFields("password", "", []string{invalid}, "", ""); err == nil {
			t.Errorf("accepted invalid Android app URI %q", invalid)
		}
	}
}
func TestDisposablePassStoreAndConflict(t *testing.T) {
	if _, err := exec.LookPath("pass"); err != nil {
		t.Skip("pass absent")
	}
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg absent")
	}
	home := t.TempDir()
	gnupg := filepath.Join(home, "gnupg")
	if err := os.Mkdir(gnupg, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", gnupg)
	store := filepath.Join(home, "store")
	key := exec.Command("gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", "Passport Go Test <go-test@example.invalid>", "default", "default", "1d")
	if out, err := key.CombinedOutput(); err != nil {
		t.Fatalf("gpg: %v %s", err, out)
	}
	out, err := exec.Command("gpg", "--with-colons", "--fingerprint", "--list-secret-keys").Output()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := ""
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "fpr:") {
			fields := strings.Split(line, ":")
			fingerprint = fields[9]
			break
		}
	}
	if fingerprint == "" {
		t.Fatal("missing fingerprint")
	}
	init := exec.Command("pass", "init", fingerprint)
	init.Env = append(os.Environ(), "PASSWORD_STORE_DIR="+store)
	if out, err := init.CombinedOutput(); err != nil {
		t.Fatalf("pass init: %v %s", err, out)
	}
	v, err := Open(store)
	if err != nil {
		t.Fatal(err)
	}
	created, err := v.CreateLogin("sites/example.com", "first", "alice", "https://example.com", "otpauth: test\ncustom: keep\n")
	if err != nil {
		t.Fatal(err)
	}
	listed, err := v.List()
	if err != nil || len(listed) != 1 || listed[0].Username == nil || *listed[0].Username != "alice" || len(listed[0].URLs) != 1 || listed[0].URLs[0] != "https://example.com" {
		t.Fatalf("List metadata = %+v, %v", listed, err)
	}
	if _, err := v.CreateLogin("sites/taken", "x", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := v.Rename("sites/example.com", "sites/taken", created.CiphertextHash); err == nil {
		t.Fatal("Rename overwrote an existing entry")
	}
	if err := v.Rename("sites/example.com", "../escape", created.CiphertextHash); err == nil {
		t.Fatal("Rename accepted a name outside the vault")
	}
	if err := v.Rename("sites/example.com", "work/example", strings.Repeat("0", 64)); err == nil {
		t.Fatal("Rename ignored a stale version")
	}
	if err := v.Rename("sites/example.com", "work/example", created.CiphertextHash); err != nil {
		t.Fatal(err)
	}
	if renamed, err := v.Read("work/example"); err != nil || renamed.Password != "first" {
		t.Fatalf("Read(renamed) = %+v, %v", renamed, err)
	}
	if _, err := v.Read("sites/example.com"); err == nil {
		t.Fatal("old name still readable after Rename")
	}
	if err := v.Rename("work/example", "sites/example.com", created.CiphertextHash); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store, "sites/example.com.gpg")); err != nil {
		t.Fatal(err)
	}
	if created.Password != "first" || created.Username == nil || *created.Username != "alice" {
		t.Fatalf("bad secret %+v", created)
	}
	favorite, err := v.SetFlag("sites/example.com", "favorite", true, created.CiphertextHash)
	if err != nil || !favorite.Favorite || favorite.Archived {
		t.Fatalf("SetFlag(favorite) = %+v, %v", favorite, err)
	}
	archived, err := v.SetFlag("sites/example.com", "archived", true, favorite.CiphertextHash)
	if err != nil || !archived.Favorite || !archived.Archived {
		t.Fatalf("SetFlag(archived) = %+v, %v", archived, err)
	}
	if _, err := v.SetFlag("sites/example.com", "favorite", false, favorite.CiphertextHash); err == nil {
		t.Fatal("SetFlag accepted a stale version")
	}
	marked, err := v.List()
	if err != nil || len(marked) != 2 || !marked[0].Archived || !marked[0].Favorite {
		t.Fatalf("List marked entries = %+v, %v", marked, err)
	}
	updated, err := v.UpdateLogin("sites/example.com", "first", "alice", "https://example.com", "custom: changed\n", archived.CiphertextHash)
	if err != nil || !updated.Archived || !updated.Favorite || strings.Contains(updated.OtherDetails, "passport-") {
		t.Fatalf("UpdateLogin lost flags = %+v, %v", updated, err)
	}
	restored, err := v.SetFlag("sites/example.com", "archived", false, updated.CiphertextHash)
	if err != nil || restored.Archived || !restored.Favorite {
		t.Fatalf("SetFlag(restore) = %+v, %v", restored, err)
	}
	created = restored
	stale := created.CiphertextHash
	external := exec.Command("pass", "insert", "-m", "-f", "sites/example.com")
	external.Env = append(os.Environ(), "PASSWORD_STORE_DIR="+store)
	external.Stdin = strings.NewReader("external\nlogin: alice\nurl: https://example.com\notpauth: test\ncustom: keep\n")
	if out, err := external.CombinedOutput(); err != nil {
		t.Fatalf("pass insert: %v %s", err, out)
	}
	if _, err := v.UpdateLogin("sites/example.com", "overwrite", "bob", "https://example.com", "", stale); err == nil {
		t.Fatal("stale update accepted")
	}
	fresh, err := v.Read("sites/example.com")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Password != "external" {
		t.Fatal("external change lost")
	}
	saved, err := v.UpdateLogin("sites/example.com", "new", "bob", "https://new.example", fresh.OtherDetails, fresh.CiphertextHash)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(saved.OtherDetails, "custom: keep") || !strings.Contains(saved.OtherDetails, "otpauth: test") {
		t.Fatalf("fields lost: %+v", saved)
	}
	multiple, err := v.UpdateLoginFields("sites/example.com", "new", "bob", []string{"https://new.example", "https://second.example/login"}, "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP", "custom: keep\n", saved.CiphertextHash)
	if err != nil || len(multiple.URLs) != 2 || multiple.TOTPURI == "" || multiple.OtherDetails != "custom: keep\n" {
		t.Fatalf("UpdateLoginFields = %+v, %v", multiple, err)
	}
	if err := os.Symlink(filepath.Join(store, "sites/example.com.gpg"), filepath.Join(store, "alias.gpg")); err == nil {
		if _, err := v.Read("alias"); err == nil {
			t.Fatal("symlink accepted")
		}
	}
	if _, err := exec.LookPath("git"); err == nil {
		for _, args := range [][]string{{"init", "-q", "-b", "main"}, {"config", "user.name", "Passport Test"}, {"config", "user.email", "passport@example.invalid"}, {"add", ".gpg-id", "sites/example.com.gpg", "sites/taken.gpg"}, {"commit", "-q", "-m", "Initial vault"}} {
			cmd := exec.Command("git", args...)
			cmd.Dir = store
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v %s", args, err, out)
			}
		}
		before, err := exec.Command("git", "-C", store, "rev-parse", "HEAD").Output()
		if err != nil {
			t.Fatal(err)
		}
		current, err := v.Read("sites/example.com")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.SetFlag("sites/example.com", "favorite", !current.Favorite, current.CiphertextHash); err != nil {
			t.Fatal(err)
		}
		after, err := exec.Command("git", "-C", store, "rev-parse", "HEAD").Output()
		if err != nil || string(after) != string(before) {
			t.Fatalf("metadata edit created a commit: %q, %v", after, err)
		}
	}
}
