package gpgkey

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gnupgHome points GNUPGHOME at a fresh directory and stops its agent afterwards.
func gnupgHome(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg absent")
	}
	dir := filepath.Join(t.TempDir(), "gnupg")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", dir)
	t.Cleanup(func() { killAgent(dir) })
	return dir
}

func killAgent(dir string) {
	cmd := exec.Command("gpgconf", "--kill", "gpg-agent")
	cmd.Env = append(os.Environ(), "GNUPGHOME="+dir)
	cmd.Run()
}

// decryptsWithoutPrompt reports whether gpg can decrypt using only the agent cache.
func decryptsWithoutPrompt(t *testing.T, ciphertext []byte) bool {
	t.Helper()
	cmd := exec.Command("gpg", "--batch", "--pinentry-mode", "error", "--decrypt")
	cmd.Stdin = bytes.NewReader(ciphertext)
	out, err := cmd.Output()
	return err == nil && string(out) == "entry"
}

func encrypt(t *testing.T, fingerprint string) []byte {
	t.Helper()
	cmd := exec.Command("gpg", "--batch", "--trust-model", "always", "--encrypt", "--recipient", fingerprint)
	cmd.Stdin = strings.NewReader("entry")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

var password = []byte("correct horse battery staple")

func TestMasterPasswordLifecycle(t *testing.T) {
	first := gnupgHome(t)
	fp, err := Generate("Passage Test <passage@example.invalid>", password)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidFingerprint(fp) {
		t.Fatalf("Generate() fingerprint %q", fp)
	}
	entry := encrypt(t, fp)
	if err := Lock(fp); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportSecret(fp, []byte("wrong")); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("ExportSecret(wrong) = %v; want ErrBadPassphrase", err)
	}
	armored, err := ExportSecret(fp, password)
	if err != nil {
		t.Fatal(err)
	}

	// A second computer: a fresh GnuPG home that receives the exported key.
	killAgent(first)
	gnupgHome(t)
	if err := Import(armored, strings.Repeat("A", 40)); err == nil {
		t.Fatal("Import accepted a key with another fingerprint")
	}
	if err := Import(armored, strings.ToLower(fp)); err != nil {
		t.Fatal(err)
	}
	if unlocked, err := Unlocked(fp); err != nil || unlocked {
		t.Fatalf("Unlocked() after import = %v, %v; want false", unlocked, err)
	}
	if err := Unlock(fp, []byte("wrong")); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("Unlock(wrong) = %v; want ErrBadPassphrase", err)
	}
	if err := Unlock(fp, password); err != nil {
		t.Fatal(err)
	}
	if unlocked, err := Unlocked(fp); err != nil || !unlocked {
		t.Fatalf("Unlocked() after Unlock = %v, %v; want true", unlocked, err)
	}
	if !decryptsWithoutPrompt(t, entry) {
		t.Fatal("entry did not decrypt from the agent cache after Unlock")
	}
	// pass needs the imported key to be trusted to encrypt new entries.
	cmd := exec.Command("gpg", "--batch", "--encrypt", "--recipient", fp)
	cmd.Stdin = strings.NewReader("new entry")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("encrypting without --trust-model failed: %v %s", err, out)
	}

	// With the passphrase cached, a wrong password must still be refused.
	if err := Unlock(fp, []byte("wrong")); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("Unlock(wrong) while cached = %v; want ErrBadPassphrase", err)
	}
	if err := Unlock(fp, password); err != nil {
		t.Fatal(err)
	}
	if err := Lock(fp); err != nil {
		t.Fatal(err)
	}
	if unlocked, _ := Unlocked(fp); unlocked {
		t.Fatal("Unlocked() after Lock = true")
	}
	if decryptsWithoutPrompt(t, entry) {
		t.Fatal("entry decrypted without a prompt after Lock")
	}
}

func TestImportRejectsPublicOnlyKey(t *testing.T) {
	gnupgHome(t)
	fp, err := Generate("Passage Test <passage@example.invalid>", password)
	if err != nil {
		t.Fatal(err)
	}
	public, err := exec.Command("gpg", "--batch", "--armor", "--export", fp).Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := Import(public, fp); err == nil {
		t.Fatal("Import accepted a public key")
	}
	if err := Import([]byte("not a key"), fp); err == nil {
		t.Fatal("Import accepted garbage")
	}
}

func TestPasswordsGPGWouldTruncate(t *testing.T) {
	for _, pw := range []string{"", "good\nextra", "good\rextra", "good\x00extra"} {
		if err := CheckPassword([]byte(pw)); err == nil {
			t.Errorf("CheckPassword(%q) accepted", pw)
		}
	}
	if _, err := Generate("Passage Test <passage@example.invalid>", []byte("a\nb")); err == nil {
		t.Error("Generate accepted a password with a newline")
	}
	if err := CheckPassword([]byte("correct horse battery staple")); err != nil {
		t.Error(err)
	}
}

func TestStatusParsing(t *testing.T) {
	bad := result{status: []byte("[GNUPG:] KEY_CONSIDERED X 0\n[GNUPG:] ERROR export_keys.secret 67108875\n[GNUPG:] FAILURE gpg-exit 33554433\n")}
	if !bad.badPassphrase() {
		t.Error("GPG_ERR_BAD_PASSPHRASE not detected")
	}
	other := result{status: []byte("[GNUPG:] ERROR pkdecrypt_failed 67108881\n")}
	if other.badPassphrase() {
		t.Error("another error read as a bad passphrase")
	}
	if got := CreatedFingerprint([]byte("[GNUPG:] KEY_CREATED B 0CBF4CAA80A81A887EBBE33E2ED3004C145B215F\n")); got != "0CBF4CAA80A81A887EBBE33E2ED3004C145B215F" {
		t.Errorf("CreatedFingerprint() = %q", got)
	}
}

func TestParseEncryptionKeygrips(t *testing.T) {
	listing := strings.Join([]string{
		"sec:u:255:22:2ED3004C145B215F:1:::u:::scESC:::+:::ed25519:::0:",
		"fpr:::::::::0CBF4CAA80A81A887EBBE33E2ED3004C145B215F:",
		"grp:::::::::09CAB6C0313A9FE19717636ADF19DAE46BDFDF50:",
		"uid:u::::1::X::Test <t@example.invalid>::::::::::0:",
		"ssb:e:255:18:1111111111111111:1::::::e:::+:::cv25519::",
		"fpr:::::::::1111111111111111111111111111111111111111:",
		"grp:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:",
		"ssb:u:255:18:2EEA991897F187DD:1::::::e:::+:::cv25519::",
		"fpr:::::::::2222222222222222222222222222222222222222:",
		"grp:::::::::E50C9D0D1BA420D05C68033E457DB5DBCD699E7F:",
	}, "\n")
	got := parseEncryptionKeygrips([]byte(listing))
	if len(got) != 1 || got[0] != "E50C9D0D1BA420D05C68033E457DB5DBCD699E7F" {
		t.Fatalf("parseEncryptionKeygrips() = %v; want only the valid encryption subkey", got)
	}
}

func TestChangePassphraseAndReplace(t *testing.T) {
	first := gnupgHome(t)
	fp, err := Generate("Passage Test <passage@example.invalid>", password)
	if err != nil {
		t.Fatal(err)
	}
	entry := encrypt(t, fp)
	before, err := ExportSecret(fp, password)
	if err != nil {
		t.Fatal(err)
	}
	newPassword := []byte("a brand new master password")
	if err := ChangePassphrase(fp, []byte("wrong"), newPassword); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("ChangePassphrase(wrong old) = %v; want ErrBadPassphrase", err)
	}
	if err := ChangePassphrase(fp, password, newPassword); err != nil {
		t.Fatal(err)
	}
	if err := Unlock(fp, password); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("old password still unlocks: %v", err)
	}
	if err := Unlock(fp, newPassword); err != nil {
		t.Fatal(err)
	}
	after, err := ExportSecret(fp, newPassword)
	if err != nil {
		t.Fatal(err)
	}

	// Another computer still holds the key under the old password.
	killAgent(first)
	gnupgHome(t)
	if err := Import(before, fp); err != nil {
		t.Fatal(err)
	}
	if err := Import(after, fp); err != nil {
		t.Fatal(err)
	}
	if err := Unlock(fp, newPassword); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("a plain re-import changed the protection: %v", err)
	}
	if err := Replace(after, fp); err != nil {
		t.Fatal(err)
	}
	if err := Unlock(fp, newPassword); err != nil {
		t.Fatalf("Unlock after Replace: %v", err)
	}
	if !decryptsWithoutPrompt(t, entry) {
		t.Fatal("entry did not decrypt after Replace")
	}
	cmd := exec.Command("gpg", "--batch", "--encrypt", "--recipient", fp)
	cmd.Stdin = strings.NewReader("new entry")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("trust lost after Replace: %v %s", err, out)
	}
}
