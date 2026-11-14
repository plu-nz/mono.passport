// Package gpgkey drives GnuPG for the master-password flow: it generates,
// exports and imports the vault key and unlocks or locks it in gpg-agent.
//
// The password always reaches gpg through an inherited pipe (--passphrase-fd 3)
// with loopback pinentry, never through argv, the environment or a file.
// Success and wrong-password detection rely on exit codes and --status-fd
// lines, which do not depend on the user's locale.
package gpgkey

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// ErrBadPassphrase means gpg-agent rejected the master password.
var ErrBadPassphrase = errors.New("Wrong master password")

var fingerprintPattern = regexp.MustCompile(`^[a-fA-F0-9]{40}([a-fA-F0-9]{24})?$`)

// ValidFingerprint reports whether s is a full v4 (40) or v5 (64) hex fingerprint.
func ValidFingerprint(s string) bool { return fingerprintPattern.MatchString(s) }

// gpgErrBadPassphrase is GPG_ERR_BAD_PASSPHRASE; status lines carry it as
// "ERROR <location> <source<<24 | code>".
const gpgErrBadPassphrase = 11

// CheckPassword rejects passwords gpg would read differently from what the
// user typed: --passphrase-fd stops at the first newline, so "a\nb" would be "a".
func CheckPassword(password []byte) error {
	if len(password) == 0 {
		return errors.New("Master password is empty")
	}
	if bytes.ContainsAny(password, "\n\r\x00") {
		return errors.New("Master password cannot contain line breaks")
	}
	return nil
}

type result struct {
	stdout, status []byte
	err            error
}

// badPassphrase reports whether a status stream contains GPG_ERR_BAD_PASSPHRASE.
func (r result) badPassphrase() bool {
	for _, line := range bytes.Split(r.status, []byte{'\n'}) {
		f := strings.Fields(string(line))
		if len(f) == 4 && f[0] == "[GNUPG:]" && f[1] == "ERROR" {
			if code, err := strconv.ParseUint(f[3], 10, 32); err == nil && code&0xFFFF == gpgErrBadPassphrase {
				return true
			}
		}
	}
	return false
}

// gpg runs gpg in batch mode with status lines on fd 4 and, when password is
// not nil, loopback pinentry reading the password from fd 3.
func gpg(password []byte, stdin []byte, args ...string) result {
	base := []string{"--batch", "--no-tty", "--status-fd", "4"}
	var files []*os.File
	if password != nil {
		r, w, err := os.Pipe()
		if err != nil {
			return result{err: err}
		}
		defer r.Close()
		// A password is far smaller than the pipe buffer, so writing before
		// the process starts cannot block.
		_, err = w.Write(password)
		w.Close()
		if err != nil {
			return result{err: err}
		}
		files = append(files, r)
		base = append(base, "--pinentry-mode", "loopback", "--passphrase-fd", "3")
	} else {
		files = append(files, nil)
	}
	statusR, statusW, err := os.Pipe()
	if err != nil {
		return result{err: err}
	}
	defer statusR.Close()
	files = append(files, statusW)

	cmd := exec.Command("gpg", append(base, args...)...)
	cmd.ExtraFiles = files
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		statusW.Close()
		return result{err: err}
	}
	statusW.Close()
	var status bytes.Buffer
	done := make(chan struct{})
	go func() { status.ReadFrom(statusR); close(done) }()
	err = cmd.Wait()
	<-done
	return result{stdout: stdout.Bytes(), status: status.Bytes(), err: err}
}

func fail(what string, r result) error {
	if r.badPassphrase() {
		return ErrBadPassphrase
	}
	return fmt.Errorf("GPG could not %s", what)
}

// Generate creates a new key for uid protected by password and returns its fingerprint.
func Generate(uid string, password []byte) (string, error) {
	if err := CheckPassword(password); err != nil {
		return "", err
	}
	r := gpg(password, nil, "--quick-generate-key", uid, "default", "default", "never")
	fp := CreatedFingerprint(r.status)
	if r.err != nil {
		if fp != "" {
			return "", fmt.Errorf("GPG did not complete generation; the key %s may exist", fp)
		}
		return "", fail("create the key", r)
	}
	if fp == "" {
		return "", errors.New("GPG finished without reporting a fingerprint; check your keys")
	}
	return fp, nil
}

// CreatedFingerprint returns the fingerprint in a KEY_CREATED status line.
func CreatedFingerprint(status []byte) string {
	for _, line := range bytes.Split(status, []byte{'\n'}) {
		f := strings.Fields(string(line))
		if len(f) >= 4 && f[0] == "[GNUPG:]" && f[1] == "KEY_CREATED" && ValidFingerprint(f[3]) {
			return f[3]
		}
	}
	return ""
}

// ExportSecret returns the armored secret key. The export stays protected by
// the key's passphrase; gpg asks for it before exporting, so a wrong password
// fails here. A failed export can still print an armor header, so only the
// exit status decides success.
func ExportSecret(fingerprint string, password []byte) ([]byte, error) {
	if !ValidFingerprint(fingerprint) {
		return nil, errors.New("Invalid key fingerprint")
	}
	if err := CheckPassword(password); err != nil {
		return nil, err
	}
	r := gpg(password, nil, "--armor", "--export-secret-keys", fingerprint)
	if r.err != nil {
		return nil, fail("export the key", r)
	}
	if !bytes.HasPrefix(bytes.TrimSpace(r.stdout), []byte("-----BEGIN PGP PRIVATE KEY BLOCK-----")) || !bytes.Contains(r.stdout, []byte("-----END PGP PRIVATE KEY BLOCK-----")) {
		return nil, errors.New("GPG exported no private key")
	}
	return r.stdout, nil
}

// Import adds an armored secret key and marks it ultimately trusted, which
// pass needs to encrypt new entries. gpg does not check the passphrase on
// import, so callers must verify the password before (recovery.Open) and
// unlock after. The key must be exactly the one named by fingerprint.
func Import(armored []byte, fingerprint string) error {
	if !ValidFingerprint(fingerprint) {
		return errors.New("Invalid key fingerprint")
	}
	fingerprint = strings.ToUpper(fingerprint)
	r := gpg(nil, armored, "--with-colons", "--import-options", "show-only", "--import")
	if r.err != nil {
		return errors.New("Recovery copy does not contain a readable key")
	}
	if got := secretPrimaries(r.stdout); len(got) != 1 || got[0] != fingerprint {
		return errors.New("Recovery copy holds a different key than expected")
	}
	if r = gpg(nil, armored, "--import"); r.err != nil {
		return errors.New("GPG could not import the key")
	}
	if r = gpg(nil, []byte(fingerprint+":6:\n"), "--import-ownertrust"); r.err != nil {
		return errors.New("GPG could not mark the key as trusted")
	}
	return nil
}

// secretPrimaries lists the primary fingerprints of the secret keys in a
// --with-colons key listing; public-only keys come back as "pub:" and are
// reported as "PUBLIC:<fpr>" so they never match an expected fingerprint.
func secretPrimaries(listing []byte) []string {
	var out []string
	kind := ""
	for _, line := range strings.Split(string(listing), "\n") {
		f := strings.Split(line, ":")
		switch f[0] {
		case "sec", "pub":
			kind = f[0]
		case "ssb", "sub", "uid":
			if kind != "" && f[0] != "uid" {
				kind = ""
			}
		case "fpr":
			if kind != "" && len(f) > 9 && ValidFingerprint(f[9]) {
				fp := strings.ToUpper(f[9])
				if kind == "pub" {
					fp = "PUBLIC:" + fp
				}
				out = append(out, fp)
			}
			kind = ""
		}
	}
	return out
}

// Unlock verifies password and leaves it in the gpg-agent cache, so pass, the
// browser host and the terminal decrypt without pinentry until the cache
// expires. A cached passphrase would make any password look right, so Unlock
// clears this key's cache first.
func Unlock(fingerprint string, password []byte) error {
	if err := CheckPassword(password); err != nil {
		return err
	}
	if err := Lock(fingerprint); err != nil {
		return err
	}
	sentinel := make([]byte, 32)
	if _, err := rand.Read(sentinel); err != nil {
		return err
	}
	enc := gpg(nil, sentinel, "--trust-model", "always", "--encrypt", "--recipient", fingerprint)
	if enc.err != nil {
		return errors.New("GPG could not use the vault key")
	}
	dec := gpg(password, enc.stdout, "--decrypt")
	if dec.err != nil {
		return fail("unlock the key", dec)
	}
	if !bytes.Equal(dec.stdout, sentinel) {
		return errors.New("GPG returned unexpected data while unlocking")
	}
	return nil
}

// Lock removes this key's passphrase from the gpg-agent cache. Other keys,
// such as a Git signing key, stay cached.
func Lock(fingerprint string) error {
	grips, err := encryptionKeygrips(fingerprint)
	if err != nil {
		return err
	}
	for _, grip := range grips {
		if _, err := agent("CLEAR_PASSPHRASE --mode=normal " + grip); err != nil {
			return err
		}
	}
	return nil
}

// Unlocked reports whether gpg-agent holds the passphrase for a key that can
// decrypt vault entries.
func Unlocked(fingerprint string) (bool, error) {
	grips, err := encryptionKeygrips(fingerprint)
	if err != nil {
		return false, err
	}
	for _, grip := range grips {
		out, err := agent("KEYINFO " + grip)
		if err != nil {
			return false, err
		}
		// S KEYINFO <grip> <type> <serial> <idstr> <cached> <protection> ...
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) >= 7 && f[0] == "S" && f[1] == "KEYINFO" && f[2] == grip && f[6] == "1" {
				return true, nil
			}
		}
	}
	return false, nil
}

var keygripPattern = regexp.MustCompile(`^[A-F0-9]{40}$`)

// encryptionKeygrips returns the keygrips of the usable primary key or
// subkeys with the encrypt capability.
func encryptionKeygrips(fingerprint string) ([]string, error) {
	if !ValidFingerprint(fingerprint) {
		return nil, errors.New("Invalid key fingerprint")
	}
	out, err := exec.Command("gpg", "--batch", "--with-colons", "--with-keygrip", "--list-secret-keys", "--", fingerprint).Output()
	if err != nil {
		return nil, errors.New("The vault key is not on this computer")
	}
	return parseEncryptionKeygrips(out), nil
}

func parseEncryptionKeygrips(out []byte) []string {
	var grips []string
	encrypts := false
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, ":")
		switch f[0] {
		case "sec", "ssb":
			// Field 2 is validity (r revoked, e expired, i invalid, d disabled);
			// field 12 lists capabilities, lowercase for this (sub)key.
			encrypts = len(f) > 11 && !strings.ContainsAny(f[1], "redi") && strings.Contains(f[11], "e")
		case "grp":
			if encrypts && len(f) > 9 && keygripPattern.MatchString(f[9]) {
				grips = append(grips, f[9])
			}
			encrypts = false
		}
	}
	return grips
}

func agent(command string) (string, error) {
	out, err := exec.Command("gpg-connect-agent", command, "/bye").Output()
	if err != nil {
		return "", errors.New("Unable to reach gpg-agent")
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "ERR ") {
			return "", fmt.Errorf("gpg-agent refused the request: %s", strings.TrimPrefix(line, "ERR "))
		}
	}
	return string(out), nil
}

// ChangePassphrase re-protects the key (primary and subkeys) with a new
// password. gpg asks for the old and then the new passphrase over
// --command-fd, which here is stdin, so neither reaches argv.
func ChangePassphrase(fingerprint string, old, new []byte) error {
	if !ValidFingerprint(fingerprint) {
		return errors.New("Invalid key fingerprint")
	}
	if err := CheckPassword(old); err != nil {
		return err
	}
	if err := CheckPassword(new); err != nil {
		return err
	}
	answers := make([]byte, 0, len(old)+len(new)+2)
	answers = append(append(append(append(answers, old...), '\n'), new...), '\n')
	defer clear(answers)
	r := gpg(nil, answers, "--pinentry-mode", "loopback", "--command-fd", "0", "--passwd", fingerprint)
	if r.err != nil {
		return fail("change the master password", r)
	}
	return nil
}

// Replace swaps the local private key for the armored one with the same
// fingerprint. gpg keeps an existing key's protection on import, so after a
// password change on another computer the old local copy must go first.
func Replace(armored []byte, fingerprint string) error {
	if !ValidFingerprint(fingerprint) {
		return errors.New("Invalid key fingerprint")
	}
	fingerprint = strings.ToUpper(fingerprint)
	r := gpg(nil, armored, "--with-colons", "--import-options", "show-only", "--import")
	if r.err != nil {
		return errors.New("Recovery copy does not contain a readable key")
	}
	if got := secretPrimaries(r.stdout); len(got) != 1 || got[0] != fingerprint {
		return errors.New("Recovery copy holds a different key than expected")
	}
	if r = gpg(nil, nil, "--yes", "--delete-secret-keys", fingerprint); r.err != nil {
		return errors.New("GPG could not replace the local key")
	}
	return Import(armored, fingerprint)
}
