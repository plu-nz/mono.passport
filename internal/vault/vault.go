package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/plu-nz/mono.passport/internal/setup"
)

type Entry struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Username   *string  `json:"username"`
	URLs       []string `json:"urls"`
	Favorite   bool     `json:"favorite"`
	Archived   bool     `json:"archived"`
	TOTPPeriod uint64   `json:"totp_period"`
}
type Secret struct {
	Password       string   `json:"password"`
	Details        string   `json:"details"`
	OtherDetails   string   `json:"other_details"`
	Username       *string  `json:"username"`
	URLs           []string `json:"urls"`
	TOTPURI        string   `json:"totp_uri"`
	CiphertextHash string   `json:"ciphertext_hash"`
	Favorite       bool     `json:"favorite"`
	Archived       bool     `json:"archived"`
}
type Vault struct{ root string }

var androidPackage = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$`)

func OpenEnv() (*Vault, error) {
	path, _, err := setup.ActiveVaultPath()
	if err != nil {
		return nil, err
	}
	return Open(path)
}
func Open(path string) (*Vault, error) {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("Vault not found at %s", path)
	}
	root, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &Vault{root: root}, nil
}
func (v *Vault) Root() string { return v.root }
func ValidateID(id string) error {
	if id == "" || strings.HasSuffix(id, ".gpg") || strings.ContainsAny(id, "\\\x00") || filepath.IsAbs(id) {
		return errors.New("Invalid entry identifier")
	}
	for _, part := range strings.Split(id, "/") {
		if part == "" || part == "." || part == ".." || strings.HasPrefix(part, "-") {
			return errors.New("Invalid entry identifier")
		}
	}
	if strings.IndexFunc(id, unicode.IsControl) >= 0 {
		return errors.New("Invalid entry identifier")
	}
	return nil
}
func (v *Vault) safeTarget(id string) (string, error) {
	if err := ValidateID(id); err != nil {
		return "", err
	}
	current := v.root
	for _, part := range strings.Split(id+".gpg", "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("Symbolic links are not allowed in the entry path")
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	return current, nil
}
func (v *Vault) existingFile(id string) (string, error) {
	target, err := v.safeTarget(id)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(target)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("Entry not found")
	}
	canonical, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(canonical, v.root+string(os.PathSeparator)) {
		return "", errors.New("Entry is outside the vault")
	}
	return canonical, nil
}
func (v *Vault) List() ([]Entry, error) {
	entries := []Entry{}
	err := filepath.WalkDir(v.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != v.root && d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 || !d.Type().IsRegular() || !strings.HasSuffix(d.Name(), ".gpg") {
			return nil
		}
		relative, err := filepath.Rel(v.root, path)
		if err != nil {
			return err
		}
		id := strings.TrimSuffix(filepath.ToSlash(relative), ".gpg")
		if ValidateID(id) != nil {
			return nil
		}
		entries = append(entries, Entry{ID: id, Title: strings.TrimSuffix(d.Name(), ".gpg"), URLs: []string{}})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return strings.ToLower(entries[i].ID) < strings.ToLower(entries[j].ID) })
	for i := range entries {
		secret, err := v.Read(entries[i].ID)
		if err != nil {
			continue
		}
		entries[i].Username = secret.Username
		entries[i].URLs = secret.URLs
		entries[i].Favorite = secret.Favorite
		entries[i].Archived = secret.Archived
		uri := secret.TOTPURI
		if uri == "" {
			uri = secret.Password // pass-otp can keep the URI on the first line.
		}
		entries[i].TOTPPeriod = totpPeriod(uri)
	}
	return entries, nil
}

func totpPeriod(uri string) uint64 {
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		return 0
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		return 0
	}
	value := parsed.Query().Get("period")
	if value == "" {
		return 30
	}
	period, err := strconv.ParseUint(value, 10, 64)
	if err != nil || period < 1 || period > 3600 {
		return 0
	}
	return period
}
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
func (v *Vault) readContent(id string) (string, string, error) {
	file, err := v.existingFile(id)
	if err != nil {
		return "", "", err
	}
	before, err := hashFile(file)
	if err != nil {
		return "", "", err
	}
	cmd := exec.Command("pass", "show", id)
	cmd.Env = append(os.Environ(), "PASSWORD_STORE_DIR="+v.root)
	out, err := cmd.Output()
	if err != nil {
		return "", "", errors.New("Could not open the entry. Check the GPG key and gpg-agent")
	}
	after, err := hashFile(file)
	if err != nil {
		return "", "", err
	}
	if after != before {
		return "", "", errors.New("The entry changed while being read. Try again")
	}
	if !utf8Valid(out) {
		return "", "", errors.New("Entry does not contain UTF-8 text")
	}
	return string(out), before, nil
}
func utf8Valid(b []byte) bool { return utf8.Valid(b) }
func (v *Vault) Read(id string) (Secret, error) {
	content, hash, err := v.readContent(id)
	if err != nil {
		return Secret{}, err
	}
	secret := ParseSecret(content)
	secret.CiphertextHash = hash
	return secret, nil
}
func ParseSecret(content string) Secret {
	password, details, _ := strings.Cut(content, "\n")
	result := Secret{Password: password, Details: strings.TrimRightFunc(details, unicode.IsSpace), URLs: []string{}}
	var other strings.Builder
	loginSeen := false
	for _, segment := range splitInclusive(details) {
		line := strings.TrimSuffix(segment, "\n")
		if strings.HasPrefix(strings.TrimSpace(line), "otpauth://") && result.TOTPURI == "" {
			result.TOTPURI = strings.TrimSpace(line)
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		isField := false
		if ok {
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "passport-favorite":
				result.Favorite = strings.EqualFold(strings.TrimSpace(value), "true")
				isField = true
			case "passport-archived":
				result.Archived = strings.EqualFold(strings.TrimSpace(value), "true")
				isField = true
			case "login", "username":
				if !loginSeen {
					loginSeen = true
					value = strings.TrimSpace(value)
					if value != "" {
						result.Username = &value
					}
					isField = true
				}
			case "url":
				value = strings.TrimSpace(value)
				if value != "" {
					result.URLs = append(result.URLs, value)
				}
				isField = true
			case "otpauth":
				if strings.HasPrefix(strings.TrimSpace(value), "otpauth://") && result.TOTPURI == "" {
					result.TOTPURI = strings.TrimSpace(value)
					isField = true
				}
			}
		}
		if !isField {
			other.WriteString(segment)
		}
	}
	result.OtherDetails = other.String()
	return result
}
func splitInclusive(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.SplitAfter(s, "\n")
	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}
func setFlag(content, key string, enabled bool) string {
	password, details, _ := strings.Cut(content, "\n")
	var out strings.Builder
	out.WriteString(password + "\n")
	for _, segment := range splitInclusive(details) {
		field, _, ok := strings.Cut(strings.TrimSuffix(segment, "\n"), ":")
		if ok && strings.EqualFold(strings.TrimSpace(field), key) {
			continue
		}
		out.WriteString(segment)
	}
	if enabled {
		if !strings.HasSuffix(out.String(), "\n") {
			out.WriteByte('\n')
		}
		out.WriteString(key + ": true\n")
	}
	return out.String()
}
func compose(password, username, siteURL, details string) (string, error) {
	urls := []string{}
	if strings.TrimSpace(siteURL) != "" {
		urls = append(urls, siteURL)
	}
	return composeFields(password, username, urls, "", details)
}
func composeFields(password, username string, urls []string, totpURI, details string) (string, error) {
	if password == "" || len(password) > 16384 || strings.ContainsAny(password, "\r\n\x00") {
		return "", errors.New("Invalid entry password")
	}
	if len(username) > 4096 || strings.ContainsAny(username, "\r\n\x00") {
		return "", errors.New("Invalid entry login")
	}
	if len(urls) > 32 {
		return "", errors.New("Too many entry URLs")
	}
	for _, siteURL := range urls {
		if len(siteURL) > 4096 || strings.ContainsAny(siteURL, "\r\n\x00") {
			return "", errors.New("Invalid entry URL")
		}
		parsed, err := url.Parse(strings.TrimSpace(siteURL))
		if err != nil || parsed.User != nil || parsed.Opaque != "" {
			return "", errors.New("Use a valid HTTP(S) URL or androidapp:// package URI")
		}
		if parsed.Scheme == "androidapp" {
			if parsed.Host != parsed.Hostname() || !androidPackage.MatchString(parsed.Host) || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
				return "", errors.New("Use androidapp:// followed by an Android package name")
			}
		} else if parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return "", errors.New("Use a valid HTTP(S) URL or androidapp:// package URI")
		}
	}
	if len(totpURI) > 8192 || strings.ContainsAny(totpURI, "\r\n\x00") || (totpURI != "" && !strings.HasPrefix(totpURI, "otpauth://totp/")) {
		return "", errors.New("Invalid authenticator key")
	}
	if len(details) > 1048576 || strings.ContainsRune(details, '\x00') {
		return "", errors.New("Invalid extra entry fields")
	}
	var out strings.Builder
	out.WriteString(password + "\n")
	if strings.TrimSpace(username) != "" {
		out.WriteString("login: " + strings.TrimSpace(username) + "\n")
	}
	for _, siteURL := range urls {
		out.WriteString("url: " + strings.TrimSpace(siteURL) + "\n")
	}
	if totpURI != "" {
		out.WriteString("otpauth: " + totpURI + "\n")
	}
	if details != "" {
		out.WriteString(details)
		if !strings.HasSuffix(details, "\n") {
			out.WriteByte('\n')
		}
	}
	return out.String(), nil
}
func replaceKnown(original, password, username, siteURL string) (string, error) {
	if _, err := compose(password, username, siteURL, ""); err != nil {
		return "", err
	}
	_, details, _ := strings.Cut(original, "\n")
	var body strings.Builder
	loginSeen := false
	urlSeen := false
	for _, segment := range splitInclusive(details) {
		line := strings.TrimSuffix(segment, "\n")
		key, _, ok := strings.Cut(line, ":")
		switch {
		case ok && !loginSeen && (strings.EqualFold(strings.TrimSpace(key), "login") || strings.EqualFold(strings.TrimSpace(key), "username")):
			loginSeen = true
			if strings.TrimSpace(username) != "" {
				body.WriteString("login: " + strings.TrimSpace(username) + "\n")
			}
		case ok && !urlSeen && strings.EqualFold(strings.TrimSpace(key), "url"):
			urlSeen = true
			if strings.TrimSpace(siteURL) != "" {
				body.WriteString("url: " + strings.TrimSpace(siteURL) + "\n")
			}
		default:
			body.WriteString(segment)
		}
	}
	var out strings.Builder
	out.WriteString(password + "\n")
	if !loginSeen && strings.TrimSpace(username) != "" {
		out.WriteString("login: " + strings.TrimSpace(username) + "\n")
	}
	if !urlSeen && strings.TrimSpace(siteURL) != "" {
		out.WriteString("url: " + strings.TrimSpace(siteURL) + "\n")
	}
	out.WriteString(body.String())
	return out.String(), nil
}
func (v *Vault) insert(id, content string) error {
	if content == "" || strings.ContainsRune(content, '\x00') {
		return errors.New("Invalid entry content")
	}
	cmd := exec.Command("pass", "insert", "-m", "-f", id)
	cmd.Env = append(os.Environ(), "PASSWORD_STORE_DIR="+v.root)
	cmd.Stdin = strings.NewReader(content)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		if saved, _, readErr := v.readContent(id); readErr == nil && saved == content {
			return nil // Encryption succeeded; a later Git commit can be retried.
		}
		return errors.New("Unable to save entry. Check GPG key")
	}
	return nil
}

// insertUncommitted lets pass select the correct recipients and encrypt in a
// disposable store, then atomically replaces only the ciphertext in the vault.
// Running pass inside the real Git worktree would create one commit per flag.
func (v *Vault) insertUncommitted(id, content, expectedHash string) error {
	target, err := v.existingFile(id)
	if err != nil {
		return err
	}
	shadow, err := os.MkdirTemp("", "passport-entry-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(shadow)
	relativeDir := filepath.Dir(filepath.FromSlash(id))
	shadowDir := filepath.Join(shadow, relativeDir)
	if err := os.MkdirAll(shadowDir, 0700); err != nil {
		return err
	}
	// Copy the nearest recipient file into the matching shadow directory.
	recipientDir := filepath.Dir(target)
	for {
		recipients := filepath.Join(recipientDir, ".gpg-id")
		if info, err := os.Lstat(recipients); err == nil && info.Mode().IsRegular() {
			for _, suffix := range []string{"", ".sig"} {
				if suffix == ".sig" {
					signature, statErr := os.Lstat(recipients + suffix)
					if errors.Is(statErr, os.ErrNotExist) {
						continue
					}
					if statErr != nil {
						return statErr
					}
					if !signature.Mode().IsRegular() {
						return errors.New("Vault recipient signature is not a regular file")
					}
				}
				data, err := os.ReadFile(recipients + suffix)
				if err != nil {
					return err
				}
				if err := os.WriteFile(filepath.Join(shadowDir, ".gpg-id"+suffix), data, 0600); err != nil {
					return err
				}
			}
			break
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if recipientDir == v.root {
			return errors.New("Vault recipients not found")
		}
		recipientDir = filepath.Dir(recipientDir)
	}
	cmd := exec.Command("pass", "insert", "-m", "-f", id)
	cmd.Env = append(os.Environ(), "PASSWORD_STORE_DIR="+shadow)
	cmd.Stdin = strings.NewReader(content)
	if err := cmd.Run(); err != nil {
		return errors.New("Unable to save entry. Check GPG key")
	}
	encrypted, err := os.ReadFile(filepath.Join(shadow, filepath.FromSlash(id)+".gpg"))
	if err != nil {
		return err
	}
	tempDir := filepath.Dir(target)
	gitDir := filepath.Join(v.root, ".git")
	if info, err := os.Stat(gitDir); err == nil && info.IsDir() {
		tempDir = gitDir
	}
	temp, err := os.CreateTemp(tempDir, ".passport-entry-")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(encrypted); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := v.checkHash(id, expectedHash); err != nil {
		return err
	}
	return os.Rename(temp.Name(), target)
}
func (v *Vault) Create(id, content string) error {
	target, err := v.safeTarget(id)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(target); err == nil {
		return errors.New("The entry already exists")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return v.insert(id, content)
}
func (v *Vault) CreateLogin(id, password, username, siteURL, details string) (Secret, error) {
	content, err := compose(password, username, siteURL, details)
	if err != nil {
		return Secret{}, err
	}
	if err = v.Create(id, content); err != nil {
		return Secret{}, err
	}
	secret, err := v.Read(id)
	if err != nil {
		return Secret{}, fmt.Errorf("Entry created but could not be reopened: %w", err)
	}
	return secret, nil
}
func (v *Vault) CreateLoginFields(id, password, username string, urls []string, totpURI, details string) (Secret, error) {
	content, err := composeFields(password, username, urls, totpURI, details)
	if err != nil {
		return Secret{}, err
	}
	if err := v.Create(id, content); err != nil {
		return Secret{}, err
	}
	return v.Read(id)
}
func (v *Vault) checkHash(id, expected string) error {
	file, err := v.existingFile(id)
	if err != nil {
		return err
	}
	if len(expected) != 64 {
		return errors.New("Invalid entry version")
	}
	if _, err = hex.DecodeString(expected); err != nil {
		return errors.New("Invalid entry version")
	}
	current, err := hashFile(file)
	if err != nil {
		return err
	}
	if current != expected {
		return errors.New("The entry changed. Refresh before saving")
	}
	return nil
}
func (v *Vault) Update(id, content, expectedHash string) error {
	if err := v.checkHash(id, expectedHash); err != nil {
		return err
	}
	return v.insert(id, content)
}
func (v *Vault) UpdateLogin(id, password, username, siteURL, details, expectedHash string) (Secret, error) {
	original, current, err := v.readContent(id)
	if err != nil {
		return Secret{}, err
	}
	if current != expectedHash {
		return Secret{}, errors.New("The entry changed. Refresh before saving")
	}
	var content string
	if details == ParseSecret(original).OtherDetails {
		content, err = replaceKnown(original, password, username, siteURL)
	} else {
		content, err = compose(password, username, siteURL, details)
	}
	if err != nil {
		return Secret{}, err
	}
	flags := ParseSecret(original)
	content = setFlag(setFlag(content, "passport-favorite", flags.Favorite), "passport-archived", flags.Archived)
	if err = v.Update(id, content, expectedHash); err != nil {
		return Secret{}, err
	}
	secret, err := v.Read(id)
	if err != nil {
		return Secret{}, fmt.Errorf("Entry updated but unable to reopen: %w", err)
	}
	return secret, nil
}
func (v *Vault) UpdateLoginFields(id, password, username string, urls []string, totpURI, details, expectedHash string) (Secret, error) {
	original, current, err := v.readContent(id)
	if err != nil {
		return Secret{}, err
	}
	if current != expectedHash {
		return Secret{}, errors.New("The entry changed. Refresh before saving")
	}
	content, err := composeFields(password, username, urls, totpURI, details)
	if err != nil {
		return Secret{}, err
	}
	flags := ParseSecret(original)
	content = setFlag(setFlag(content, "passport-favorite", flags.Favorite), "passport-archived", flags.Archived)
	if err := v.Update(id, content, expectedHash); err != nil {
		return Secret{}, err
	}
	return v.Read(id)
}
func (v *Vault) SetFlag(id, flag string, enabled bool, expectedHash string) (Secret, error) {
	if flag != "favorite" && flag != "archived" {
		return Secret{}, errors.New("Invalid entry flag")
	}
	content, hash, err := v.readContent(id)
	if err != nil {
		return Secret{}, err
	}
	if hash != expectedHash {
		return Secret{}, errors.New("The entry changed. Refresh before saving")
	}
	updated := setFlag(content, "passport-"+flag, enabled)
	if updated == content {
		return v.Read(id)
	}
	if err := v.checkHash(id, expectedHash); err != nil {
		return Secret{}, err
	}
	if err := v.insertUncommitted(id, updated, expectedHash); err != nil {
		return Secret{}, err
	}
	return v.Read(id)
}
func (v *Vault) Remove(id, expectedHash string) error {
	if err := v.checkHash(id, expectedHash); err != nil {
		return err
	}
	cmd := exec.Command("pass", "rm", "-f", id)
	cmd.Env = append(os.Environ(), "PASSWORD_STORE_DIR="+v.root)
	if err := cmd.Run(); err != nil {
		if target, targetErr := v.safeTarget(id); targetErr == nil {
			if _, statErr := os.Lstat(target); errors.Is(statErr, os.ErrNotExist) {
				return nil // The file was removed; only Git recording failed.
			}
		}
		return errors.New("pass operation failed")
	}
	return nil
}

// Rename moves an entry with `pass mv`, which re-encrypts it when the new
// folder has other recipients and commits when the vault uses Git. The new
// name must be free, and the entry must still match expectedHash.
func (v *Vault) Rename(id, newID, expectedHash string) error {
	if id == newID {
		return nil
	}
	target, err := v.safeTarget(newID)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(target); err == nil {
		return errors.New("An entry with that name already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := v.checkHash(id, expectedHash); err != nil {
		return err
	}
	cmd := exec.Command("pass", "mv", "--", id, newID)
	cmd.Env = append(os.Environ(), "PASSWORD_STORE_DIR="+v.root)
	if err := cmd.Run(); err != nil {
		if _, oldErr := v.existingFile(id); oldErr != nil {
			if _, newErr := v.Read(newID); newErr == nil {
				return nil // The move succeeded; Git recording can be retried.
			}
		}
		return errors.New("Unable to rename the entry")
	}
	if _, err := v.existingFile(newID); err != nil {
		return errors.New("pass did not move the entry")
	}
	return nil
}
