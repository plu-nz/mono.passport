package ghauth

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/zalando/go-keyring"
)

// Account is the signed-in GitHub account. Token never leaves Go.
type Account struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Token string `json:"token"`
	// Insecure is true when no Secret Service was available and the account
	// was saved to a file readable only by the user, as gh does.
	Insecure bool `json:"-"`
}

func (a Account) User() User { return User{Login: a.Login, ID: a.ID, Name: a.Name} }

const keyringService = "nz.plu.passport"
const keyringUser = "github.com"

// ErrSignedOut means no GitHub account is saved.
var ErrSignedOut = errors.New("Not signed in to GitHub")

func fallbackPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "passport", "github.json"), nil
}

// Save stores the account in Secret Service, or in a 0600 file when there is none.
func Save(a Account) (Account, error) {
	if a.Token == "" || a.Login == "" {
		return a, errors.New("Incomplete GitHub account")
	}
	data, err := json.Marshal(a)
	if err != nil {
		return a, err
	}
	path, err := fallbackPath()
	if err != nil {
		return a, err
	}
	if err := keyring.Set(keyringService, keyringUser, string(data)); err == nil {
		os.Remove(path)
		a.Insecure = false
		return a, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return a, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return a, err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return a, err
	}
	a.Insecure = true
	return a, nil
}

// Load returns the saved account or ErrSignedOut.
func Load() (Account, error) {
	var a Account
	secret, err := keyring.Get(keyringService, keyringUser)
	if err == nil {
		if json.Unmarshal([]byte(secret), &a) != nil || a.Token == "" {
			return Account{}, errors.New("Saved GitHub sign-in is damaged. Sign in again")
		}
		return a, nil
	}
	path, perr := fallbackPath()
	if perr != nil {
		return Account{}, perr
	}
	data, ferr := os.ReadFile(path)
	if errors.Is(ferr, os.ErrNotExist) {
		return Account{}, ErrSignedOut
	}
	if ferr != nil {
		return Account{}, ferr
	}
	if json.Unmarshal(data, &a) != nil || a.Token == "" {
		return Account{}, errors.New("Saved GitHub sign-in is damaged. Sign in again")
	}
	a.Insecure = true
	return a, nil
}

// Delete forgets the account locally. The authorization itself is revoked on
// GitHub, because revoking through the API needs the client secret.
func Delete() error {
	// Not found, or no Secret Service at all: either way nothing is left there.
	keyring.Delete(keyringService, keyringUser)
	path, err := fallbackPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// RevokeURL is where the user removes Passport's access on GitHub.
func RevokeURL() string {
	return "https://github.com/settings/connections/applications/" + ClientID
}

// CredentialHelper implements `passport git-credential <operation>`, a Git
// credential helper that answers only HTTPS requests for github.com with the
// saved token. Store and erase are ignored: the token is managed by Passport.
func CredentialHelper(args []string, in io.Reader, out io.Writer) int {
	if len(args) != 1 || args[0] != "get" {
		return 0
	}
	attributes := map[string]string{}
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		if key, value, ok := strings.Cut(line, "="); ok {
			attributes[key] = value
		}
	}
	if attributes["protocol"] != "https" || attributes["host"] != "github.com" {
		return 0
	}
	account, err := Load()
	if err != nil {
		return 0
	}
	if strings.ContainsAny(account.Token, "\r\n") {
		return 1
	}
	fmt.Fprintf(out, "username=x-access-token\npassword=%s\n", account.Token)
	return 0
}
