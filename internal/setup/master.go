package setup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/plu-nz/mono.passport/internal/gitvault"
	"github.com/plu-nz/mono.passport/internal/gpgkey"
	"github.com/plu-nz/mono.passport/internal/recovery"
)

func managedGit() (*gitvault.GitVault, bool, error) {
	repo, err := GitHubRepo()
	if err != nil || repo == "" {
		return nil, false, err
	}
	path, _, err := ActiveVaultPath()
	if err != nil {
		return nil, false, err
	}
	g, err := gitvault.Open(path)
	return g, err == nil, err
}

// publishRecovery seals the key under password and replaces the remote copy.
func publishRecovery(g *gitvault.GitVault, fingerprint string, password []byte) error {
	armored, err := gpgkey.ExportSecret(fingerprint, password)
	if err != nil {
		return err
	}
	defer clear(armored)
	sealed, err := recovery.Seal(password, strings.ToUpper(fingerprint), armored)
	if err != nil {
		return err
	}
	return g.PublishRecovery(sealed)
}

// ChangeMasterPassword re-protects the vault key and, for a vault Passport
// manages, replaces the recovery copy. If the new copy cannot be uploaded the
// change is undone, so the key and the copy never disagree.
func ChangeMasterPassword(old, new []byte) error {
	if err := PasswordPolicy(new); err != nil {
		return err
	}
	fp, err := VaultFingerprint()
	if err != nil {
		return err
	}
	if err := gpgkey.Unlock(fp, old); err != nil {
		return err
	}
	g, managed, err := managedGit()
	if err != nil {
		return err
	}
	if err := gpgkey.ChangePassphrase(fp, old, new); err != nil {
		return err
	}
	if managed {
		if err := publishRecovery(g, fp, new); err != nil {
			if undo := gpgkey.ChangePassphrase(fp, new, old); undo != nil {
				return errors.New("The new password works on this computer, but the recovery copy on GitHub still uses the old one. Change the password again when online")
			}
			return errors.New("Unable to update the recovery copy on GitHub. Your master password was not changed")
		}
	}
	return gpgkey.Unlock(fp, new)
}

// UnlockVault unlocks the vault key. When the password is wrong for the local
// key but opens the recovery copy, it was changed on another computer: the
// local key is replaced with the new copy and unlocked.
func UnlockVault(password []byte) error {
	fp, err := VaultFingerprint()
	if err != nil {
		return err
	}
	err = gpgkey.Unlock(fp, password)
	if !errors.Is(err, gpgkey.ErrBadPassphrase) {
		return err
	}
	g, managed, gerr := managedGit()
	if gerr != nil || !managed {
		return err
	}
	sealed, ferr := g.FetchRecovery()
	if ferr != nil {
		return err
	}
	armored, sealedFor, oerr := recovery.Open(password, sealed)
	if oerr != nil || !strings.EqualFold(sealedFor, fp) {
		return err
	}
	defer clear(armored)
	if err := gpgkey.Replace(armored, fp); err != nil {
		return err
	}
	return gpgkey.Unlock(fp, password)
}

// ExportKey writes the vault's private key, still protected by the master
// password, to path for use in other pass apps.
func ExportKey(password []byte, path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("Choose where to save the key")
	}
	fp, err := VaultFingerprint()
	if err != nil {
		return err
	}
	// With the passphrase cached, gpg would export without checking it.
	if err := gpgkey.Unlock(fp, password); err != nil {
		return err
	}
	armored, err := gpgkey.ExportSecret(fp, password)
	if err != nil {
		return err
	}
	defer clear(armored)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return errors.New("Unable to save the key there")
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(armored); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
