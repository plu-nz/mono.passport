package main

import (
	"errors"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"time"

	"github.com/plu-nz/mono.passport/internal/github"
	"github.com/plu-nz/mono.passport/internal/gitvault"
	"github.com/plu-nz/mono.passport/internal/otp"
	"github.com/plu-nz/mono.passport/internal/pairing"
	"github.com/plu-nz/mono.passport/internal/setup"
	"github.com/plu-nz/mono.passport/internal/vault"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// DesktopService exposes a fixed set of Passport actions to the embedded UI.
type DesktopService struct{}

type VaultState struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason,omitempty"`
}

func (*DesktopService) VaultState() VaultState {
	if pending, err := setup.OnboardingPending(); err == nil && pending != "" {
		return VaultState{Kind: "onboarding", Reason: pending}
	}
	if err := exec.Command("pass", "--version").Run(); err != nil {
		return VaultState{Kind: "unavailable", Reason: "GNU pass is not installed or is not in the PATH."}
	}
	v, err := vault.OpenEnv()
	if err != nil {
		return VaultState{Kind: "unavailable", Reason: err.Error()}
	}
	if !setup.IsInitialized(v.Root()) {
		return VaultState{Kind: "unavailable", Reason: "The directory is not yet initialized with GNU pass (.gpg-id missing)."}
	}
	return VaultState{Kind: "available"}
}

func (*DesktopService) VaultInfo() (setup.VaultInfo, error) { return setup.VaultInfoCurrent() }
func (*DesktopService) GPGKeys() []setup.GPGKey             { return setup.GPGKeys() }
func (*DesktopService) SelectVault(path string) (setup.VaultInfo, error) {
	return setup.SelectVault(path)
}
func (*DesktopService) CreateVault(path, keyID string) (setup.VaultInfo, error) {
	return setup.CreateVault(path, keyID)
}
func (*DesktopService) CreateKeyAndVault(path, name, email string) (setup.CreatedKeyVault, error) {
	return setup.CreateKeyAndVault(path, name, email)
}
func (*DesktopService) ListEntries() ([]vault.Entry, error) {
	v, err := vault.OpenEnv()
	if err != nil {
		return nil, err
	}
	return v.List()
}
func (*DesktopService) ReadEntry(id string) (vault.Secret, error) {
	v, err := vault.OpenEnv()
	if err != nil {
		return vault.Secret{}, err
	}
	return v.Read(id)
}
func (*DesktopService) CreateLoginEntry(id, password, username, url, details string) (vault.Secret, error) {
	vaultMutation.Lock()
	defer vaultMutation.Unlock()
	prepareImmediate()
	defer scheduleSync()
	v, err := vault.OpenEnv()
	if err != nil {
		return vault.Secret{}, err
	}
	return v.CreateLogin(id, password, username, url, details)
}
func (*DesktopService) CreateLoginFields(id, password, username string, urls []string, authenticator, details string) (vault.Secret, error) {
	vaultMutation.Lock()
	defer vaultMutation.Unlock()
	prepareImmediate()
	defer scheduleSync()
	v, err := vault.OpenEnv()
	if err != nil {
		return vault.Secret{}, err
	}
	uri, err := otp.Normalize(authenticator, id)
	if err != nil {
		return vault.Secret{}, err
	}
	return v.CreateLoginFields(id, password, username, urls, uri, details)
}
func (*DesktopService) UpdateLoginEntry(id, password, username, url, details, expectedHash string) (vault.Secret, error) {
	vaultMutation.Lock()
	defer vaultMutation.Unlock()
	prepareImmediate()
	defer scheduleSync()
	v, err := vault.OpenEnv()
	if err != nil {
		return vault.Secret{}, err
	}
	return v.UpdateLogin(id, password, username, url, details, expectedHash)
}
func (*DesktopService) UpdateLoginFields(id, password, username string, urls []string, authenticator, details, expectedHash string) (vault.Secret, error) {
	vaultMutation.Lock()
	defer vaultMutation.Unlock()
	prepareImmediate()
	defer scheduleSync()
	v, err := vault.OpenEnv()
	if err != nil {
		return vault.Secret{}, err
	}
	uri, err := otp.Normalize(authenticator, id)
	if err != nil {
		return vault.Secret{}, err
	}
	return v.UpdateLoginFields(id, password, username, urls, uri, details, expectedHash)
}
func (*DesktopService) SetEntryFlag(id, flag string, enabled bool, expectedHash string) (vault.Secret, error) {
	vaultMutation.Lock()
	defer vaultMutation.Unlock()
	v, err := vault.OpenEnv()
	if err != nil {
		return vault.Secret{}, err
	}
	if err := markPending(); err != nil {
		return vault.Secret{}, err
	}
	defer scheduleBatchSync()
	return v.SetFlag(id, flag, enabled, expectedHash)
}
func (*DesktopService) CreateEntry(id, content string) error {
	vaultMutation.Lock()
	defer vaultMutation.Unlock()
	prepareImmediate()
	defer scheduleSync()
	v, err := vault.OpenEnv()
	if err != nil {
		return err
	}
	if err := v.Create(id, content); err != nil {
		return err
	}
	return nil
}
func (*DesktopService) UpdateEntry(id, content, expectedHash string) error {
	vaultMutation.Lock()
	defer vaultMutation.Unlock()
	prepareImmediate()
	defer scheduleSync()
	v, err := vault.OpenEnv()
	if err != nil {
		return err
	}
	if err := v.Update(id, content, expectedHash); err != nil {
		return err
	}
	return nil
}

// RenameEntry moves an entry to a new name with pass mv.
func (*DesktopService) RenameEntry(id, newID, expectedHash string) error {
	vaultMutation.Lock()
	defer vaultMutation.Unlock()
	prepareImmediate()
	defer scheduleSync()
	v, err := vault.OpenEnv()
	if err != nil {
		return err
	}
	if err := v.Rename(id, newID, expectedHash); err != nil {
		return err
	}
	return nil
}
func (*DesktopService) RemoveEntry(id, expectedHash string) error {
	vaultMutation.Lock()
	defer vaultMutation.Unlock()
	prepareImmediate()
	defer scheduleSync()
	v, err := vault.OpenEnv()
	if err != nil {
		return err
	}
	if err := v.Remove(id, expectedHash); err != nil {
		return err
	}
	return nil
}

// OpenURL opens an entry's web address in the default browser. Only http and
// https links are opened, so an entry cannot launch other handlers.
func (*DesktopService) OpenURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("Only http and https links can be opened")
	}
	return application.Get().Browser.OpenURL(u.String())
}

func (*DesktopService) GenerateTOTP(id string) (otp.Code, error) {
	v, err := vault.OpenEnv()
	if err != nil {
		return otp.Code{}, err
	}
	secret, err := v.Read(id)
	if err != nil {
		return otp.Code{}, err
	}
	return otp.Generate(secret)
}
func (*DesktopService) PreviewTOTP(authenticator, label string) (otp.Code, error) {
	uri, err := otp.Normalize(authenticator, label)
	if err != nil {
		return otp.Code{}, err
	}
	if uri == "" {
		return otp.Code{}, errors.New("Enter an authenticator key")
	}
	return otp.CodeAt(uri, uint64(time.Now().Unix()))
}
func (*DesktopService) CloneVault(path, url string) (setup.VaultInfo, error) {
	return setup.CloneVault(path, url)
}
func (*DesktopService) GitInitialize() (gitvault.Status, error) {
	v, err := vault.OpenEnv()
	if err != nil {
		return gitvault.Status{}, err
	}
	return gitvault.Initialize(v.Root())
}
func (*DesktopService) GitStatus() (gitvault.Status, error) {
	g, err := openGit()
	if err != nil {
		return gitvault.Status{}, err
	}
	return g.Status()
}
func (*DesktopService) GitSetRemote(url string) (gitvault.Status, error) {
	g, err := openGit()
	if err != nil {
		return gitvault.Status{}, err
	}
	return g.SetRemote(url)
}
func (*DesktopService) GitPublishNewVault() (gitvault.Status, error) {
	vaultMutation.Lock()
	defer vaultMutation.Unlock()
	g, err := openGit()
	if err != nil {
		return gitvault.Status{}, err
	}
	status, err := g.PublishNewVault()
	if err == nil {
		_ = clearPendingMarker(g)
	}
	return status, err
}
func (*DesktopService) GitCommitChanges() (gitvault.Status, error) {
	vaultMutation.Lock()
	defer vaultMutation.Unlock()
	g, err := openGit()
	if err != nil {
		return gitvault.Status{}, err
	}
	if path, err := pendingMarker(g); err == nil {
		if _, err := os.Stat(path); err == nil {
			if err := flushPending(); err != nil {
				return gitvault.Status{}, err
			}
			return g.Status()
		}
	}
	return g.CommitChanges()
}
func (*DesktopService) GitMergePreservingBoth() (gitvault.Status, error) {
	vaultMutation.Lock()
	defer vaultMutation.Unlock()
	if err := flushPending(); err != nil {
		return gitvault.Status{}, err
	}
	g, err := openGit()
	if err != nil {
		return gitvault.Status{}, err
	}
	return g.MergePreservingBoth()
}
func (*DesktopService) GitPull() (gitvault.Status, error) {
	vaultMutation.Lock()
	defer vaultMutation.Unlock()
	if err := flushPending(); err != nil {
		return gitvault.Status{}, err
	}
	g, err := openGit()
	if err != nil {
		return gitvault.Status{}, err
	}
	if err := g.Pull(); err != nil {
		return gitvault.Status{}, err
	}
	return g.Status()
}
func (*DesktopService) GitPush() (gitvault.Status, error) {
	vaultMutation.Lock()
	defer vaultMutation.Unlock()
	if err := flushPending(); err != nil {
		return gitvault.Status{}, err
	}
	g, err := openGit()
	if err != nil {
		return gitvault.Status{}, err
	}
	if err := g.Push(); err != nil {
		return gitvault.Status{}, err
	}
	return g.Status()
}
func openGit() (*gitvault.GitVault, error) {
	v, err := vault.OpenEnv()
	if err != nil {
		return nil, err
	}
	return gitvault.Open(v.Root())
}

// RefreshSeconds is the entry list reload interval; 0 means off.
func (*DesktopService) RefreshSeconds() (int, error) { return setup.RefreshSeconds() }
func (*DesktopService) SetRefreshSeconds(seconds int) error {
	return setup.SetRefreshSeconds(seconds)
}

func (*DesktopService) GithubStatus() github.StatusInfo {
	v, _ := vault.OpenEnv()
	if v == nil {
		return github.Status("")
	}
	return github.Status(v.Root())
}
func (*DesktopService) GithubLogin() error { return github.StartLogin() }
func (*DesktopService) GithubConfigureVault() (github.StatusInfo, error) {
	v, err := vault.OpenEnv()
	if err != nil {
		return github.StatusInfo{}, err
	}
	return github.ConfigureVault(v.Root())
}

var pairingCode = regexp.MustCompile(`^[a-fA-F0-9]{12}$`)
var extensionOrigin = regexp.MustCompile(`^chrome-extension://[a-p]{32}/$`)

func (*DesktopService) ListPairings() ([]pairing.Pairing, error) {
	v, err := vault.OpenEnv()
	if err != nil {
		return nil, err
	}
	s, err := pairing.OpenDefault()
	if err != nil {
		return nil, err
	}
	return s.ListCurrent(v.Root())
}
func (*DesktopService) ApprovePairing(code string) error {
	if !pairingCode.MatchString(code) {
		return errors.New("Invalid pairing code")
	}
	s, err := pairing.OpenDefault()
	if err != nil {
		return err
	}
	_, err = s.Approve(code)
	return err
}
func (*DesktopService) RevokePairing(origin, installationID string) error {
	if !extensionOrigin.MatchString(origin) || installationID == "" || len(installationID) > 128 {
		return errors.New("Invalid pairing")
	}
	s, err := pairing.OpenDefault()
	if err != nil {
		return err
	}
	_, err = s.Revoke(origin, installationID)
	return err
}
func (*DesktopService) BrowserAccessState() (bool, error) {
	s, err := pairing.OpenDefault()
	if err != nil {
		return false, err
	}
	return s.Locked()
}
func (*DesktopService) LockBrowserAccess() error {
	s, err := pairing.OpenDefault()
	if err != nil {
		return err
	}
	return s.SetLocked(true)
}
func (*DesktopService) UnlockBrowserAccess() error {
	s, err := pairing.OpenDefault()
	if err != nil {
		return err
	}
	return s.SetLocked(false)
}
