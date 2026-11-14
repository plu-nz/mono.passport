package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/plu-nz/mono.passage/internal/ghauth"
	"github.com/plu-nz/mono.passage/internal/gitvault"
	"github.com/plu-nz/mono.passage/internal/gpgkey"
	"github.com/plu-nz/mono.passage/internal/setup"
	"github.com/plu-nz/mono.passage/internal/vault"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// onboardingEvent carries the step the create or restore flow is working on.
const onboardingEvent = "passage:onboarding-step"

// syncEvent carries a fresh SyncState whenever background sync changes it.
const syncEvent = "passage:sync"

var githubClient = ghauth.New()

// signIn holds the device flow in progress; the device code never reaches the UI.
var signIn struct {
	sync.Mutex
	device *ghauth.Device
	cancel context.CancelFunc
}

type GitHubAccount struct {
	SignedIn  bool   `json:"signedIn"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Insecure  bool   `json:"insecure"`
	RevokeURL string `json:"revokeUrl"`
}

func accountInfo(a ghauth.Account) GitHubAccount {
	return GitHubAccount{SignedIn: true, Login: a.Login, Name: a.Name, Insecure: a.Insecure, RevokeURL: ghauth.RevokeURL()}
}

// GitHubAccount returns the saved account, if any.
func (*DesktopService) GitHubAccount() (GitHubAccount, error) {
	a, err := ghauth.Load()
	if errors.Is(err, ghauth.ErrSignedOut) {
		return GitHubAccount{RevokeURL: ghauth.RevokeURL()}, nil
	}
	if err != nil {
		return GitHubAccount{}, err
	}
	return accountInfo(a), nil
}

// GitHubStartSignIn asks GitHub for a code and opens the verification page.
func (*DesktopService) GitHubStartSignIn() (*ghauth.Device, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	device, err := githubClient.StartDevice(ctx)
	if err != nil {
		return nil, err
	}
	signIn.Lock()
	if signIn.cancel != nil {
		signIn.cancel()
	}
	signIn.device, signIn.cancel = device, nil
	signIn.Unlock()
	return device, nil
}

// GitHubOpenVerification opens GitHub's code entry page in the browser.
func (*DesktopService) GitHubOpenVerification() error {
	signIn.Lock()
	device := signIn.device
	signIn.Unlock()
	if device == nil || !strings.HasPrefix(device.VerificationURI, "https://github.com/") {
		return errors.New("Start GitHub sign-in first")
	}
	return application.Get().Browser.OpenURL(device.VerificationURI)
}

// GitHubFinishSignIn waits until the user approves the code, then saves the account.
func (*DesktopService) GitHubFinishSignIn() (GitHubAccount, error) {
	signIn.Lock()
	device := signIn.device
	if device == nil {
		signIn.Unlock()
		return GitHubAccount{}, errors.New("Start GitHub sign-in first")
	}
	ctx, cancel := context.WithDeadline(context.Background(), device.Expires)
	signIn.cancel = cancel
	signIn.Unlock()
	defer cancel()
	token, err := githubClient.Wait(ctx, device)
	if errors.Is(err, context.Canceled) {
		return GitHubAccount{}, errors.New("GitHub sign-in was cancelled")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return GitHubAccount{}, ghauth.ErrExpired
	}
	if err != nil {
		return GitHubAccount{}, err
	}
	user, err := githubClient.User(ctx, token)
	if err != nil {
		return GitHubAccount{}, err
	}
	saved, err := ghauth.Save(ghauth.Account{Login: user.Login, ID: user.ID, Name: user.Name, Token: token})
	if err != nil {
		return GitHubAccount{}, err
	}
	signIn.Lock()
	signIn.device, signIn.cancel = nil, nil
	signIn.Unlock()
	return accountInfo(saved), nil
}

// GitHubCancelSignIn stops waiting for approval.
func (*DesktopService) GitHubCancelSignIn() { cancelSignIn() }

func cancelSignIn() {
	signIn.Lock()
	defer signIn.Unlock()
	if signIn.cancel != nil {
		signIn.cancel()
	}
	signIn.device, signIn.cancel = nil, nil
}

// GitHubSignOut forgets the account on this computer. Access is revoked on
// GitHub at GitHubAccount.RevokeURL.
func (*DesktopService) GitHubSignOut() error {
	cancelSignIn()
	return ghauth.Delete()
}

// OpenRevokePage opens GitHub's page for removing Passage's access.
func (*DesktopService) OpenRevokePage() error {
	return application.Get().Browser.OpenURL(ghauth.RevokeURL())
}

// FindGitHubVaults lists the account's repositories that hold a Passage vault.
func (*DesktopService) FindGitHubVaults() ([]ghauth.Repo, error) {
	a, err := ghauth.Load()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return setup.FindGitHubVaults(ctx, githubClient, a.Token)
}

type OnboardingStatus struct {
	// Pending is "create" or "restore" when an attempt was interrupted.
	Pending     string `json:"pending"`
	MinPassword int    `json:"minPassword"`
	VaultPath   string `json:"vaultPath"`
}

func (*DesktopService) OnboardingStatus() (OnboardingStatus, error) {
	pending, err := setup.OnboardingPending()
	if err != nil {
		return OnboardingStatus{}, err
	}
	path, _ := setup.DefaultVaultPath()
	return OnboardingStatus{Pending: pending, MinPassword: setup.MinPasswordLength, VaultPath: path}, nil
}

func (*DesktopService) AbandonOnboarding() error { return setup.AbandonOnboarding() }

// executable is the path Git will run for credentials. A development build
// lives in a temporary directory, so startup refreshes the helper path.
func executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

func emitStep(step string) {
	if app := application.Get(); app != nil {
		app.Event.Emit(onboardingEvent, step)
	}
}

// onboarding serialises create and restore: two at once would race on the
// same directory and key.
var onboarding sync.Mutex

func (*DesktopService) CreateVaultWithGitHub(password string) (setup.VaultInfo, error) {
	if !onboarding.TryLock() {
		return setup.VaultInfo{}, errors.New("Passage is already setting up a vault")
	}
	defer onboarding.Unlock()
	a, err := ghauth.Load()
	if err != nil {
		return setup.VaultInfo{}, err
	}
	exe, err := executable()
	if err != nil {
		return setup.VaultInfo{}, err
	}
	secret := []byte(password)
	defer clear(secret)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return setup.CreateWithGitHub(ctx, githubClient, a, secret, exe, emitStep)
}

func (*DesktopService) RestoreVaultFromGitHub(fullName, password string) (setup.VaultInfo, error) {
	if !onboarding.TryLock() {
		return setup.VaultInfo{}, errors.New("Passage is already setting up a vault")
	}
	defer onboarding.Unlock()
	a, err := ghauth.Load()
	if err != nil {
		return setup.VaultInfo{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	repos, err := setup.FindGitHubVaults(ctx, githubClient, a.Token)
	if err != nil {
		return setup.VaultInfo{}, err
	}
	var repo *ghauth.Repo
	for i := range repos {
		if repos[i].FullName == fullName {
			repo = &repos[i]
		}
	}
	if repo == nil {
		return setup.VaultInfo{}, errors.New("That repository has no Passage vault")
	}
	exe, err := executable()
	if err != nil {
		return setup.VaultInfo{}, err
	}
	secret := []byte(password)
	defer clear(secret)
	return setup.RestoreFromGitHub(ctx, a, *repo, secret, exe, emitStep)
}

// Unlock checks the master password and keeps the key unlocked in gpg-agent.
func (*DesktopService) Unlock(password string) error {
	fp, err := setup.VaultFingerprint()
	if err != nil {
		return err
	}
	secret := []byte(password)
	defer clear(secret)
	return gpgkey.Unlock(fp, secret)
}

// Lock forgets the master password in gpg-agent for the vault key only.
func (*DesktopService) Lock() error {
	fp, err := setup.VaultFingerprint()
	if err != nil {
		return err
	}
	return gpgkey.Lock(fp)
}

// KeyUnlocked reports whether the vault key can decrypt without a prompt.
func (*DesktopService) KeyUnlocked() (bool, error) {
	fp, err := setup.VaultFingerprint()
	if err != nil {
		return false, err
	}
	return gpgkey.Unlocked(fp)
}

// SyncState is what the UI shows in its sync indicator.
type SyncState struct {
	// State is "off", "syncing", "synced", "offline" or "attention".
	State   string    `json:"state"`
	Message string    `json:"message,omitempty"`
	At      time.Time `json:"at"`
}

var syncer struct {
	sync.Mutex
	state   SyncState
	running bool
	again   bool
	timer   *time.Timer
}

func (*DesktopService) SyncState() SyncState {
	syncer.Lock()
	defer syncer.Unlock()
	if on, _ := setup.AutoSync(); !on {
		return SyncState{State: "off"}
	}
	if syncer.state.State == "" {
		return SyncState{State: "synced"}
	}
	return syncer.state
}

func (*DesktopService) AutoSync() (bool, error)   { return setup.AutoSync() }
func (*DesktopService) SetAutoSync(on bool) error { return setup.SetAutoSync(on) }

// SyncNow runs a sync and returns its result; concurrent calls share one run.
func (s *DesktopService) SyncNow() SyncState {
	runSync()
	return s.SyncState()
}

// scheduleSync coalesces bursts of edits into one sync shortly after the last.
func scheduleSync() {
	if on, _ := setup.AutoSync(); !on {
		return
	}
	syncer.Lock()
	defer syncer.Unlock()
	if syncer.timer != nil {
		syncer.timer.Stop()
	}
	syncer.timer = time.AfterFunc(time.Second, runSync)
}

func setSyncState(state SyncState) {
	syncer.Lock()
	syncer.state = state
	syncer.Unlock()
	if app := application.Get(); app != nil {
		app.Event.Emit(syncEvent, state)
	}
}

func runSync() {
	if on, _ := setup.AutoSync(); !on {
		return
	}
	syncer.Lock()
	if syncer.running {
		syncer.again = true
		syncer.Unlock()
		return
	}
	syncer.running = true
	syncer.Unlock()
	for {
		setSyncState(SyncState{State: "syncing", At: time.Now()})
		setSyncState(syncOnce())
		syncer.Lock()
		if !syncer.again {
			syncer.running = false
			syncer.Unlock()
			return
		}
		syncer.again = false
		syncer.Unlock()
	}
}

func syncOnce() SyncState {
	now := time.Now()
	g, err := openGit()
	if err != nil {
		return SyncState{State: "attention", Message: err.Error(), At: now}
	}
	_, err = g.Sync()
	switch {
	case err == nil:
		return SyncState{State: "synced", At: now}
	case errors.Is(err, gitvault.ErrDiverged):
		return SyncState{State: "attention", Message: err.Error(), At: now}
	case strings.HasPrefix(err.Error(), "Unable to reach") || strings.HasPrefix(err.Error(), "Unable to send"):
		return SyncState{State: "offline", Message: err.Error(), At: now}
	}
	return SyncState{State: "attention", Message: err.Error(), At: now}
}

// refreshHelper keeps the vault's credential helper pointing at this
// executable after Passage moves (an update, or a development build).
func refreshHelper() {
	v, err := vault.OpenEnv()
	if err != nil {
		return
	}
	g, err := gitvault.Open(v.Root())
	if err != nil {
		return
	}
	current, ok := g.UsesPassageHelper()
	if !ok {
		return
	}
	exe, err := executable()
	if err != nil || current == gitvault.HelperCommand(exe) {
		return
	}
	a, err := ghauth.Load()
	if err != nil {
		return
	}
	g.ConfigurePassage(exe, a.User().DisplayName(), a.User().NoreplyEmail())
}
