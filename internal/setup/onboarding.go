package setup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/plu-nz/mono.passport/internal/ghauth"
	"github.com/plu-nz/mono.passport/internal/gitvault"
	"github.com/plu-nz/mono.passport/internal/gpgkey"
	"github.com/plu-nz/mono.passport/internal/recovery"
)

// Onboarding steps, reported in order through Progress so the UI can tick them off.
const (
	StepKey        = "key"
	StepVault      = "vault"
	StepRepository = "repository"
	StepPublish    = "publish"
	StepClone      = "clone"
	StepRecovery   = "recovery"
	StepImport     = "import"
	StepUnlock     = "unlock"
)

// Progress receives the step about to run.
type Progress func(step string)

// MinPasswordLength is the floor enforced in Go; the UI also shows a strength meter.
const MinPasswordLength = 12

// RepoName is the default name of the private vault repository.
const RepoName = ".passport"

// VaultTopic marks a repository as a Passport vault, so restore finds it
// whatever its name.
const VaultTopic = "passport-vault"

// onboardingState is saved after each completed step, never with secrets, so
// an interrupted create or restore resumes instead of starting over.
type onboardingState struct {
	Mode        string `json:"mode"`
	Path        string `json:"path"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Repo        string `json:"repo,omitempty"`
	CloneURL    string `json:"cloneUrl,omitempty"`
}

// PasswordPolicy checks a new master password.
func PasswordPolicy(password []byte) error {
	if err := gpgkey.CheckPassword(password); err != nil {
		return err
	}
	if utf8.RuneCount(password) < MinPasswordLength {
		return fmt.Errorf("Use at least %d characters", MinPasswordLength)
	}
	return nil
}

// DefaultVaultPath is where GNU pass looks without PASSWORD_STORE_DIR.
func DefaultVaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("HOME is not defined")
	}
	return filepath.Join(home, ".password-store"), nil
}

func readState() (settings, error) {
	config, err := settingsPath()
	if err != nil {
		return settings{}, err
	}
	return readSettings(config)
}

func saveState(state *onboardingState) error {
	return updateSettings(func(s *settings) { s.Onboarding = state })
}

// OnboardingPending reports an interrupted create or restore ("create" or "restore").
func OnboardingPending() (string, error) {
	s, err := readState()
	if err != nil || s.Onboarding == nil {
		return "", err
	}
	return s.Onboarding.Mode, nil
}

// AbandonOnboarding forgets an interrupted attempt. Files, keys and the
// repository already created are left in place.
func AbandonOnboarding() error { return saveState(nil) }

// AutoSync reports whether Passport syncs the vault on its own.
func AutoSync() (bool, error) {
	s, err := readState()
	return s.AutoSync, err
}

// SetAutoSync turns automatic sync on or off.
func SetAutoSync(on bool) error { return updateSettings(func(s *settings) { s.AutoSync = on }) }

// GitHubRepo is the "owner/name" of the vault repository Passport manages, if any.
func GitHubRepo() (string, error) {
	s, err := readState()
	return s.GitHubRepo, err
}

func finish(path, repo string) error {
	return updateSettings(func(s *settings) {
		s.VaultPath = path
		s.GitHubRepo = repo
		s.AutoSync = true
		s.Onboarding = nil
	})
}

// hasSecretKey reports whether this computer holds the private key fingerprint.
func hasSecretKey(fingerprint string) bool {
	return exec.Command("gpg", "--batch", "--list-secret-keys", "--", fingerprint).Run() == nil
}

func passInit(path, fingerprint string) error {
	cmd := exec.Command("pass", "init", fingerprint)
	cmd.Env = append(os.Environ(), "PASSWORD_STORE_DIR="+path, "GIT_TERMINAL_PROMPT=0")
	if err := cmd.Run(); err != nil {
		return errors.New("Unable to create vault. Check GPG and permissions")
	}
	if !IsInitialized(path) {
		return errors.New("GNU pass did not create .gpg-id")
	}
	return nil
}

func recipients(path string) []string {
	data, _ := os.ReadFile(filepath.Join(path, ".gpg-id"))
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// CreateWithGitHub creates a key protected by the master password, a pass
// vault at the default path, a private GitHub repository holding it, and the
// sealed recovery copy, then unlocks the key. exe is the Passport executable
// Git will call for credentials.
//
// repoName chooses the repository; empty means RepoName, trying RepoName-2 …
// when it is taken. A chosen name is used as is.
func CreateWithGitHub(ctx context.Context, client *ghauth.Client, account ghauth.Account, password []byte, repoName, exe string, progress Progress) (VaultInfo, error) {
	repoName = strings.TrimSpace(repoName)
	if repoName != "" && !ghauth.ValidRepoName(repoName) {
		return VaultInfo{}, errors.New("Use only letters, digits, dots, hyphens and underscores in the repository name")
	}
	if err := allowed(); err != nil {
		return VaultInfo{}, err
	}
	if err := PasswordPolicy(password); err != nil {
		return VaultInfo{}, err
	}
	if !available("gpg") || !available("pass") || !available("git") {
		return VaultInfo{}, errors.New("GNU pass, GPG and Git must be installed")
	}
	s, err := readState()
	if err != nil {
		return VaultInfo{}, err
	}
	state := s.Onboarding
	if state == nil || state.Mode != "create" {
		path, err := DefaultVaultPath()
		if err != nil {
			return VaultInfo{}, err
		}
		if IsInitialized(path) {
			return VaultInfo{}, fmt.Errorf("A vault already exists at %s. Open it in Settings > Advanced", path)
		}
		if err := validateNewPath(path); err != nil {
			return VaultInfo{}, fmt.Errorf("%s is not empty. Move it away or use Settings > Advanced", path)
		}
		state = &onboardingState{Mode: "create", Path: path}
	}
	user := account.User()

	progress(StepKey)
	if state.Fingerprint != "" && hasSecretKey(state.Fingerprint) {
		// A key from an interrupted attempt is reused, so it must open with this password.
		if err := gpgkey.Unlock(state.Fingerprint, password); errors.Is(err, gpgkey.ErrBadPassphrase) {
			return VaultInfo{}, errors.New("Use the same master password as in the interrupted attempt")
		} else if err != nil {
			return VaultInfo{}, err
		}
	} else {
		fp, err := gpgkey.Generate(user.DisplayName()+" <"+user.NoreplyEmail()+">", password)
		if err != nil {
			return VaultInfo{}, err
		}
		state.Fingerprint = fp
		if err := saveState(state); err != nil {
			return VaultInfo{}, err
		}
	}

	progress(StepVault)
	if !IsInitialized(state.Path) {
		if err := validateNewPath(state.Path); err != nil {
			return VaultInfo{}, err
		}
		if err := passInit(state.Path, state.Fingerprint); err != nil {
			return VaultInfo{}, err
		}
	} else if ids := recipients(state.Path); len(ids) != 1 || !strings.EqualFold(ids[0], state.Fingerprint) {
		return VaultInfo{}, fmt.Errorf("%s holds another vault. Move it away or use Settings > Advanced", state.Path)
	}
	if _, err := os.Stat(filepath.Join(state.Path, ".git")); errors.Is(err, os.ErrNotExist) {
		if _, err := gitvault.Initialize(state.Path); err != nil {
			return VaultInfo{}, err
		}
	}
	git, err := gitvault.Open(state.Path)
	if err != nil {
		return VaultInfo{}, err
	}
	if err := git.ConfigurePassport(exe, user.DisplayName(), user.NoreplyEmail()); err != nil {
		return VaultInfo{}, err
	}

	progress(StepRepository)
	if state.Repo == "" {
		repo, err := createRepo(ctx, client, account.Token, repoName)
		if err != nil {
			return VaultInfo{}, err
		}
		state.Repo, state.CloneURL = repo.FullName, repo.CloneURL
		if err := saveState(state); err != nil {
			return VaultInfo{}, err
		}
	}

	progress(StepPublish)
	status, err := git.Status()
	if err != nil {
		return VaultInfo{}, err
	}
	if status.Upstream == nil {
		if origin, ok := git.OriginURL(); !ok {
			if _, err := git.SetRemote(state.CloneURL); err != nil {
				return VaultInfo{}, err
			}
		} else if origin != state.CloneURL {
			return VaultInfo{}, errors.New("This vault already points to another remote. Use Settings > Advanced")
		}
		if _, err := git.PublishNewVault(); err != nil {
			return VaultInfo{}, err
		}
	}

	progress(StepRecovery)
	armored, err := gpgkey.ExportSecret(state.Fingerprint, password)
	if err != nil {
		return VaultInfo{}, err
	}
	sealed, err := recovery.Seal(password, strings.ToUpper(state.Fingerprint), armored)
	clear(armored)
	if err != nil {
		return VaultInfo{}, err
	}
	if err := git.PublishRecovery(sealed); err != nil {
		return VaultInfo{}, err
	}

	progress(StepUnlock)
	if err := gpgkey.Unlock(state.Fingerprint, password); err != nil {
		return VaultInfo{}, err
	}
	if err := finish(state.Path, state.Repo); err != nil {
		return VaultInfo{}, err
	}
	return VaultInfoCurrent()
}

// createRepo creates the chosen name, or tries .passport, then .passport-2 …
// -9, and tags the repository with VaultTopic.
func createRepo(ctx context.Context, client *ghauth.Client, token, chosen string) (ghauth.Repo, error) {
	repo, err := createRepoNamed(ctx, client, token, chosen)
	if err != nil {
		return repo, err
	}
	// Without the topic, restore still finds names containing "passport".
	client.SetTopics(ctx, token, repo.FullName, []string{VaultTopic})
	return repo, nil
}

func createRepoNamed(ctx context.Context, client *ghauth.Client, token, chosen string) (ghauth.Repo, error) {
	const description = "Passport vault: entries encrypted with GPG, compatible with pass"
	if chosen != "" {
		repo, err := client.CreatePrivateRepo(ctx, token, chosen, description)
		if errors.Is(err, ghauth.ErrRepoExists) {
			return repo, fmt.Errorf("A repository named %s already exists on GitHub. Choose another name", chosen)
		}
		return repo, err
	}
	for i := 1; i <= 9; i++ {
		name := RepoName
		if i > 1 {
			name = fmt.Sprintf("%s-%d", RepoName, i)
		}
		repo, err := client.CreatePrivateRepo(ctx, token, name, description)
		if errors.Is(err, ghauth.ErrRepoExists) {
			continue
		}
		return repo, err
	}
	return ghauth.Repo{}, errors.New("Unable to find a free repository name. Rename an old .passport repository on GitHub")
}

// FindGitHubVaults lists the account's private repositories that hold a
// Passport recovery copy. Only repositories tagged VaultTopic or named with
// "passport" are checked, so the lookup stays a handful of requests.
func FindGitHubVaults(ctx context.Context, client *ghauth.Client, token string) ([]ghauth.Repo, error) {
	repos, err := client.OwnedRepos(ctx, token)
	if err != nil {
		return nil, err
	}
	found := []ghauth.Repo{}
	for _, repo := range repos {
		if !repo.Private || !(slices.Contains(repo.Topics, VaultTopic) || strings.Contains(strings.ToLower(repo.Name), "passport")) {
			continue
		}
		ok, err := client.HasBranch(ctx, token, repo.FullName, gitvault.RecoveryBranch)
		if err != nil {
			return nil, err
		}
		if ok {
			found = append(found, repo)
		}
	}
	return found, nil
}

// RestoreFromGitHub clones a vault repository to the default path, opens the
// recovery copy with the master password, imports the key and unlocks it.
func RestoreFromGitHub(ctx context.Context, account ghauth.Account, repo ghauth.Repo, password []byte, exe string, progress Progress) (VaultInfo, error) {
	if err := allowed(); err != nil {
		return VaultInfo{}, err
	}
	if err := gpgkey.CheckPassword(password); err != nil {
		return VaultInfo{}, err
	}
	if !available("gpg") || !available("pass") || !available("git") {
		return VaultInfo{}, errors.New("GNU pass, GPG and Git must be installed")
	}
	if !strings.HasPrefix(repo.CloneURL, "https://github.com/") || strings.ContainsAny(repo.CloneURL, "\r\n\x00 ") {
		return VaultInfo{}, errors.New("Invalid repository")
	}
	s, err := readState()
	if err != nil {
		return VaultInfo{}, err
	}
	state := s.Onboarding
	if state == nil || state.Mode != "restore" || state.CloneURL != repo.CloneURL {
		path, err := DefaultVaultPath()
		if err != nil {
			return VaultInfo{}, err
		}
		if IsInitialized(path) {
			return VaultInfo{}, fmt.Errorf("A vault already exists at %s. Open it in Settings > Advanced", path)
		}
		if err := validateNewPath(path); err != nil {
			return VaultInfo{}, fmt.Errorf("%s is not empty. Move it away or use Settings > Advanced", path)
		}
		state = &onboardingState{Mode: "restore", Path: path, Repo: repo.FullName, CloneURL: repo.CloneURL}
		if err := saveState(state); err != nil {
			return VaultInfo{}, err
		}
	}
	user := account.User()

	progress(StepClone)
	if !IsInitialized(state.Path) {
		if err := validateNewPath(state.Path); err != nil {
			return VaultInfo{}, err
		}
		helper := gitvault.HelperCommand(exe)
		cmd := exec.CommandContext(ctx, "git", "-c", "credential.https://github.com.helper=", "-c", "credential.https://github.com.helper="+helper, "clone", "--no-tags", "--single-branch", "--branch", "main", "--", state.CloneURL, state.Path)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false")
		if err := cmd.Run(); err != nil {
			return VaultInfo{}, errors.New("Unable to download the vault from GitHub. Check your connection and try again")
		}
		if !IsInitialized(state.Path) {
			return VaultInfo{}, errors.New("This repository is not a pass vault (.gpg-id missing)")
		}
	}
	git, err := gitvault.Open(state.Path)
	if err != nil {
		return VaultInfo{}, err
	}
	if err := git.ConfigurePassport(exe, user.DisplayName(), user.NoreplyEmail()); err != nil {
		return VaultInfo{}, err
	}

	progress(StepRecovery)
	sealed, err := git.FetchRecovery()
	if err != nil {
		return VaultInfo{}, err
	}
	armored, fingerprint, err := recovery.Open(password, sealed)
	if errors.Is(err, recovery.ErrWrongPassword) {
		return VaultInfo{}, gpgkey.ErrBadPassphrase
	}
	if err != nil {
		return VaultInfo{}, err
	}
	defer clear(armored)
	listed := false
	for _, id := range recipients(state.Path) {
		listed = listed || strings.EqualFold(id, fingerprint)
	}
	if !listed {
		return VaultInfo{}, errors.New("The recovery copy does not belong to this vault")
	}

	progress(StepImport)
	if !hasSecretKey(fingerprint) {
		if err := gpgkey.Import(armored, fingerprint); err != nil {
			return VaultInfo{}, err
		}
	}

	progress(StepUnlock)
	if err := gpgkey.Unlock(fingerprint, password); err != nil {
		return VaultInfo{}, err
	}
	if err := finish(state.Path, state.Repo); err != nil {
		return VaultInfo{}, err
	}
	return VaultInfoCurrent()
}

// VaultFingerprint returns the fingerprint of the private key on this
// computer that opens the active vault.
func VaultFingerprint() (string, error) {
	path, _, err := ActiveVaultPath()
	if err != nil {
		return "", err
	}
	for _, id := range recipients(path) {
		out, err := exec.Command("gpg", "--batch", "--with-colons", "--list-secret-keys", "--", id).Output()
		if err != nil {
			continue
		}
		secret := false
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Split(line, ":")
			switch {
			case f[0] == "sec":
				secret = true
			case f[0] == "fpr" && secret && len(f) > 9 && gpgkey.ValidFingerprint(f[9]):
				return f[9], nil
			}
		}
	}
	return "", errors.New("The key that opens this vault is not on this computer")
}
