package gitvault

import (
	"bytes"
	"errors"
	"os/exec"
	"strconv"
	"strings"
)

// RecoveryBranch holds the sealed private key, outside main so pass, browserpass
// and Android Password Store never see it. It always has a single commit, so
// changing the master password does not keep the old copy in its history.
const RecoveryBranch = "passport-recovery"

const recoveryFile = "recovery-key"
const recoveryRef = "refs/passport/recovery"
const maxRecoverySize = 1 << 20

// ErrDiverged means this computer and the remote both have new commits.
var ErrDiverged = errors.New("This computer and the remote both have new changes. Review them in Settings > Advanced")

// ErrNoRecovery means the remote has no recovery branch.
var ErrNoRecovery = errors.New("This repository has no Passport recovery copy")

func (g *GitVault) input(stdin []byte, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = g.root
	cmd.Env = gitEnv()
	cmd.Stdin = bytes.NewReader(stdin)
	out, err := cmd.Output()
	if err != nil {
		return "", errors.New("Git failed " + args[0])
	}
	return strings.TrimSpace(string(out)), nil
}

// shellQuote makes path safe inside the "!command" form Git runs through sh.
func shellQuote(path string) string {
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}

// HelperCommand is the credential.helper value that makes Git ask Passport
// (the executable at exe) for github.com credentials.
func HelperCommand(exe string) string { return "!" + shellQuote(exe) + " git-credential" }

// ConfigurePassport points this repository's github.com credentials at Passport
// and sets the commit identity, both only in the local .git/config.
func (g *GitVault) ConfigurePassport(exe, name, email string) error {
	if exe == "" || strings.ContainsAny(exe, "\r\n\x00") || strings.ContainsAny(name+email, "\r\n\x00") {
		return errors.New("Invalid Git configuration")
	}
	// An empty value first resets helpers inherited from the global config.
	steps := [][]string{
		{"config", "--local", "--replace-all", "credential.https://github.com.helper", ""},
		{"config", "--local", "--add", "credential.https://github.com.helper", HelperCommand(exe)},
		{"config", "--local", "user.name", name},
		{"config", "--local", "user.email", email},
	}
	for _, args := range steps {
		if _, err := g.output(args...); err != nil {
			return err
		}
	}
	return nil
}

// UsesPassportHelper reports whether the repository asks Passport for credentials,
// and through which executable.
func (g *GitVault) UsesPassportHelper() (string, bool) {
	out, ok := g.tryOutput("config", "--local", "--get-all", "credential.https://github.com.helper")
	if !ok {
		return "", false
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "!'") && strings.HasSuffix(line, "' git-credential") {
			return line, true
		}
	}
	return "", false
}

// OriginURL returns the URL of the origin remote, if there is one.
func (g *GitVault) OriginURL() (string, bool) {
	out, ok := g.tryOutput("remote", "get-url", "origin")
	return strings.TrimSpace(out), ok
}

func (g *GitVault) syncRemote() (string, error) {
	branch, err := g.output("symbolic-ref", "--quiet", "--short", "HEAD")
	if err == nil {
		if remote, err := g.remote(strings.TrimSpace(branch)); err == nil {
			return remote, nil
		}
	}
	if _, ok := g.tryOutput("remote", "get-url", "origin"); ok {
		return "origin", nil
	}
	return "", errors.New("This vault has no remote")
}

// PublishRecovery replaces the remote recovery branch with a single commit
// holding blob. It never touches the working tree or main.
func (g *GitVault) PublishRecovery(blob []byte) error {
	if len(blob) == 0 || len(blob) > maxRecoverySize {
		return errors.New("Invalid recovery copy")
	}
	remote, err := g.syncRemote()
	if err != nil {
		return err
	}
	object, err := g.input(blob, "hash-object", "-w", "--stdin")
	if err != nil {
		return err
	}
	tree, err := g.input([]byte("100644 blob "+object+"\t"+recoveryFile+"\n"), "mktree")
	if err != nil {
		return err
	}
	commit, err := g.input(nil, "commit-tree", tree, "-m", "Passport recovery copy")
	if err != nil {
		return errors.New("Git could not record the recovery copy. Check user.name and user.email")
	}
	if _, err := g.output("update-ref", recoveryRef, commit); err != nil {
		return err
	}
	_, err = g.output("push", "--force", remote, commit+":refs/heads/"+RecoveryBranch)
	return err
}

// FetchRecovery downloads the recovery branch and returns the sealed key.
func (g *GitVault) FetchRecovery() ([]byte, error) {
	remote, err := g.syncRemote()
	if err != nil {
		return nil, err
	}
	if _, ok := g.tryOutput("ls-remote", "--exit-code", remote, "refs/heads/"+RecoveryBranch); !ok {
		if _, reachable := g.tryOutput("ls-remote", remote); reachable {
			return nil, ErrNoRecovery
		}
		return nil, errors.New("Unable to reach the vault remote. Check your connection")
	}
	if _, err := g.output("fetch", "--no-tags", remote, "+refs/heads/"+RecoveryBranch+":"+recoveryRef); err != nil {
		return nil, err
	}
	size, err := g.output("cat-file", "-s", recoveryRef+":"+recoveryFile)
	if err != nil {
		return nil, ErrNoRecovery
	}
	if n, err := strconv.Atoi(strings.TrimSpace(size)); err != nil || n <= 0 || n > maxRecoverySize {
		return nil, errors.New("Invalid recovery copy")
	}
	out, err := g.git("cat-file", "blob", recoveryRef+":"+recoveryFile)
	if err != nil {
		return nil, ErrNoRecovery
	}
	return out, nil
}

// Sync fetches once, then fast-forwards when only the remote moved or pushes
// when only this computer did. Both moving returns ErrDiverged with the
// status, leaving the explicit "preserve both versions" merge to the user.
func (g *GitVault) Sync() (Status, error) {
	before, err := g.requireCleanUpstream()
	if err != nil {
		return before, err
	}
	remote, err := g.remote(before.Branch)
	if err != nil {
		return before, err
	}
	if _, err = g.output("fetch", "--no-tags", remote); err != nil {
		return before, errors.New("Unable to reach the vault remote. Changes stay on this computer until the next sync")
	}
	s, err := g.Status()
	if err != nil {
		return s, err
	}
	switch {
	case s.Ahead > 0 && s.Behind > 0:
		return s, ErrDiverged
	case s.Behind > 0:
		if _, err := g.output("merge", "--ff-only", "@{upstream}"); err != nil {
			return s, err
		}
	case s.Ahead > 0:
		mergeRef, err := g.output("config", "--get", "branch."+s.Branch+".merge")
		if err != nil {
			return s, err
		}
		mergeRef = strings.TrimSpace(mergeRef)
		if !strings.HasPrefix(mergeRef, "refs/heads/") {
			return s, errors.New("Invalid remote branch")
		}
		if _, err := g.output("push", remote, "HEAD:"+mergeRef); err != nil {
			return s, errors.New("Unable to send changes to the vault remote. They stay on this computer until the next sync")
		}
	}
	return g.Status()
}
