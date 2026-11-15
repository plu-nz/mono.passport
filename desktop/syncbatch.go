package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/plu-nz/mono.passport/internal/gitvault"
)

// vaultMutation keeps pass writes and the delayed commit from racing each other.
var vaultMutation sync.Mutex

func prepareImmediate() {
	if err := flushPending(); err != nil {
		setSyncState(SyncState{State: "attention", Message: "Changes are not saved to the remote: " + err.Error(), At: time.Now()})
	}
	if err := markPending(); err != nil {
		setSyncState(SyncState{State: "attention", Message: "Changes are not saved to the remote: " + err.Error(), At: time.Now()})
	}
}

// The marker lives in Git's private directory, outside the synced vault tree.
// It survives an app restart so a saved metadata edit can be committed later.
func pendingMarker(g *gitvault.GitVault) (string, error) {
	cmd := exec.Command("git", "-C", g.Root(), "rev-parse", "--git-path", "passport-pending")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	path := strings.TrimSpace(string(out))
	if !filepath.IsAbs(path) {
		path = filepath.Join(g.Root(), path)
	}
	return path, nil
}

func markPending() error {
	g, err := openGit()
	if err != nil {
		return nil // A vault without Git has nothing to commit or push.
	}
	path, err := pendingMarker(g)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	return f.Close()
}

// flushPending must run while vaultMutation is held. It leaves the marker in
// place on any commit failure, allowing a later sync or app launch to retry.
func flushPending() error {
	g, err := openGit()
	if err != nil {
		return nil
	}
	path, err := pendingMarker(g)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	status, err := g.Status()
	if err != nil {
		return err
	}
	if status.Dirty {
		if _, err := g.CommitChanges(); err != nil {
			return err
		}
	}
	return os.Remove(path)
}

func clearPendingMarker(g *gitvault.GitVault) error {
	path, err := pendingMarker(g)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
