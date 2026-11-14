// Package rename moves the directories of Passage, Passport's former name, to
// Passport's names once, so an upgrade keeps the vault selection, extension
// pairings, the unpacked extension and the WebView data.
package rename

import (
	"errors"
	"os"
	"path/filepath"
)

// bases returns the XDG configuration and data directories.
func bases() []string {
	home, _ := os.UserHomeDir()
	var out []string
	for _, pair := range [][2]string{{"XDG_CONFIG_HOME", ".config"}, {"XDG_DATA_HOME", ".local/share"}} {
		base := os.Getenv(pair[0])
		if base == "" && home != "" {
			base = filepath.Join(home, pair[1])
		}
		if filepath.IsAbs(base) {
			out = append(out, base)
		}
	}
	return out
}

// Migrate renames <base>/passage to <base>/passport when only the old one
// exists. Concurrent callers race safely: the rename is atomic and the loser
// finds the new directory in place.
func Migrate() {
	for _, base := range bases() {
		old, current := filepath.Join(base, "passage"), filepath.Join(base, "passport")
		if _, err := os.Lstat(current); !errors.Is(err, os.ErrNotExist) {
			continue
		}
		if info, err := os.Lstat(old); err == nil && info.IsDir() {
			os.Rename(old, current)
		}
	}
}
