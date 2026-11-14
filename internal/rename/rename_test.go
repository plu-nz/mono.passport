package rename

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigrateMovesOnlyWhenNewIsMissing(t *testing.T) {
	root := t.TempDir()
	config, data := filepath.Join(root, "config"), filepath.Join(root, "data")
	t.Setenv("XDG_CONFIG_HOME", config)
	t.Setenv("XDG_DATA_HOME", data)
	os.MkdirAll(filepath.Join(config, "passage"), 0o700)
	os.WriteFile(filepath.Join(config, "passage", "settings.json"), []byte(`{"vaultPath":"/v"}`), 0o600)
	os.MkdirAll(filepath.Join(data, "passage", "signing"), 0o700)
	os.MkdirAll(filepath.Join(data, "passport"), 0o700)

	Migrate()
	if got, err := os.ReadFile(filepath.Join(config, "passport", "settings.json")); err != nil || string(got) != `{"vaultPath":"/v"}` {
		t.Fatalf("config not moved: %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(config, "passage")); !os.IsNotExist(err) {
		t.Fatal("old config directory left behind")
	}
	// The data directory already existed under the new name: nothing is overwritten.
	if _, err := os.Stat(filepath.Join(data, "passage", "signing")); err != nil {
		t.Fatal("old data directory touched although passport existed")
	}
	Migrate() // idempotent
}
