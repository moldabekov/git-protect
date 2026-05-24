package paths

import (
	"os"
	"path/filepath"
)

func ConfigDir() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "git-protect")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "git-protect")
}

func HooksDir() string {
	return filepath.Join(ConfigDir(), "hooks")
}

func TrustStorePath() string {
	return filepath.Join(ConfigDir(), "trust.toml")
}
