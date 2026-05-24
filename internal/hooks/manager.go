package hooks

import (
	"fmt"
	"os"
	"path/filepath"
)

// hookNames are the three git hooks installed by git-protect.
var hookNames = []string{"post-checkout", "post-merge", "post-rewrite"}

// hookScript generates the shell script body for a given hook.
// The script execs the git-protect binary with scan --hook-mode.
// Using exec avoids keeping a parent shell process alive.
func hookScript(binaryPath string) string {
	return fmt.Sprintf(`#!/bin/sh
# Installed by git-protect. Do not edit manually.
# Scans the repository after git operations for security threats.
exec "%s" scan --hook-mode "$@"
`, binaryPath)
}

// Install creates the hooks directory and writes post-checkout, post-merge,
// and post-rewrite hook scripts. Each script is set executable (0755).
// Install is idempotent — running it again overwrites existing hook files.
func Install(hooksDir, binaryPath string) error {
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("hooks: create directory %q: %w", hooksDir, err)
	}

	script := hookScript(binaryPath)
	for _, name := range hookNames {
		hookPath := filepath.Join(hooksDir, name)
		if err := os.WriteFile(hookPath, []byte(script), 0755); err != nil {
			return fmt.Errorf("hooks: write %q: %w", hookPath, err)
		}
	}
	return nil
}

// Uninstall removes all three hook files from hooksDir.
// Returns nil if the files do not exist (idempotent).
func Uninstall(hooksDir string) error {
	for _, name := range hookNames {
		hookPath := filepath.Join(hooksDir, name)
		if err := os.Remove(hookPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("hooks: remove %q: %w", hookPath, err)
		}
	}
	return nil
}

// HookNames returns a copy of the managed hook names.
func HookNames() []string {
	result := make([]string, len(hookNames))
	copy(result, hookNames)
	return result
}
