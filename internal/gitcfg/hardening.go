package gitcfg

import (
	"fmt"
	"os/exec"
	"strings"
)

// ConfigEntry describes one global git config setting managed by git-protect.
type ConfigEntry struct {
	Key         string
	Value       string
	Overridable bool   // true = local .git/config can override this
	Purpose     string // human-readable description
}

// HardeningEntries returns the six config entries that git-protect install applies.
// This list is the authoritative definition – install, uninstall, and status
// all derive from it.
func HardeningEntries() []ConfigEntry {
	return []ConfigEntry{
		{
			Key:         "core.hooksPath",
			Overridable: true,
			Purpose:     "Redirect hooks to git-protect managed directory (best-effort; can be overridden by local config)",
			// Value is set at install time to the actual hooks dir path.
		},
		{
			Key:         "safe.bareRepository",
			Value:       "explicit",
			Overridable: false,
			Purpose:     "Block embedded bare repo attacks (protected config; cannot be overridden by local config)",
		},
		{
			Key:         "core.fsmonitor",
			Value:       "false",
			Overridable: true,
			Purpose:     "Disable fsmonitor to prevent RCE via core.fsmonitor (best-effort; can be overridden)",
		},
		{
			Key:         "transfer.fsckObjects",
			Value:       "true",
			Overridable: true,
			Purpose:     "Validate git object integrity during fetch (best-effort; can be overridden)",
		},
		{
			Key:         "core.protectHFS",
			Value:       "true",
			Overridable: true,
			Purpose:     "Prevent HFS+ Unicode normalization attacks on macOS (best-effort)",
		},
		{
			Key:         "core.protectNTFS",
			Value:       "true",
			Overridable: true,
			Purpose:     "Prevent NTFS alternate data stream attacks on Windows (best-effort)",
		},
	}
}

// SetGlobal runs: git config --global <key> <value>
func SetGlobal(key, value string) error {
	cmd := exec.Command("git", "config", "--global", key, value)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git config --global %s %s: %w\n%s", key, value, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// GetGlobal runs: git config --global --get <key>
// Returns ("", nil) if the key is not set.
func GetGlobal(key string) (string, error) {
	cmd := exec.Command("git", "config", "--global", "--get", key)
	out, err := cmd.Output()
	if err != nil {
		// exit status 1 means "key not found" – not an error for our purposes
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return "", nil
		}
		return "", fmt.Errorf("git config --global --get %s: %w", key, err)
	}
	return strings.TrimRight(string(out), "\n"), nil
}

// UnsetGlobal runs: git config --global --unset <key>
// Returns nil if the key was not set (idempotent).
func UnsetGlobal(key string) error {
	cmd := exec.Command("git", "config", "--global", "--unset", key)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 5 {
			// exit 5 = "key not found" – idempotent OK
			return nil
		}
		return fmt.Errorf("git config --global --unset %s: %w\n%s", key, err, strings.TrimSpace(string(out)))
	}
	return nil
}
