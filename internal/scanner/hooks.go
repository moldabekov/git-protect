package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// hooksModule scans .git/hooks/ for executable files that are not .sample stubs.
// Any executable hook in a freshly cloned repo is suspicious – git does not
// install executable hooks from a remote; they come only from init.templateDir.
type hooksModule struct{}

// NewHooksModule returns a Module that detects executable git hooks.
func NewHooksModule() Module {
	return &hooksModule{}
}

func (h *hooksModule) Name() string { return "hooks" }

func (h *hooksModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	hooksDir := filepath.Join(sc.RepoPath, ".git", "hooks")

	entries, err := os.ReadDir(hooksDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("hooks: read dir %s: %w", hooksDir, err)
	}

	var findings []Finding
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// .sample files are git's bundled hook examples; they are never
		// executed automatically and their presence is expected.
		if strings.HasSuffix(e.Name(), ".sample") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		// Flag any file with at least one executable bit set.
		if info.Mode()&0o111 == 0 {
			continue
		}
		hookPath := filepath.Join(".git", "hooks", e.Name())
		findings = append(findings, Finding{
			Severity: Critical,
			Module:   "hooks",
			Path:     hookPath,
			Message:  fmt.Sprintf("executable hook %q found in .git/hooks/", e.Name()),
			Detail: "Executable hooks in a cloned repository run attacker code during " +
				"git operations such as commit, checkout, and push. In a clean clone, " +
				"hook files must not exist unless populated by init.templateDir, which " +
				"is outside the attacker's control in a normal clone.",
		})
	}
	return findings, nil
}
