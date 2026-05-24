package scanner

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// bareReposModule walks the repository working tree and flags any embedded .git/
// directories (including case variants: .GIT/, .Git/, etc.).
//
// An embedded bare repo is the primary attack surface for CVE-2024-32002:
// git parses the embedded .git/config when it enters that directory, allowing
// an attacker to inject core.fsmonitor or other command-execution directives.
//
// The root .git/ directory (the repo's own git storage) is excluded from results.
type bareReposModule struct{}

// NewBareReposModule returns a Module that detects embedded bare repositories.
func NewBareReposModule() Module {
	return &bareReposModule{}
}

func (b *bareReposModule) Name() string { return "bare-repos" }

func (b *bareReposModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	// The root .git directory to exclude.
	rootGit := filepath.Join(sc.RepoPath, ".git")

	var findings []Finding
	err := filepath.WalkDir(sc.RepoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if !d.IsDir() {
			return nil
		}
		// Only care about directories whose name is a case variant of ".git".
		if !isGitDirName(d.Name()) {
			return nil
		}
		// Exclude the repository's own root .git directory.
		if path == rootGit {
			return filepath.SkipDir
		}
		// This is an embedded .git directory – flag it.
		relPath, relErr := filepath.Rel(sc.RepoPath, path)
		if relErr != nil {
			relPath = path
		}
		findings = append(findings, Finding{
			Severity: Critical,
			Module:   "bare-repos",
			Path:     relPath,
			Message:  fmt.Sprintf("embedded git directory %q found in working tree", relPath),
			Detail: "An embedded .git/ directory is a bare git repository. Git parses " +
				"its config file automatically during operations, allowing an attacker " +
				"to inject core.fsmonitor or other command-execution directives. " +
				"This is the primary attack surface for CVE-2024-32002.",
		})
		// Do not descend into the embedded .git/ itself.
		return filepath.SkipDir
	})
	if err != nil {
		return findings, fmt.Errorf("bare-repos: walk %s: %w", sc.RepoPath, err)
	}
	return findings, nil
}

// isGitDirName returns true if name is ".git" in any ASCII case combination
// (.git, .GIT, .Git, .gIt, etc.).
func isGitDirName(name string) bool {
	return strings.EqualFold(name, ".git")
}
