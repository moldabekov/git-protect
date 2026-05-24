package scanner

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// symlinksModule detects symlinks whose resolved target escapes the repository tree.
// Severity: HIGH – can expose sensitive host files when the repo is opened in an IDE
// or archive tool that follows symlinks transparently.
type symlinksModule struct{}

// NewSymlinksModule returns a Module that detects symlinks escaping the repo tree.
func NewSymlinksModule() Module {
	return &symlinksModule{}
}

func (m *symlinksModule) Name() string { return "symlinks" }

// Scan walks the repository tree and flags any symlink whose resolved absolute
// path does not begin with the repository root.
func (m *symlinksModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	repoRoot, err := filepath.EvalSymlinks(sc.RepoPath)
	if err != nil {
		// If we cannot resolve the repo root itself, fall back to the raw path.
		repoRoot = filepath.Clean(sc.RepoPath)
	}
	// Ensure the prefix ends with the OS separator so that a repo at /tmp/repo
	// does not accidentally match /tmp/repo-other.
	repoPrefix := repoRoot + string(filepath.Separator)

	var findings []Finding

	walkErr := filepath.WalkDir(sc.RepoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Skip unreadable entries; don't abort the whole walk.
			return nil
		}

		// Skip the .git directory entirely – git manages its own internals.
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}

		// Only process symlinks.
		if d.Type()&fs.ModeSymlink == 0 {
			return nil
		}

		resolved, resolveErr := filepath.EvalSymlinks(path)
		if resolveErr != nil {
			// Broken symlink – read the raw link target and check it lexically.
			rawTarget, linkErr := os.Readlink(path)
			if linkErr != nil {
				return nil // Cannot inspect; skip.
			}

			// Make absolute for comparison.
			if !filepath.IsAbs(rawTarget) {
				rawTarget = filepath.Join(filepath.Dir(path), rawTarget)
			}
			rawTarget = filepath.Clean(rawTarget)

			if !isInsideRepo(rawTarget, repoRoot, repoPrefix) {
				relPath, _ := filepath.Rel(sc.RepoPath, path)
				findings = append(findings, Finding{
					Severity: High,
					Module:   m.Name(),
					Path:     relPath,
					Message:  fmt.Sprintf("symlink target escapes repository tree: %s", rawTarget),
					Detail:   "Broken symlink with target outside repo; could expose host files if target is later created.",
				})
			}
			return nil
		}

		if !isInsideRepo(resolved, repoRoot, repoPrefix) {
			relPath, _ := filepath.Rel(sc.RepoPath, path)
			findings = append(findings, Finding{
				Severity: High,
				Module:   m.Name(),
				Path:     relPath,
				Message:  fmt.Sprintf("symlink target escapes repository tree: %s -> %s", relPath, resolved),
				Detail:   "A symlink pointing outside the repo can expose host files when opened in IDEs or archive tools.",
			})
		}

		return nil
	})

	if walkErr != nil {
		return findings, fmt.Errorf("symlinks: walk error: %w", walkErr)
	}

	return findings, nil
}

// isInsideRepo reports whether target is the repo root itself or a path under it.
func isInsideRepo(target, repoRoot, repoPrefix string) bool {
	return target == repoRoot || strings.HasPrefix(target, repoPrefix)
}
