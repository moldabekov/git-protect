package clone

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/moldabekov/git-protect/internal/scanner"
)

// Result is the outcome of a safe clone operation.
type Result struct {
	PreReport  scanner.Report // findings from pre-checkout scan
	PostReport scanner.Report // findings from post-checkout scan (only if not blocked)
	Blocked    bool           // true if clone was blocked due to threats
	CleanedUp  bool           // true if the cloned directory was removed
	Dir        string         // resolved clone target directory
}

// ScanFunc is a function that scans a repository directory.
// The engine accepts this as a dependency to allow test injection.
type ScanFunc func(ctx context.Context, repoPath string, preCheckout bool) (scanner.Report, error)

// BuildCloneArgs constructs the argument list for git clone. It always adds
// --no-checkout and strips --recurse-submodules (handled separately by the engine).
func BuildCloneArgs(url, dir string, extraArgs []string) []string {
	args := []string{"clone", "--no-checkout"}
	for _, a := range extraArgs {
		// Strip submodule recursion – git-protect handles it separately
		if a == "--recurse-submodules" || strings.HasPrefix(a, "--recurse-submodules=") {
			continue
		}
		if a == "--recursive" {
			continue
		}
		args = append(args, a)
	}
	args = append(args, url)
	if dir != "" {
		args = append(args, dir)
	}
	return args
}

// DetectGitBin locates the git binary using PATH resolution.
func DetectGitBin() (string, error) {
	path, err := exec.LookPath("git")
	if err != nil {
		return "", fmt.Errorf("git binary not found in PATH: %w", err)
	}
	return path, nil
}

// inferCloneDir derives the target directory name from a clone URL and explicit
// dir argument, matching git's own logic.
func inferCloneDir(url, dir string) string {
	if dir != "" {
		return dir
	}
	// Strip trailing slashes
	url = strings.TrimRight(url, "/")
	// Take last path segment
	last := filepath.Base(url)
	// Strip .git suffix
	last = strings.TrimSuffix(last, ".git")
	// Handle SCP-style git@host:org/repo
	if idx := strings.LastIndex(last, ":"); idx != -1 {
		last = last[idx+1:]
		last = strings.TrimSuffix(last, ".git")
	}
	return last
}

// Execute performs a safe clone: git clone --no-checkout, pre-scan, checkout,
// post-scan. If blocking threats are found before or after checkout the
// cloned directory is removed and Blocked+CleanedUp are set in the result.
func Execute(
	ctx context.Context,
	gitBin, url, dir string,
	extraArgs []string,
	scan ScanFunc,
) (Result, error) {
	resolvedDir := inferCloneDir(url, dir)
	result := Result{Dir: resolvedDir}

	// Step 1: git clone --no-checkout
	cloneArgs := BuildCloneArgs(url, dir, extraArgs)
	cloneCmd := exec.CommandContext(ctx, gitBin, cloneArgs...)
	cloneCmd.Stdout = os.Stdout
	cloneCmd.Stderr = os.Stderr
	if err := cloneCmd.Run(); err != nil {
		return result, fmt.Errorf("git clone failed: %w", err)
	}

	// Step 2: Pre-checkout scan
	preReport, err := scan(ctx, resolvedDir, true)
	if err != nil {
		return result, fmt.Errorf("pre-checkout scan failed: %w", err)
	}
	result.PreReport = preReport

	// Step 3: Block if threats found
	if preReport.HasBlocking() {
		result.Blocked = true
		if err := os.RemoveAll(resolvedDir); err != nil {
			return result, fmt.Errorf("cleanup after block: %w", err)
		}
		result.CleanedUp = true
		return result, nil
	}

	// Step 4: git checkout
	checkoutCmd := exec.CommandContext(ctx, gitBin, "-C", resolvedDir, "checkout")
	checkoutCmd.Stdout = os.Stdout
	checkoutCmd.Stderr = os.Stderr
	if err := checkoutCmd.Run(); err != nil {
		return result, fmt.Errorf("git checkout failed: %w", err)
	}

	// Step 5: Post-checkout TOCTOU re-verification
	postReport, err := scan(ctx, resolvedDir, false)
	if err != nil {
		return result, fmt.Errorf("post-checkout scan failed: %w", err)
	}
	result.PostReport = postReport

	// Step 6: Block if post-checkout scan found threats
	if postReport.HasBlocking() {
		result.Blocked = true
		if err := os.RemoveAll(resolvedDir); err != nil {
			return result, fmt.Errorf("cleanup after post-checkout block: %w", err)
		}
		result.CleanedUp = true
		return result, nil
	}

	return result, nil
}
