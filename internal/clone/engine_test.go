package clone_test

import (
	"testing"

	"github.com/moldabekov/git-protect/internal/clone"
)

func TestBuildCloneArgs_Basic(t *testing.T) {
	args := clone.BuildCloneArgs("https://github.com/org/repo.git", "mydir", nil)
	if !containsArg(args, "clone") {
		t.Errorf("args missing 'clone': %v", args)
	}
	if !containsArg(args, "--no-checkout") {
		t.Errorf("args missing '--no-checkout': %v", args)
	}
	if !containsArg(args, "https://github.com/org/repo.git") {
		t.Errorf("args missing URL: %v", args)
	}
	if !containsArg(args, "mydir") {
		t.Errorf("args missing target dir: %v", args)
	}
}

func TestBuildCloneArgs_NoDir(t *testing.T) {
	args := clone.BuildCloneArgs("https://github.com/org/repo.git", "", nil)
	if !containsArg(args, "https://github.com/org/repo.git") {
		t.Errorf("args missing URL: %v", args)
	}
	for _, a := range args {
		if a == "mydir" {
			t.Errorf("unexpected 'mydir' in args when dir is empty: %v", args)
		}
	}
}

func TestBuildCloneArgs_WithDepth(t *testing.T) {
	args := clone.BuildCloneArgs("https://github.com/org/repo.git", "", []string{"--depth", "1"})
	if !containsArg(args, "--depth") {
		t.Errorf("args missing '--depth': %v", args)
	}
	if !containsArg(args, "1") {
		t.Errorf("args missing depth value '1': %v", args)
	}
}

func TestBuildCloneArgs_StripsRecurseSubmodules(t *testing.T) {
	extraArgs := []string{"--depth", "1", "--recurse-submodules", "--branch", "main"}
	args := clone.BuildCloneArgs("https://github.com/org/repo.git", "", extraArgs)
	for _, a := range args {
		if a == "--recurse-submodules" {
			t.Errorf("--recurse-submodules should be stripped from clone args: %v", args)
		}
	}
	if !containsArg(args, "--depth") {
		t.Errorf("--depth should be preserved: %v", args)
	}
	if !containsArg(args, "--branch") {
		t.Errorf("--branch should be preserved: %v", args)
	}
}

func TestBuildCloneArgs_StripsRecurseSubmodulesWithValue(t *testing.T) {
	args := clone.BuildCloneArgs("https://example.com/repo.git", "", []string{
		"--recurse-submodules=path/to/sub",
	})
	for _, a := range args {
		if a == "--recurse-submodules=path/to/sub" {
			t.Errorf("--recurse-submodules=... should be stripped: %v", args)
		}
	}
}

func TestBuildCloneArgs_AlwaysHasNoCheckout(t *testing.T) {
	args := clone.BuildCloneArgs("https://example.com/repo.git", "", []string{})
	found := false
	for _, a := range args {
		if a == "--no-checkout" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("--no-checkout missing from args: %v", args)
	}
}

func TestBuildCloneArgs_StripsRecursive(t *testing.T) {
	args := clone.BuildCloneArgs("https://example.com/repo.git", "", []string{
		"--recursive", "--depth", "1",
	})
	for _, a := range args {
		if a == "--recursive" {
			t.Errorf("--recursive should be stripped from clone args: %v", args)
		}
	}
	if !containsArg(args, "--depth") {
		t.Errorf("--depth should be preserved: %v", args)
	}
}

func containsArg(args []string, target string) bool {
	for _, a := range args {
		if a == target {
			return true
		}
	}
	return false
}
