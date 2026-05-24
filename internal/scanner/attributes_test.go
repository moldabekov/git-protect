package scanner_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func attrScan(t *testing.T, repo string) []scanner.Finding {
	t.Helper()
	m := scanner.NewAttributesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("attributes scan error: %v", err)
	}
	return findings
}

func TestAttributesScanner_NoGitattributes(t *testing.T) {
	repo := makeRepo(t)
	findings := attrScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestAttributesScanner_CleanAttributes(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitattributes"), `*.go text eol=lf
*.png binary
*.txt text
Makefile text eol=lf
`)
	findings := attrScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean attributes, got %d: %v", len(findings), findings)
	}
}

func TestAttributesScanner_FilterLfs_NotFlagged(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitattributes"), `*.bin filter=lfs diff=lfs merge=lfs -text
*.mp4 filter=lfs diff=lfs merge=lfs -text
`)
	findings := attrScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for filter=lfs, got %d: %v", len(findings), findings)
	}
}

func TestAttributesScanner_CustomFilter_IsHigh(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitattributes"), "*.c filter=build\n")
	findings := attrScan(t, repo)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != scanner.High {
		t.Errorf("severity = %v, want HIGH", f.Severity)
	}
	if f.Module != "attributes" {
		t.Errorf("module = %q, want %q", f.Module, "attributes")
	}
	if !strings.Contains(f.Message, "filter=build") {
		t.Errorf("message %q should contain 'filter=build'", f.Message)
	}
	if !strings.Contains(f.Path, ".gitattributes") {
		t.Errorf("path %q should contain .gitattributes", f.Path)
	}
}

func TestAttributesScanner_CustomDiff_IsHigh(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitattributes"), "*.bin diff=binary-parser\n")
	findings := attrScan(t, repo)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Severity != scanner.High {
		t.Errorf("severity = %v, want HIGH", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Message, "diff=binary-parser") {
		t.Errorf("message %q should contain driver name", findings[0].Message)
	}
}

func TestAttributesScanner_CustomMerge_IsHigh(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitattributes"), "*.lock merge=custom-lock-driver\n")
	findings := attrScan(t, repo)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Severity != scanner.High {
		t.Errorf("severity = %v, want HIGH", findings[0].Severity)
	}
}

func TestAttributesScanner_BuiltinMergeDrivers_NotFlagged(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitattributes"), `*.txt merge=union
*.go merge=text
`)
	findings := attrScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for built-in merge drivers, got %d: %v", len(findings), findings)
	}
}

func TestAttributesScanner_NestedGitattributes_Scanned(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, "src", "native", ".gitattributes"),
		"*.so filter=native-build\n")
	findings := attrScan(t, repo)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from nested .gitattributes, got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Path, filepath.Join("src", "native", ".gitattributes")) {
		t.Errorf("path %q should reference nested file", findings[0].Path)
	}
}

func TestAttributesScanner_GitDirNotWalked(t *testing.T) {
	repo := makeRepo(t)
	// A .gitattributes inside .git/ must not be scanned.
	writeFile(t, filepath.Join(repo, ".git", "info", ".gitattributes"),
		"*.bin filter=evil\n")
	findings := attrScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (skipping .git/), got %d", len(findings))
	}
}

func TestAttributesScanner_MultipleCustomDrivers_AllReported(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitattributes"), `*.c   filter=inject
*.h   filter=inject
*.cpp diff=custom-cpp
*.rs  merge=custom-rust
*.bin filter=lfs diff=lfs merge=lfs -text
`)
	findings := attrScan(t, repo)
	// inject on *.c and *.h (2 findings), custom-cpp (1), custom-rust (1) = 4.
	// filter=lfs must not be counted.
	if len(findings) != 4 {
		t.Errorf("expected 4 findings, got %d: %v", len(findings), findings)
	}
}

func TestAttributesScanner_SingleLineMultipleAttrs(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitattributes"),
		"*.bin filter=attack diff=attack merge=attack\n")
	findings := attrScan(t, repo)
	// 3 distinct attribute=driver pairs on one line.
	if len(findings) != 3 {
		t.Errorf("expected 3 findings (filter + diff + merge), got %d: %v", len(findings), findings)
	}
}

func TestAttributesScanner_ModuleName(t *testing.T) {
	m := scanner.NewAttributesModule()
	if m.Name() != "attributes" {
		t.Errorf("Name() = %q, want %q", m.Name(), "attributes")
	}
}
