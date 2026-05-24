package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func TestUnicode_CleanFile(t *testing.T) {
	dir := t.TempDir()
	src := "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"Hello, World!\")\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewUnicodeModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("clean file got %d findings, want 0", len(findings))
	}
}

func TestUnicode_BiDiCharInGoFile(t *testing.T) {
	dir := t.TempDir()
	// U+202E (RIGHT-TO-LEFT OVERRIDE) – UTF-8: 0xE2 0x80 0xAE
	src := "package main\n\n// access check: \xe2\x80\xae bypass if admin\nfunc isAllowed() bool { return true }\n"
	if err := os.WriteFile(filepath.Join(dir, "auth.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewUnicodeModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for BiDi character, got none")
	}
	if findings[0].Severity != scanner.Medium {
		t.Errorf("severity = %v, want MEDIUM", findings[0].Severity)
	}
}

func TestUnicode_BiDiCharInPythonFile(t *testing.T) {
	dir := t.TempDir()
	// U+200F (RIGHT-TO-LEFT MARK) – UTF-8: 0xE2 0x80 0x8F
	src := "def check_admin(user):\n    # \xe2\x80\x8f admin check\n    return user == 'admin'\n"
	if err := os.WriteFile(filepath.Join(dir, "auth.py"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewUnicodeModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for BiDi character in .py, got none")
	}
}

func TestUnicode_BiDiIsolate(t *testing.T) {
	dir := t.TempDir()
	// U+2066 (LEFT-TO-RIGHT ISOLATE) – UTF-8: 0xE2 0x81 0xA6
	src := "function validate(input) {\n  // \xe2\x81\xa6 safe check\n  return input.length > 0;\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "validate.js"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewUnicodeModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for BiDi isolate character, got none")
	}
}

func TestUnicode_SkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules", "some-pkg")
	if err := os.MkdirAll(nmDir, 0755); err != nil {
		t.Fatal(err)
	}
	// U+202E inside node_modules – should be skipped.
	src := "// \xe2\x80\xae evil\nmodule.exports = {};\n"
	if err := os.WriteFile(filepath.Join(nmDir, "index.js"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewUnicodeModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("node_modules should be skipped, got %d findings", len(findings))
	}
}

func TestUnicode_SkipsLargeFiles(t *testing.T) {
	dir := t.TempDir()
	large := make([]byte, 1024*1024+100)
	for i := range large {
		large[i] = 'a'
	}
	// Embed U+202E (0xE2 0x80 0xAE) near the end.
	copy(large[len(large)-10:], []byte("\xe2\x80\xae\n"))
	if err := os.WriteFile(filepath.Join(dir, "big.go"), large, 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewUnicodeModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("file >1MB should be skipped, got %d findings", len(findings))
	}
}

func TestUnicode_NonSourceFileSkipped(t *testing.T) {
	dir := t.TempDir()
	// A Markdown file with a BiDi char – not in the scanned extension list.
	content := "# README\nThis is \xe2\x80\xae safe.\n"
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewUnicodeModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf(".md should be skipped, got %d findings", len(findings))
	}
}

func TestUnicode_Name(t *testing.T) {
	m := scanner.NewUnicodeModule()
	if m.Name() != "unicode" {
		t.Errorf("Name() = %q, want %q", m.Name(), "unicode")
	}
}
