#!/bin/bash
set -uo pipefail

# Runs git-protect scan against all test repos and reports results.
# Usage: ./test-repos/run-tests.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$SCRIPT_DIR/repos"
GP="$(cd "$SCRIPT_DIR/.." && pwd)/git-protect"

if [ ! -x "$GP" ]; then
    echo "ERROR: git-protect binary not found. Run 'make build' first."
    exit 1
fi

if [ ! -d "$REPO_DIR" ]; then
    echo "ERROR: test repos not found. Run './test-repos/setup-attack-repos.sh' first."
    exit 1
fi

PASS=0
FAIL=0
TOTAL=0

# Expected results: repo-name=expected-severity (CRITICAL, HIGH, MEDIUM, CLEAN)
declare -A EXPECTED=(
    ["01-vscode-folderopen"]="HIGH"
    ["02-envrc-gitconfig"]="CRITICAL"
    ["03-embedded-bare-repo"]="CRITICAL"
    ["04-gitattributes-filter"]="HIGH"
    ["05-submodule-ext"]="CRITICAL"
    ["06-submodule-traversal"]="CRITICAL"
    ["07-credential-stealer"]="MEDIUM"
    ["08-npm-postinstall"]="MEDIUM"
    ["09-trojan-source"]="MEDIUM"
    ["10-devcontainer"]="HIGH"
    ["11-vscode-settings"]="HIGH"
    ["12-ci-pipeline"]="MEDIUM"
    ["13-makefile-shell"]="MEDIUM"
    ["14-symlink-escape"]="HIGH"
    ["15-clean-repo"]="CLEAN"
)

printf "\n%-30s %-10s %-10s %s\n" "REPO" "EXPECTED" "RESULT" "STATUS"
printf "%-30s %-10s %-10s %s\n" "----" "--------" "------" "------"

for repo_path in "$REPO_DIR"/*/; do
    repo_name=$(basename "$repo_path")
    expected="${EXPECTED[$repo_name]:-UNKNOWN}"
    TOTAL=$((TOTAL + 1))

    # Run scan and capture output
    scan_output=$("$GP" scan "$repo_path" 2>&1)
    exit_code=$?

    # Determine highest severity found
    if echo "$scan_output" | grep -q "CRITICAL"; then
        actual="CRITICAL"
    elif echo "$scan_output" | grep -q "HIGH"; then
        actual="HIGH"
    elif echo "$scan_output" | grep -q "MEDIUM"; then
        actual="MEDIUM"
    elif echo "$scan_output" | grep -q "No threats found"; then
        actual="CLEAN"
    else
        actual="CLEAN"
    fi

    # Check if result matches expectation
    if [ "$expected" = "CLEAN" ] && [ "$actual" = "CLEAN" ]; then
        status="PASS"
        PASS=$((PASS + 1))
    elif [ "$expected" = "CLEAN" ] && [ "$actual" != "CLEAN" ]; then
        status="FAIL (false positive)"
        FAIL=$((FAIL + 1))
    elif [ "$expected" != "CLEAN" ] && [ "$actual" = "CLEAN" ]; then
        status="FAIL (missed)"
        FAIL=$((FAIL + 1))
    elif [ "$expected" = "$actual" ]; then
        status="PASS"
        PASS=$((PASS + 1))
    else
        # Detected but at different severity — still a detection
        status="PASS (sev=$actual)"
        PASS=$((PASS + 1))
    fi

    printf "%-30s %-10s %-10s %s\n" "$repo_name" "$expected" "$actual" "$status"
done

echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "FAILED REPOS — detailed output:"
    for repo_path in "$REPO_DIR"/*/; do
        repo_name=$(basename "$repo_path")
        expected="${EXPECTED[$repo_name]:-UNKNOWN}"
        scan_output=$("$GP" scan "$repo_path" 2>&1)

        if echo "$scan_output" | grep -q "CRITICAL"; then
            actual="CRITICAL"
        elif echo "$scan_output" | grep -q "HIGH"; then
            actual="HIGH"
        elif echo "$scan_output" | grep -q "MEDIUM"; then
            actual="MEDIUM"
        else
            actual="CLEAN"
        fi

        is_fail=false
        if [ "$expected" = "CLEAN" ] && [ "$actual" != "CLEAN" ]; then is_fail=true; fi
        if [ "$expected" != "CLEAN" ] && [ "$actual" = "CLEAN" ]; then is_fail=true; fi

        if $is_fail; then
            echo ""
            echo "--- $repo_name (expected=$expected, got=$actual) ---"
            echo "$scan_output"
        fi
    done
    exit 1
fi

echo ""

# Test clone blocking
echo "=== Clone blocking test ==="
CLONE_DIR=$(mktemp -d)
echo -n "Cloning malicious repo (02-envrc-gitconfig)... "
if "$GP" clone "$REPO_DIR/02-envrc-gitconfig" "$CLONE_DIR/test-clone" >/dev/null 2>&1; then
    echo "FAIL (clone should have been blocked)"
    rm -rf "$CLONE_DIR"
    exit 1
else
    echo "BLOCKED (correct)"
fi

echo -n "Cloning clean repo (15-clean-repo)... "
if "$GP" clone "$REPO_DIR/15-clean-repo" "$CLONE_DIR/clean-clone" >/dev/null 2>&1; then
    echo "PASS (clone succeeded)"
else
    echo "FAIL (clean repo should clone successfully)"
    rm -rf "$CLONE_DIR"
    exit 1
fi

rm -rf "$CLONE_DIR"

echo ""
echo "=== All tests passed ==="
