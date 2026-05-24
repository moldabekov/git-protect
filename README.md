# git-protect

You get a coding task for a job interview. You clone the repo. Your SSH keys are now on someone's server in Eastern Europe.

This actually happens. A lot. And not just interviews – any repo you clone can contain hooks, configs, IDE settings, or scripts that execute before you even open a file. Git itself has no mechanism to warn you about this.

`git-protect` scans repositories for these attack vectors before they can run.

```
$ git-protect clone https://github.com/totally-legit-company/interview-task.git

  Cloning (no-checkout)... done.
  Scanning for threats...

  CRITICAL   .envrc: .envrc sets GIT_CONFIG_COUNT – overrides git config protections
  HIGH       .vscode/tasks.json: VS Code task "setup" has runOn:folderOpen – auto-executes on folder open

  BLOCKED – 2 threats found. Repository has NOT been checked out.
  Cleaned up.
```

The repo never touches your filesystem. No checkout, no execution, nothing.

## How it works

`git-protect clone` does a `--no-checkout` clone first (just fetches git objects, no files land on disk), scans everything, and only checks out if it's clean. If something's wrong, it deletes the directory and tells you what it found.

For repos you clone the normal way (`git clone`), there's a fallback: global git hooks that scan after checkout and warn you. Not as strong (can't undo a checkout), but catches the cases where you forget to use the wrapper.

## What it catches

13 detection modules covering the real attack surface:

**The dangerous stuff (blocks clone):**
- `core.fsmonitor`, `core.pager`, `core.editor` and 25+ other git config keys that execute arbitrary commands
- `include`/`includeIf` config injection (CVE-2023-29007)
- Submodule `ext::` protocol (arbitrary command execution)
- Submodule path traversal and carriage return smuggling (CVE-2025-48384)
- Embedded bare `.git/` directories (the IDE-triggers-fsmonitor attack)
- `.gitattributes` with custom filter/diff/merge drivers
- `.vscode/tasks.json` with `runOn: folderOpen` (used in the Contagious Interview campaign)
- `.vscode/settings.json` overriding `git.path`, Python interpreter, terminal shell
- `.envrc` files (especially ones setting `GIT_CONFIG_*` to bypass protections)
- `.devcontainer` lifecycle hooks
- Symlinks escaping the repo tree

**The suspicious stuff (warns but doesn't block):**
- `package.json` postinstall/preinstall scripts
- Makefile `$(shell)` calls
- Scripts with credential access patterns (`~/.ssh/id_rsa`, `~/.aws/credentials`)
- Reverse shell patterns, base64 decode chains
- BiDi control characters (Trojan Source / CVE-2021-42574)
- CI pipeline definitions with `curl | sh`

## Install

```
go install github.com/moldabekov/git-protect/cmd/git-protect@latest
```

Then set up the global protections:

```
git-protect install
```

This does three things:
1. Sets `core.hooksPath` to git-protect's hooks directory (so every checkout gets scanned)
2. Sets `safe.bareRepository=explicit` (blocks embedded bare repo attacks)
3. Sets `core.fsmonitor=false` and a few other hardening flags

If you want `git clone` to automatically route through the safe scanner:

```
git-protect install --alias
```

Now `git clone` = `git-protect clone`. You don't have to remember.

## Usage

**Safe clone** (recommended):
```
git-protect clone https://github.com/someone/repo.git
```

**Scan an existing repo:**
```
git-protect scan .
git-protect scan ~/projects/sketchy-repo
```

**JSON output** (for CI):
```
git-protect scan --json --exit-code .
```

**Trust repos you work with daily:**
```
git-protect trust add "github.com/mycompany/*"
git-protect trust add "github.com/torvalds/linux"
git-protect trust list
```

**Check protection status:**
```
git-protect status
```

## Trust system

Scanning every checkout of your company's monorepo gets old fast. The trust store lets you allowlist repos, orgs, or entire hosts:

```
git-protect trust add "github.com/mycompany/*"        # org wildcard
git-protect trust add "gitlab.internal.corp/*"          # host wildcard
git-protect trust add "github.com/torvalds/linux"       # single repo
```

Trusted repos still get scanned – findings just don't block. If a trusted org's repo gets compromised, you'll see the warning.

Trust entries live in `~/.config/git-protect/trust.toml` (plain text, easy to audit). The file is locked to 0600 permissions and rejects symlinks.

Nothing is trusted by default. Not even github.com.

## Limitations

Be honest about what this can and can't do.

**Strong protection:**
- `git-protect clone` blocks threats before any files hit your disk. This is the primary defense and it works.
- `safe.bareRepository=explicit` is enforced by git itself – no local config can override it.

**Best-effort protection:**
- The global hooks (`core.hooksPath`) can be overridden by a malicious `.git/config` in the cloned repo. If someone crafts a repo that both sets `core.fsmonitor` to something evil AND overrides `core.hooksPath`, a raw `git clone` (without the wrapper) gets zero warning.
- `core.fsmonitor=false` in global config is overridden by local `.git/config`. Same for most of the hardening flags.

This is a fundamental git limitation – local config wins over global for most keys. The `--alias` flag exists to make `git clone` always go through the safe path. Use it.

**Not covered:**
- Compiled binaries in the repo (that's antivirus territory)
- Supply chain attacks through legitimate package registries
- Attacks that require you to explicitly run something (if you run `make` or `npm install` in an untrusted repo, that's on you – though we do warn about suspicious scripts)

## How it got built

This started from a real threat: developers getting their credentials stolen through interview coding tasks. The attack surface of `git clone` is genuinely scary once you look at it – fsmonitor, gitattributes filters, IDE configs, devcontainers, direnv, submodule tricks, and more.

There was no tool that defended against this. Everything in the ecosystem (Gitleaks, TruffleHog, Talisman) scans for secrets you might accidentally commit – outbound protection. Nobody was doing inbound protection.

So here we are.

## License

MIT
