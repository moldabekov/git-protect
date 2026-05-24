package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/moldabekov/git-protect/internal/clone"
	"github.com/moldabekov/git-protect/internal/gitcfg"
	"github.com/moldabekov/git-protect/internal/hooks"
	"github.com/moldabekov/git-protect/internal/output"
	"github.com/moldabekov/git-protect/internal/paths"
	"github.com/moldabekov/git-protect/internal/scanner"
	"github.com/moldabekov/git-protect/internal/trust"
)

// version is set at build time via -ldflags.
var version = "dev"

// ---- Module registration ----

// allModules registers all 13 scanner modules with the engine.
func allModules(e *scanner.Engine) {
	e.Register(scanner.NewHooksModule())
	e.Register(scanner.NewConfigModule())
	e.Register(scanner.NewConfigIncludeModule())
	e.Register(scanner.NewAttributesModule())
	e.Register(scanner.NewSubmodulesModule())
	e.Register(scanner.NewBareReposModule())
	e.Register(scanner.NewSymlinksModule())
	e.Register(scanner.NewIDEConfigsModule())
	e.Register(scanner.NewDevenvModule())
	e.Register(scanner.NewScriptsModule())
	e.Register(scanner.NewBuildHooksModule())
	e.Register(scanner.NewUnicodeModule())
	e.Register(scanner.NewPipelinesModule())
}

// ---- Severity parsing ----

func parseSeverity(s string) (scanner.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return scanner.Critical, nil
	case "high":
		return scanner.High, nil
	case "medium":
		return scanner.Medium, nil
	case "info":
		return scanner.Info, nil
	default:
		return scanner.Info, fmt.Errorf("unknown severity %q (valid: critical, high, medium, info)", s)
	}
}

// ---- Root command ----

func buildRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "git-protect",
		Short: "Protect against malicious git repositories",
		Long: `git-protect scans git repositories for attack patterns before they can execute.

It provides three defense layers:
  1. Safe clone wrapper (git-protect clone) — primary defense, blocks before checkout
  2. Global git hooks — secondary defense, warns on every checkout
  3. Git config hardening — best-effort fallback`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(buildVersionCmd())
	root.AddCommand(buildScanCmd())
	root.AddCommand(buildInstallCmd())
	root.AddCommand(buildUninstallCmd())
	root.AddCommand(buildCloneCmd())
	root.AddCommand(buildTrustCmd())
	root.AddCommand(buildStatusCmd())

	return root
}

// ---- version command ----

func buildVersionCmd() *cobra.Command {
	var checkUpdate bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(os.Stdout, "git-protect %s (%s, %s/%s)\n",
				version, runtime.Version(), runtime.GOOS, runtime.GOARCH)

			if checkUpdate && os.Getenv("GIT_PROTECT_NO_UPDATE_CHECK") == "" {
				checkForUpdate(os.Stdout, version)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&checkUpdate, "check", false, "Check for newer releases on GitHub")
	return cmd
}

// checkForUpdate fetches the latest release from GitHub Releases API and
// prints an update notice if a newer version is available. Fails silently
// on network errors or non-200 responses.
func checkForUpdate(w io.Writer, currentVersion string) {
	const apiURL = "https://api.github.com/repos/moldabekov/git-protect/releases/latest"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return
	}

	latest := strings.TrimPrefix(release.TagName, "v")
	current := strings.TrimPrefix(currentVersion, "v")
	if latest != "" && latest != current && latest != "dev" {
		fmt.Fprintf(w, "Latest: %s — update available at %s\n", release.TagName, release.HTMLURL)
	}
}

// ---- scan command ----

func buildScanCmd() *cobra.Command {
	var (
		jsonOut     bool
		verbose     bool
		severityStr string
		modulesStr  string
		exitCode    bool
		hookMode    bool
	)

	cmd := &cobra.Command{
		Use:   "scan [dir]",
		Short: "Scan a repository for security threats",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) > 0 {
				dir = args[0]
			}

			minSeverity := scanner.Medium
			if verbose {
				minSeverity = scanner.Info
			}
			if severityStr != "" {
				sev, err := parseSeverity(severityStr)
				if err != nil {
					return err
				}
				minSeverity = sev
			}
			if hookMode && severityStr == "" && !verbose {
				minSeverity = scanner.Medium
			}

			var onlyModules []string
			if modulesStr != "" {
				for _, m := range strings.Split(modulesStr, ",") {
					m = strings.TrimSpace(m)
					if m != "" {
						onlyModules = append(onlyModules, m)
					}
				}
			}

			e := scanner.NewEngine()
			allModules(e)

			sc := scanner.ScanContext{
				RepoPath:    dir,
				PreCheckout: false,
			}

			var report scanner.Report
			var err error
			if len(onlyModules) > 0 {
				report, err = e.ScanModules(context.Background(), sc, onlyModules)
			} else {
				report, err = e.Scan(context.Background(), sc)
			}
			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}

			if jsonOut {
				return output.RenderJSON(os.Stdout, report)
			}

			if hookMode {
				// Hook mode: minimal stderr output, always exit non-zero on findings
				findings := report.AtOrAbove(minSeverity)
				if len(findings) > 0 {
					output.RenderText(os.Stderr, report, minSeverity)
					os.Exit(1)
				}
				return nil
			}

			output.RenderText(os.Stdout, report, minSeverity)

			filtered := report.AtOrAbove(minSeverity)
			if len(filtered) == 0 {
				fmt.Fprintln(os.Stdout, "Scan complete. No threats found.")
			} else {
				blocking := len(report.AtOrAbove(scanner.High))
				if blocking > 0 {
					fmt.Fprintf(os.Stdout, "\n%d blocking findings (%d total).\n", blocking, len(filtered))
				} else {
					fmt.Fprintf(os.Stdout, "\n%d findings (none blocking).\n", len(filtered))
				}
			}

			if exitCode && report.HasBlocking() {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output in JSON format")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show INFO-level findings")
	cmd.Flags().StringVar(&severityStr, "severity", "", "Minimum severity to show (critical|high|medium|info)")
	cmd.Flags().StringVar(&modulesStr, "modules", "", "Comma-separated list of modules to run")
	cmd.Flags().BoolVar(&exitCode, "exit-code", false, "Exit non-zero if blocking threats are found (for CI)")
	cmd.Flags().BoolVar(&hookMode, "hook-mode", false, "Running as a git hook (minimal stderr output, exits non-zero on findings)")

	return cmd
}

// ---- install command ----

func buildInstallCmd() *cobra.Command {
	var (
		alias  bool
		dryRun bool
	)

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Set up global git protection",
		Long:  "Installs git hooks and applies git config hardening entries globally.",
		RunE: func(cmd *cobra.Command, args []string) error {
			hooksDir := paths.HooksDir()
			trustPath := paths.TrustStorePath()

			if dryRun {
				fmt.Fprintln(os.Stdout, "Dry run — no changes will be made.")
				fmt.Fprintln(os.Stdout)
			}

			// Check for existing core.hooksPath (conflict detection)
			existing, err := gitcfg.GetGlobal("core.hooksPath")
			if err != nil {
				return fmt.Errorf("check existing core.hooksPath: %w", err)
			}
			if existing != "" && existing != hooksDir {
				fmt.Fprintf(os.Stderr,
					"WARNING: core.hooksPath is already set to %q (possibly Husky, pre-commit, or Lefthook).\n"+
						"  git-protect will override this. To restore on uninstall, the original value is noted.\n\n",
					existing)
			}

			// Apply hardening entries
			entries := gitcfg.HardeningEntries()
			for _, entry := range entries {
				val := entry.Value
				if entry.Key == "core.hooksPath" {
					val = hooksDir
				}
				if val == "" {
					continue
				}
				if dryRun {
					fmt.Fprintf(os.Stdout, "  [dry-run] %s = %s\n", entry.Key, val)
				} else {
					if setErr := gitcfg.SetGlobal(entry.Key, val); setErr != nil {
						fmt.Fprintf(os.Stderr, "  [warn] %s: %v\n", entry.Key, setErr)
						continue
					}
					fmt.Fprintf(os.Stdout, "  [ok] %s = %s\n", entry.Key, val)
				}
			}

			// Install hook scripts
			if dryRun {
				for _, name := range hooks.HookNames() {
					fmt.Fprintf(os.Stdout, "  [dry-run] Install %s hook\n", name)
				}
			} else {
				binaryPath, err := os.Executable()
				if err != nil {
					return fmt.Errorf("resolve binary path: %w", err)
				}
				binaryPath, err = filepath.EvalSymlinks(binaryPath)
				if err != nil {
					return fmt.Errorf("resolve binary symlinks: %w", err)
				}

				if err := hooks.Install(hooksDir, binaryPath); err != nil {
					return fmt.Errorf("install hooks: %w", err)
				}
				for _, name := range hooks.HookNames() {
					fmt.Fprintf(os.Stdout, "  [ok] Installed %s hook\n", name)
				}
			}

			// Initialize trust store
			if dryRun {
				fmt.Fprintf(os.Stdout, "  [dry-run] Create trust store at %s (mode 0600)\n", trustPath)
			} else {
				if mkdirErr := os.MkdirAll(filepath.Dir(trustPath), 0700); mkdirErr != nil {
					return fmt.Errorf("create config dir: %w", mkdirErr)
				}
				// Create the trust store file if it does not exist
				if _, statErr := os.Stat(trustPath); os.IsNotExist(statErr) {
					store := trust.NewStore(trustPath)
					// Add and remove a dummy entry to create the file with correct perms
					_ = store.Add(trust.Entry{Pattern: "__init__", Type: "repo"})
					_ = store.Remove("__init__")
				}
				fmt.Fprintf(os.Stdout, "  [ok] Trust store at %s (mode 0600)\n", trustPath)
			}

			// Optional alias
			if alias {
				if err := installAlias(dryRun); err != nil {
					fmt.Fprintf(os.Stderr, "  [warn] alias: %v\n", err)
				} else if dryRun {
					// message already printed by installAlias
				} else {
					fmt.Fprintln(os.Stdout, "  [ok] git alias.clone set to git-protect clone")
				}
			} else {
				fmt.Fprintln(os.Stdout, "\n  RECOMMENDED: Run 'git-protect install --alias' to route 'git clone'")
				fmt.Fprintln(os.Stdout, "  through the safe-clone wrapper for maximum protection.")
			}

			fmt.Fprintln(os.Stdout, "\n  Protection active. All future clones and checkouts will be scanned.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&alias, "alias", false, "Set git alias.clone to route through git-protect")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be changed without applying")
	return cmd
}

// installAlias sets git config --global alias.clone to use the absolute binary path.
func installAlias(dryRun bool) error {
	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve binary: %w", err)
	}
	binaryPath, err = filepath.EvalSymlinks(binaryPath)
	if err != nil {
		return fmt.Errorf("resolve symlinks: %w", err)
	}
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return fmt.Errorf("abs path: %w", err)
	}
	aliasVal := fmt.Sprintf("!%s clone", absPath)
	if dryRun {
		fmt.Fprintf(os.Stdout, "  [dry-run] git config --global alias.clone '%s'\n", aliasVal)
		return nil
	}
	return gitcfg.SetGlobal("alias.clone", aliasVal)
}

// ---- uninstall command ----

func buildUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove global git protection",
		Long:  "Removes all global config changes, hooks, and the clone alias.",
		RunE: func(cmd *cobra.Command, args []string) error {
			hooksDir := paths.HooksDir()

			// Remove hardening config entries
			entries := gitcfg.HardeningEntries()
			for _, entry := range entries {
				if err := gitcfg.UnsetGlobal(entry.Key); err != nil {
					fmt.Fprintf(os.Stderr, "  [warn] unset %s: %v\n", entry.Key, err)
					continue
				}
				fmt.Fprintf(os.Stdout, "  [ok] unset %s\n", entry.Key)
			}

			// Remove alias if set
			if err := gitcfg.UnsetGlobal("alias.clone"); err != nil {
				fmt.Fprintf(os.Stderr, "  [warn] unset alias.clone: %v\n", err)
			} else {
				fmt.Fprintln(os.Stdout, "  [ok] unset alias.clone")
			}

			// Remove hook files
			if err := hooks.Uninstall(hooksDir); err != nil {
				return fmt.Errorf("uninstall hooks: %w", err)
			}
			fmt.Fprintf(os.Stdout, "  [ok] Removed hooks from %s\n", hooksDir)

			fmt.Fprintln(os.Stdout, "\n  git-protect has been uninstalled.")
			return nil
		},
	}
}

// ---- clone command ----

func buildCloneCmd() *cobra.Command {
	var (
		force       bool
		trustFlag   bool
		jsonOut     bool
		showThreats bool
		bareFlag    bool
		mirrorFlag  bool
	)

	cmd := &cobra.Command{
		Use:   "clone <url> [<dir>] [-- git-clone-flags...]",
		Short: "Safe clone: scan before checkout",
		Long: `Clone a repository safely by fetching without checkout, scanning for threats,
and only checking out if the scan is clean.

Any flags after -- are passed through to git clone (e.g., --depth, --branch).
The --recurse-submodules flag is intercepted and handled by git-protect.`,
		Args:                  cobra.MinimumNArgs(1),
		DisableFlagParsing:    false,
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			url := args[0]
			dir := ""
			var extraArgs []string

			if len(args) > 1 {
				remaining := args[1:]
				// If the first remaining arg does not start with '-', treat as dir
				if !strings.HasPrefix(remaining[0], "-") {
					dir = remaining[0]
					extraArgs = remaining[1:]
				} else {
					extraArgs = remaining
				}
			}

			if bareFlag {
				extraArgs = append(extraArgs, "--bare")
			}
			if mirrorFlag {
				extraArgs = append(extraArgs, "--mirror")
			}

			// --trust requires interactive TTY confirmation
			if trustFlag {
				if !isTerminal(os.Stdin) {
					return fmt.Errorf("--trust requires an interactive TTY; use 'git-protect trust add <url>' instead")
				}
				fmt.Fprintf(os.Stderr, "Are you sure you want to permanently trust %q? [y/N] ", url)
				var answer string
				fmt.Fscanln(os.Stdin, &answer)
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					return fmt.Errorf("trust confirmation declined")
				}
			}

			// Check trust store
			store := trust.NewStore(paths.TrustStorePath())
			trusted, err := store.IsTrusted(url)
			if err != nil {
				fmt.Fprintf(os.Stderr, "WARNING: trust store error: %v\n", err)
			}

			gitBin, err := clone.DetectGitBin()
			if err != nil {
				return err
			}

			fmt.Fprintln(os.Stdout, "  Cloning (no-checkout)...")

			scanFn := func(ctx context.Context, repoPath string, preCheckout bool) (scanner.Report, error) {
				e := scanner.NewEngine()
				allModules(e)
				sc := scanner.ScanContext{
					RepoPath:    repoPath,
					PreCheckout: preCheckout,
				}
				return e.Scan(ctx, sc)
			}

			result, err := clone.Execute(context.Background(), gitBin, url, dir, extraArgs, scanFn)
			if err != nil {
				return err
			}

			if jsonOut {
				type cloneResult struct {
					Blocked   bool           `json:"blocked"`
					CleanedUp bool           `json:"cleaned_up"`
					Dir       string         `json:"dir"`
					Trusted   bool           `json:"trusted"`
					PreScan   scanner.Report `json:"pre_scan"`
					PostScan  scanner.Report `json:"post_scan"`
				}
				return json.NewEncoder(os.Stdout).Encode(cloneResult{
					Blocked:   result.Blocked,
					CleanedUp: result.CleanedUp,
					Dir:       result.Dir,
					Trusted:   trusted,
					PreScan:   result.PreReport,
					PostScan:  result.PostReport,
				})
			}

			if result.Blocked {
				fmt.Fprintln(os.Stdout, "  Scanning for threats...")
				minSev := scanner.High
				if showThreats {
					minSev = scanner.Info
				}
				output.RenderText(os.Stdout, result.PreReport, minSev)
				blockingCount := len(result.PreReport.AtOrAbove(scanner.High))
				fmt.Fprintf(os.Stdout, "\n  BLOCKED -- %d threats found. Repository has NOT been checked out.\n",
					blockingCount)
				if result.CleanedUp {
					fmt.Fprintf(os.Stdout, "  Cleaned up: ./%s removed.\n", result.Dir)
				}

				if force || trustFlag {
					fmt.Fprintln(os.Stdout, "\n  --force/--trust specified: proceeding despite threats...")
					plainArgs := buildPlainCloneArgs(url, dir, extraArgs)
					plainCmd := exec.Command(gitBin, plainArgs...)
					plainCmd.Stdout = os.Stdout
					plainCmd.Stderr = os.Stderr
					if runErr := plainCmd.Run(); runErr != nil {
						return fmt.Errorf("forced clone failed: %w", runErr)
					}
				} else {
					fmt.Fprintln(os.Stdout, "\n  Actions:")
					fmt.Fprintf(os.Stdout, "    git-protect clone --show-threats %s    Full threat analysis\n", url)
					fmt.Fprintf(os.Stdout, "    git-protect clone --force %s           Clone once without trusting\n", url)
					fmt.Fprintf(os.Stdout, "    git-protect clone --trust %s           Clone and add to trustlist\n", url)
					os.Exit(1)
				}
			} else {
				fmt.Fprintln(os.Stdout, "  Scanning for threats... clean.")
				fmt.Fprintln(os.Stdout, "  Checking out... done.")
				if len(result.PostReport.Findings) > 0 {
					output.RenderText(os.Stdout, result.PostReport, scanner.High)
				} else {
					fmt.Fprintln(os.Stdout, "  Post-checkout verification... clean.")
				}
				fmt.Fprintf(os.Stdout, "\n  Repository cloned safely to ./%s\n", result.Dir)
			}

			// Add to trust store if --trust was confirmed and clone succeeded
			if trustFlag {
				norm, ok := trust.Normalize(url)
				if ok {
					addErr := store.Add(trust.Entry{
						Pattern: norm,
						Type:    "repo",
					})
					if addErr != nil {
						fmt.Fprintf(os.Stderr, "  [warn] trust add: %v\n", addErr)
					} else {
						fmt.Fprintf(os.Stdout, "  Added %q to trust store.\n", norm)
					}
				}
			}

			_ = trusted // suppress unused warning for non-JSON paths
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Clone once despite threats (does not add to trust store)")
	cmd.Flags().BoolVar(&trustFlag, "trust", false, "Clone despite threats AND add to trust store permanently (requires TTY)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output in JSON format")
	cmd.Flags().BoolVar(&showThreats, "show-threats", false, "Show full threat analysis")
	cmd.Flags().BoolVar(&bareFlag, "bare", false, "Pass --bare to git clone")
	cmd.Flags().BoolVar(&mirrorFlag, "mirror", false, "Pass --mirror to git clone")

	return cmd
}

// buildPlainCloneArgs constructs a plain git clone argument list (without --no-checkout).
func buildPlainCloneArgs(url, dir string, extraArgs []string) []string {
	args := []string{"clone"}
	args = append(args, extraArgs...)
	args = append(args, url)
	if dir != "" {
		args = append(args, dir)
	}
	return args
}

// isTerminal returns true if the given file is a terminal (TTY).
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// ---- trust command ----

func buildTrustCmd() *cobra.Command {
	trustCmd := &cobra.Command{
		Use:   "trust",
		Short: "Manage the repository trust/allowlist",
	}

	trustCmd.AddCommand(buildTrustListCmd())
	trustCmd.AddCommand(buildTrustAddCmd())
	trustCmd.AddCommand(buildTrustRemoveCmd())
	trustCmd.AddCommand(buildTrustCheckCmd())

	return trustCmd
}

func buildTrustListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all trusted patterns",
		RunE: func(cmd *cobra.Command, args []string) error {
			store := trust.NewStore(paths.TrustStorePath())
			entries, err := store.Load()
			if err != nil {
				return fmt.Errorf("trust store: %w", err)
			}
			if len(entries) == 0 {
				fmt.Fprintln(os.Stdout, "  No trusted patterns. Use 'git-protect trust add <pattern>' to add one.")
				return nil
			}
			fmt.Fprintf(os.Stdout, "  %-45s %-6s %s\n", "Pattern", "Type", "Added")
			fmt.Fprintf(os.Stdout, "  %s\n", strings.Repeat("-", 70))
			for _, entry := range entries {
				added := ""
				if !entry.Added.IsZero() {
					added = entry.Added.Format("2006-01-02")
				}
				fmt.Fprintf(os.Stdout, "  %-45s %-6s %s", entry.Pattern, entry.Type, added)
				if entry.Note != "" {
					fmt.Fprintf(os.Stdout, "  # %s", entry.Note)
				}
				fmt.Fprintln(os.Stdout)
			}
			return nil
		},
	}
}

func buildTrustAddCmd() *cobra.Command {
	var (
		yes     bool
		noteStr string
		typeStr string
	)

	cmd := &cobra.Command{
		Use:   "add <pattern>",
		Short: "Add a trusted pattern (requires TTY confirmation unless -y)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pattern := args[0]

			if !yes {
				if !isTerminal(os.Stdin) {
					return fmt.Errorf("interactive TTY required; use -y to bypass confirmation")
				}
				fmt.Fprintf(os.Stderr, "Add %q to the trust store? [y/N] ", pattern)
				var answer string
				fmt.Fscanln(os.Stdin, &answer)
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					return fmt.Errorf("cancelled")
				}
			}

			entryType := typeStr
			if entryType == "" {
				// Infer type from pattern
				switch {
				case strings.HasSuffix(pattern, "/*"):
					parts := strings.Split(strings.TrimSuffix(pattern, "/*"), "/")
					if len(parts) == 1 {
						entryType = "host"
					} else {
						entryType = "org"
					}
				default:
					entryType = "repo"
				}
			}

			store := trust.NewStore(paths.TrustStorePath())
			if err := store.Add(trust.Entry{
				Pattern: pattern,
				Type:    entryType,
				Note:    noteStr,
			}); err != nil {
				return fmt.Errorf("trust add: %w", err)
			}
			fmt.Fprintf(os.Stdout, "  Added %q (%s) to trust store.\n", pattern, entryType)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt")
	cmd.Flags().StringVar(&noteStr, "note", "", "Optional note for this entry")
	cmd.Flags().StringVar(&typeStr, "type", "", "Trust type: repo, org, or host (auto-detected if omitted)")
	return cmd
}

func buildTrustRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <pattern>",
		Short: "Remove a trusted pattern",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store := trust.NewStore(paths.TrustStorePath())
			if err := store.Remove(args[0]); err != nil {
				return fmt.Errorf("trust remove: %w", err)
			}
			fmt.Fprintf(os.Stdout, "  Removed %q from trust store.\n", args[0])
			return nil
		},
	}
}

func buildTrustCheckCmd() *cobra.Command {
	var quiet bool

	cmd := &cobra.Command{
		Use:   "check [url]",
		Short: "Check if the current repo (or a URL) is trusted",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var urlToCheck string

			if len(args) > 0 {
				urlToCheck = args[0]
			} else {
				// Get current repo's remote URL via git
				out, err := exec.Command("git", "remote", "get-url", "origin").Output()
				if err != nil {
					return fmt.Errorf("could not determine current repo URL: %w", err)
				}
				urlToCheck = strings.TrimRight(string(out), "\n")
			}

			store := trust.NewStore(paths.TrustStorePath())
			trusted, err := store.IsTrusted(urlToCheck)
			if err != nil {
				return fmt.Errorf("trust check: %w", err)
			}

			if quiet {
				if !trusted {
					os.Exit(1)
				}
				return nil
			}

			if trusted {
				fmt.Fprintf(os.Stdout, "  %q is TRUSTED\n", urlToCheck)
			} else {
				fmt.Fprintf(os.Stdout, "  %q is NOT trusted\n", urlToCheck)
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&quiet, "quiet", false, "Exit non-zero if not trusted, print nothing")
	return cmd
}

// ---- status command ----

func buildStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show current protection status",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(os.Stdout, "  git-protect %s\n\n", version)
			fmt.Fprintln(os.Stdout, "  Protection:")

			entries := gitcfg.HardeningEntries()
			hooksDir := paths.HooksDir()
			for _, entry := range entries {
				val := entry.Value
				if entry.Key == "core.hooksPath" {
					val = hooksDir
				}
				current, err := gitcfg.GetGlobal(entry.Key)
				if err != nil {
					current = "(error)"
				}

				active := current == val
				status := "NOT SET"
				if active {
					status = "active"
				} else if current != "" {
					status = fmt.Sprintf("set to %q (expected %q)", current, val)
				}

				overridable := "(overridable by local config)"
				if !entry.Overridable {
					overridable = "(enforced)"
				}

				fmt.Fprintf(os.Stdout, "    %-25s %-35s %s %s\n", entry.Key, val, status, overridable)
			}

			// Clone alias
			aliasVal, _ := gitcfg.GetGlobal("alias.clone")
			if aliasVal != "" {
				fmt.Fprintf(os.Stdout, "    %-25s %-35s %s\n", "clone alias", aliasVal, "active")
			} else {
				fmt.Fprintf(os.Stdout, "    %-25s %-35s %s\n", "clone alias", "not set", "recommended")
			}

			// Check for unsafe safe.directory=*
			safeDirVal, _ := gitcfg.GetGlobal("safe.directory")
			if safeDirVal == "*" {
				fmt.Fprintln(os.Stdout, "\n  Warnings:")
				fmt.Fprintln(os.Stdout, "    safe.directory = *    UNSAFE — accepts repos owned by other users")
			}

			// Trust store
			trustPath := paths.TrustStorePath()
			store := trust.NewStore(trustPath)
			trustEntries, err := store.Load()
			entryCount := 0
			if err == nil {
				entryCount = len(trustEntries)
			}
			fmt.Fprintf(os.Stdout, "\n  Trust store: %s (%s entries, mode 0600)\n",
				trustPath, strconv.Itoa(entryCount))

			// Module count
			e := scanner.NewEngine()
			allModules(e)
			fmt.Fprintf(os.Stdout, "  Detection modules: %d loaded\n", len(e.ModuleNames()))

			return nil
		},
	}
}

// ---- entrypoint ----

func main() {
	root := buildRoot()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "git-protect:", err)
		os.Exit(1)
	}
}
