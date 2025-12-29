# Zimara: Pre-Push Security Sweep

**Published by Oob Skulden™**

A bash script that catches the "oh shit" moments before they hit production. Runs locally, exits fast, blocks bad commits.

**Version:** 0.44.0  
**Tagline:** "The threats you don't see coming"

---

## What It Does

Zimara runs **33 security checks** before you push code:

- Private keys (hard stop)
- `.env` files in git
- Hardcoded API keys and passwords
- Secrets in build output
- Internal IPs in production builds
- Debug files you forgot about
- Large accidental commits
- CI/CD secret leakage
- OAuth tokens in frontend code
- Third-party scripts without integrity checks
- Forms submitting over HTTP
- PII in analytics
- Serverless function vulnerabilities

Plus checks for git hygiene, dependency vulns, DNS takeover risks, and more.

Each check is numbered. Exit codes are predictable. No network calls required.

---

## Why This Exists

Security incidents usually start with:

```bash
git add .
git commit -m "quick fix"
git push
```

Then you realize your API key is public.

Zimara catches that **before it leaves your machine**. It's not enterprise SAST. It's a pre-flight checklist.

**Every check in this script exists because these mistakes happen in real projects.**

---

## Threat Model

### In Scope

- **Accidental credential exposure** - API tokens, secrets, private keys committed to Git
- **Unsafe artifacts** - Backup files, debug output, temporary files accidentally tracked
- **Static output leakage** - Internal IPs, localhost references, `.git/` exposure in published output
- **Configuration drift** - Mixed HTTP/HTTPS content warnings, environment-specific values leaking
- **Operational mistakes** - Large unintended files, dependency vulnerabilities surfaced late
- **Supply chain risks** - Unvetted third-party themes or modules

### Explicitly Out of Scope

- Advanced code exploitation or vulnerability discovery
- Runtime vulnerabilities (XSS, CSRF, SQL injection in dynamic applications)
- Authentication or authorization logic flaws
- Deep dependency graph analysis or supply chain attacks
- Adversarial code review or penetration testing
- Network-level security or infrastructure hardening

**If you need those capabilities, you want a real SAST pipeline and human security review - not a Bash script.**

---

## Supported Platforms

- **Linux** (Debian, Ubuntu tested)
- **macOS** (basic compatibility)
- Git-based workflows (GitHub, GitLab, Bitbucket)

Zimara is written in POSIX-compatible Bash and avoids non-portable dependencies.

### Static Site Generators

Auto-detects:

- **Hugo** → `public/`
- **Jekyll** → `_site/`
- **Astro** → `dist/`
- **Next.js** → `out/`
- **Eleventy** → `_site/`
- **Generic** → common patterns

Override with `OUTPUT_DIR=custom/path ./zimara.sh`

---

## Requirements

### Minimal

- `bash` (version 4.0+)
- `git`
- Standard Unix utilities (`grep`, `find`, `sed`, `cut`, `wc`, `du`)

### Optional

- **npm** - Enables dependency audit (CHECK 16)
- **gitleaks** - Best-in-class secret scanning
- **detect-secrets** - Yelp's secrets detection
- **git-secrets** - AWS Labs secrets prevention

No external scanners, package managers, or network access required for core functionality.

---

## Installation

### Quick Install

```bash
curl -O https://raw.githubusercontent.com/oob-skulden/zimara/main/zimara.sh
chmod +x zimara.sh
```

Verify:
```bash
./zimara.sh --version
```

### System-Wide Install

```bash
sudo mv zimara.sh /usr/local/bin/zimara
sudo chmod +x /usr/local/bin/zimara
```

Then run from anywhere:
```bash
zimara
```

---

## Usage

### Basic Usage

From your repository root:

```bash
zimara
```

This scans the current directory with default settings.

### Common Options

```bash
# CI/CD mode (no prompts, fail on HIGH/CRITICAL)
zimara --non-interactive

# Skip build output scanning (faster for commits)
zimara --skip-output

# Scan only build output
zimara --only-output

# Allow output dir in git (for GitHub Pages, etc.)
zimara --include-output-in-source

# Check version
zimara --version

# Get help
zimara --help
```

---

## Exit Codes

Zimara uses explicit exit codes for predictable automation:

| Exit Code | Severity | Meaning | Action |
|-----------|----------|---------|--------|
| `0` | None | No issues found | ✅ Safe to push |
| `1` | Medium/Low | Non-blocking issues detected | ⚠️ Review findings; your call |
| `2` | High | High-severity issues detected | 🛑 Fix before pushing |
| `3` | Critical | Credentials, private keys, major exposure | 🚨 **DO NOT PUSH** |
| `99` | - | Invalid usage/directory not found | - |

### Using Exit Codes in Scripts

```bash
#!/bin/bash

zimara --non-interactive

case $? in
  0)
    echo "✅ Security checks passed"
    git push
    ;;
  1)
    echo "⚠️ Minor issues - review recommended"
    # Optional: prompt user
    git push
    ;;
  2)
    echo "🛑 High-severity issues - fix required"
    exit 2
    ;;
  3)
    echo "🚨 CRITICAL issues - DO NOT PUSH"
    exit 3
    ;;
esac
```

---

## Security Checks Reference

Zimara executes 33 numbered checks. Here are the highlights:

### Critical Severity (Exit 3)

1. **Private Keys** - SSH, TLS certs, anything with BEGIN PRIVATE KEY
2. **Environment Files** - .env and variants
3. **Secrets in Output** - Config files, keys in published build
4. **Front Matter Secrets** - API keys in Markdown metadata
5. **CI/CD Secret Leaks** - GitHub Actions echoing secrets
6. **Serverless Creds** - Hardcoded tokens in functions
7. **OAuth client_secret** - In frontend code
8. **Typosquatting Packages** - Malicious npm lookalikes

### High Severity (Exit 2)

9. **Hardcoded Credentials** - API keys in code
10. **Debug Files** - phpinfo.php, .sql dumps, test.html
11. **Build Env Exposure** - Netlify commands leaking vars
12. **Output Committed** - Build artifacts in git
13. **CORS Wildcards** - Functions allowing any origin
14. **SQL in Functions** - Without parameterization
15. **Forms over HTTP** - Unencrypted submissions
16. **Analytics PII** - Email in Google Analytics
17. **Build Downloads** - Curl'ing unknown sources

### Medium Severity (Exit 1)

18. **Large Files** - Anything over 10MB
19. **Internal URLs** - localhost, 192.168.x.x in output
20. **Mixed Content** - http:// on https:// pages
21. **Source Maps** - Exposing original code
22. **Missing .gitignore** - Or incomplete patterns
23. **Dependency Vulns** - npm audit findings
24. **Git History** - Sensitive files in old commits
25. **Third-party Modules** - Unvetted dependencies
26. **Sensitive Sitemap Paths** - /admin, /internal
27. **Scripts Without SRI** - CDN scripts, no integrity hash
28. **mailto: Forms** - Email harvesting risk
29. **Implicit OAuth** - Deprecated flow
30. **localStorage Tokens** - XSS vulnerable
31. **DNS Takeover Refs** - Links to orphaned subdomains
32. **Custom npm Registry** - Non-official source

### Low Severity (Exit 1)

33. **Email/Phone Exposure** - Contact info in output
34. **Protocol-relative URLs** - //cdn.example.com
35. **Demo Content** - Lorem ipsum placeholders
36. **Missing .gitignore Patterns** - Incomplete coverage
37. **Dev Comments** - TODO, FIXME in HTML
38. **Missing Security Headers** - X-Frame-Options, CSP
39. **Identity Leaks** - Personal git config
40. **No Pre-commit Hooks** - Missing prevention
41. **Client IDs Visible** - OAuth IDs (normal but verify)
42. **No CSRF Tokens** - Forms without protection
43. **Stale Key Rotation** - 90+ days unchanged

Check numbering is stable across releases to support automation and documentation.

---

## Secret Scanner Integration

Zimara works with external tools when available:

```bash
# Auto-detect gitleaks, detect-secrets, or git-secrets
zimara

# Force specific tool
SECRET_TOOL=gitleaks zimara

# Skip external scanning
SECRET_TOOL=none zimara
```

Install any of: gitleaks, detect-secrets, git-secrets. Zimara auto-uses them.

**Configuration files:**

- **gitleaks:** `.gitleaks.toml` (auto-detected)
- **detect-secrets:** `.secrets.baseline` (auto-detected)

---

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `SHOW_MATCHES` | Lines to show per finding | 5 |
| `OUTPUT_DIR` | Override output directory | Auto-detect |
| `SECRET_TOOL` | Scanner (auto/gitleaks/detect-secrets/git-secrets/none) | auto |
| `SECRET_BASELINE` | detect-secrets baseline file | .secrets.baseline |
| `GITLEAKS_CONFIG` | gitleaks config file | .gitleaks.toml |

Examples:

```bash
# Show only 3 matches per finding
SHOW_MATCHES=3 zimara

# Custom output directory
OUTPUT_DIR=build zimara

# Force gitleaks
SECRET_TOOL=gitleaks zimara
```

---

## Git Hook Integration

### Recommended Pre-Commit Hook

```bash
#!/usr/bin/env bash
set -u

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT" || exit 1

AUDIT_SCRIPT="/usr/local/bin/zimara"

# Explicit bypass (auditable)
if [[ "${SKIP_ZIMARA:-0}" == "1" ]]; then
  echo "ℹ️  SKIP_ZIMARA=1 set; skipping Zimara audit."
  exit 0
fi

# Verify script exists
if [[ ! -x "$AUDIT_SCRIPT" ]]; then
  echo "🚨 Zimara not found: $AUDIT_SCRIPT"
  echo ""
  echo "Install with:"
  echo "  curl -O https://raw.githubusercontent.com/oob-skulden/zimara/main/zimara.sh"
  echo "  chmod +x zimara.sh"
  echo "  sudo mv zimara.sh /usr/local/bin/zimara"
  echo ""
  echo "Or bypass once:"
  echo "  SKIP_ZIMARA=1 git commit -m 'your message'"
  exit 1
fi

# Optional: only run on site-relevant files
STAGED="$(git diff --cached --name-only || true)"
if [[ -n "$STAGED" ]]; then
  if ! echo "$STAGED" | grep -Eq '^(content/|layouts/|static/|assets/|data/|config\.|hugo\.|netlify\.toml|package\.json|package-lock\.json|\.env|\.gitignore|functions/|\.github/)'; then
    echo "ℹ️  No site-relevant files staged; skipping Zimara audit."
    exit 0
  fi
fi

echo "🔒 Running Zimara Security Audit before commit..."
echo ""

"$AUDIT_SCRIPT" "$REPO_ROOT" --skip-output --non-interactive
EXIT_CODE=$?

echo ""

case "$EXIT_CODE" in
  0)
    echo "✅ Security audit passed"
    exit 0
    ;;
  1)
    echo "⚠️  MEDIUM/LOW security issues found (commit allowed)"
    echo "    Recommended: review and fix when practical."
    echo ""
    echo "To review:"
    echo "  zimara --skip-output"
    exit 0
    ;;
  2)
    echo "❌ HIGH security issues found — must fix before committing"
    echo ""
    echo "Run for details:"
    echo "  zimara --skip-output"
    echo ""
    echo "To bypass (not recommended):"
    echo "  SKIP_ZIMARA=1 git commit -m 'your message'"
    exit 1
    ;;
  3)
    echo "🚨 CRITICAL security issues found — must fix immediately"
    echo ""
    echo "Run for details:"
    echo "  zimara --skip-output"
    echo ""
    echo "DO NOT bypass - fix the issues or remove them from staging:"
    echo "  git reset HEAD <file>"
    exit 1
    ;;
  *)
    echo "⚠️  Unexpected error from security audit (exit code: $EXIT_CODE)"
    echo ""
    echo "To bypass:"
    echo "  SKIP_ZIMARA=1 git commit -m 'your message'"
    exit 1
    ;;
esac
```

**Install:**

```bash
# From your repository root
cat > .git/hooks/pre-commit << 'EOF'
[paste hook above]
EOF

chmod +x .git/hooks/pre-commit
```

**Intentional Bypass:**

```bash
SKIP_ZIMARA=1 git commit -m "commit message"
```

---

## CI/CD Integration

Zimara can be used in CI as a fast, early-fail signal, but it is **not** a replacement for:

- Secret scanning (GitHub Secret Scanning, GitLab Secret Detection)
- Dependency vulnerability scanning (Dependabot, Snyk, WhiteSource)
- SAST / DAST (CodeQL, Semgrep, SonarQube)

### Example GitHub Actions

```yaml
name: Security

on: [push, pull_request]

jobs:
  zimara:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full history for git checks
      
      - name: Set up Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
        if: hashFiles('package.json') != ''
      
      - name: Install dependencies
        run: npm ci
        if: hashFiles('package.json') != ''
      
      - name: Install gitleaks
        run: |
          wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
          tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
          sudo mv gitleaks /usr/local/bin/
      
      - name: Run Zimara
        run: |
          chmod +x zimara.sh
          ./zimara.sh --non-interactive
        env:
          SECRET_TOOL: gitleaks
```

**Typical CI usage:** Many teams fail CI on exit codes ≥ 2.

---

## Design Philosophy

Zimara favors:

- **Clarity over cleverness** - Readable checks, predictable behavior
- **Deterministic results** - Same input = same output
- **Zero network calls** - Works offline
- **Stable check numbering** - For docs and automation
- **Fits real workflows** - Security that doesn't get removed

**If a security tool is painful to use, people remove it. Zimara stays enabled.**

---

## What Zimara Does NOT Do

Zimara does not:

- Replace CI security tooling (GitHub Secret Scanning, Dependabot, CodeQL)
- Perform dependency vulnerability analysis (use Snyk, npm audit, OWASP Dependency-Check)
- Scan live services or deployed infrastructure
- Phone home or require network access
- Provide penetration testing or threat modeling
- Analyze runtime vulnerabilities (XSS, CSRF, SQL injection)

**Zimara is a local pre-flight check.** Fast, deterministic, zero dependencies.

For production: use GitHub scanning, Dependabot, actual SAST tools.

---

## Sample Output

Example output (abbreviated):

```text
==============================================
🔒 Zimara 🔒  (v0.44.0)
==============================================

Directory scanned: /home/user/my-site
Generator detected: hugo
Output dir detected: public
Mode: Non-interactive (CI/CD)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CHECK 1: Private Keys (HARD STOP)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ No private keys found

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CHECK 2: Environment / Secrets Files
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ No .env files found

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CHECK 3: Hardcoded Credentials
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  Possible hardcoded credentials [HIGH]
  config.toml:42: api_key = "sk_test_xxxxxxxxxx"
Actions:
  • Replace with env vars / secret manager references
  • Rotate exposed values

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CHECK X: Enhanced Secret Scanning (optional tools)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ℹ️  Using gitleaks
✓ gitleaks: no secrets found

[... additional checks ...]

==============================================
🔒 FINAL SECURITY SUMMARY 🔒
==============================================

Generator detected: hugo
Output dir detected: public

🚨 CRITICAL: 0 issue(s) - FIX IMMEDIATELY
⚠️  HIGH:     2 issue(s) - Fix soon
⚠️  MEDIUM:   3 issue(s) - Address when possible
ℹ️  LOW:      1 issue(s) - Nice to fix

Priority actions (in order):
  1. ⚠️  Address HIGH priority issues
  2. ⚠️  Review MEDIUM priority issues
  3. ℹ️  Consider LOW priority improvements

==============================================
Generated by: 🦛 Published by Oob Skulden™ 🦛
"The threats you don't see coming"
==============================================
```

**Exit code:** 2 (HIGH severity issues detected)

---

## Future Enhancements

### Short-Term

- **JSON output mode (`--json`)** - Structured output for CI/CD automation
- **Fail-on threshold flag (`--fail-on high|critical`)** - Severity-based exit behavior
- **Common fixes quick reference** - Actionable next steps after final summary

### Medium-Term

- **Configuration file support** - `.zimara.yml` for project-specific settings
- **Parallel scanning** - Multi-threaded for repos with 10,000+ files
- **Additional generators** - Docusaurus, VuePress, Gatsby, Nuxt.js

### Long-Term

- **Plugin system** for custom checks
- **Interactive mode** with fix/ignore/defer prompts
- **Security dashboard integration**

---

## Contributing

Contributions welcome for bug fixes, additional generators, secret patterns, and documentation.

**Guidelines:**

1. Keep the script opinionated and focused on real-world exploitability
2. Maintain backward compatibility for flags and exit codes
3. Document all new checks with severity rationale
4. Respect the Oob Skulden™ trademark usage rules
5. Test against multiple static site generators

**Before submitting a PR:**

1. Test against multiple generators
2. Verify exit codes remain consistent
3. Update README if adding features
4. Run the script against itself: `zimara`

---

## License

**Published by Oob Skulden™**

MIT License (for the code).

Oob Skulden™ is a trademark. USPTO registration pending.

---

## Support and Contact

- **Issue Tracker:** https://github.com/oob-skulden/zimara/issues
- **Discussions:** https://github.com/oob-skulden/zimara/discussions
- **Security Guides:** https://oobskulden.com/security-guides

**Found a security issue in Zimara itself?**

Please reach out to me in any of the forms found on my website **Ook Skulden** https://oobskulden.com

---

## Acknowledgments

Zimara is informed by real-world incident response experience, OWASP guidance, and lessons learned from open-source tooling such as:

- gitleaks
- detect-secrets
- git-secrets

Zimara intentionally remains self-contained to avoid dependency drift and environment-specific failures.

The tool emerged organically while securing and publishing a production static website (https://oobskulden.com), where recurring risks and overlooked edge cases shaped its scope and checks over time.

---

**Published by Oob Skulden™**  
**"The threats you don't see coming"**  
**🦛 95% underwater 🦛**