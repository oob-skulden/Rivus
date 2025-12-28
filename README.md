# Rivus: Ultimate Security Audit Script

**Published by Oob Skulden™**

Pre-push security sweep for static sites and web projects (Hugo, Jekyll, Astro, Next.js export, Eleventy, and generic static generators).

**Version:** 0.42.1  
**Tagline:** “The threats you don’t see coming”

-----

## Table of Contents

- [What It Does](#what-it-does)
- [Why This Exists](#why-this-exists)
- [Threat Model](#threat-model)
- [Supported Platforms](#supported-platforms)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Options and Flags](#options-and-flags)
- [Exit Codes](#exit-codes)
- [Generator Detection](#generator-detection)
- [Security Checks Reference](#security-checks-reference)
- [Environment Variables](#environment-variables)
- [Sample Output](#sample-output)
- [What This Does NOT Do](#what-this-does-not-do)
- [CI/CD Integration Guidance](#cicd-integration-guidance)
- [Future Enhancements](#future-enhancements)
- [Contributing](#contributing)
- [License](#license)

-----

## What It Does

Rivus is a fast, local security audit script you run before pushing changes to production. It performs **24 comprehensive security checks** focused on the most common “oops” moments that later become incident tickets.

### Core Security Checks

- **Private keys and certificates** (SSH, TLS/SSL, PGP, signing keys) - **hard stop**
- **Environment files** (.env, .env.local, .env.production, etc.)
- **Hardcoded credentials** in config files and code
- **Optional external secret scanning** (gitleaks, detect-secrets, git-secrets integration)
- **Sensitive files in build output** (.git/, config files, keys)
- **Internal URL/IP leakage** (localhost, 127.0.0.1, RFC1918 private IPs)
- **Large files** (>10MB - potential database dumps or accidental commits)
- **Debug/test artifacts** (test.html, debug.log, phpinfo.php, .sql files)
- **Email/phone scraping risk** in output
- **Mixed content issues** (http:// in HTTPS pages)
- **Default/demo content** (Lorem ipsum, example.com, placeholder text)
- **.gitignore coverage** (missing critical patterns)
- **Hardcoded credentials in code directories**
- **Sensitive HTML comments** (TODO, DEBUG, passwords in comments)
- **Security headers** in netlify.toml
- **Metadata/identity leaks** (git config, draft markers)
- **Dependency vulnerabilities** (npm audit integration)
- **Git history analysis** (sensitive files in commit history)
- **Module/theme supply chain** (third-party dependencies)
- **Custom shortcode injection risks** (Hugo-specific)
- **Netlify build environment exposure** (env vars in build logs)
- **RSS/sitemap unintended disclosure** (drafts, sensitive paths)
- **Front matter secrets** (API keys in Markdown metadata)
- **Pre-commit hook validation** (ensuring hooks exist)
- **Output directory hygiene** (build artifacts committed to git)

### Smart Detection

Rivus automatically:

- Detects your static site generator (Hugo, Jekyll, Astro, Next.js, Eleventy, or generic)
- Identifies the most likely output directory (`public/`, `dist/`, `_site/`, `out/`, `build/`)
- Supports optional integration with best-in-class secret scanners (gitleaks, detect-secrets, git-secrets)
- Provides severity-based exit codes for automation
- Runs output-based checks only when output directory exists

-----

## Why This Exists

Most security incidents don’t start with zero-days or nation-state actors.

They start with small, human mistakes:

- A debug file left behind
- A token copied “just for testing”
- A local URL that leaks into production output
- A build artifact that exposes more than intended
- An API key committed to front matter “temporarily”

**Every check in this script exists because these mistakes happen in real projects.**

Rivus exists to catch those issues **before** they leave your machine.

It’s designed for:

- Solo operators building and publishing sites
- Small teams without dedicated security resources
- Engineers who want a fast, local safety net
- Projects that can’t wait for CI, code review, or a security team to notice after the fact

**Think of it as a seatbelt, not an airbag.**

-----

## Threat Model

Rivus is intentionally scoped. It focuses on **high-probability, low-friction failure modes**, not theoretical edge cases.

### In Scope

- **Accidental credential exposure**
  - API tokens, secrets, private keys committed to Git
  - Environment variables hardcoded in config files
  - Database credentials in connection strings
  - API keys in front matter or comments
- **Unsafe artifacts**
  - Backup files, debug output, temporary files accidentally tracked
  - Editor swap files (.swp, .swo), OS-specific temp files
  - Development-only scripts or utilities
  - Test databases or SQL dumps
- **Static output leakage**
  - Internal IPs, localhost references, `.git/` exposure in published output
  - Configuration files (.env, config.yml, etc.) in build output
  - Source maps in production builds
  - Private keys or certificates in output directory
- **Configuration drift**
  - Mixed HTTP/HTTPS content warnings
  - Environment-specific values leaking into production builds
  - Development URLs hardcoded in production output
  - Internal infrastructure topology exposed
- **Operational mistakes**
  - Large unintended files committed (database dumps, media archives)
  - Dependency vulnerabilities surfaced late
  - Build processes that expose secrets in logs
  - Output directories committed to version control
- **Supply chain risks**
  - Unvetted third-party themes or modules
  - Missing or incompatible licenses
  - Untracked theme versions (copied vs. git submodule)

### Explicitly Out of Scope

- Advanced code exploitation or vulnerability discovery
- Runtime vulnerabilities (XSS, CSRF, SQL injection in dynamic applications)
- Authentication or authorization logic flaws
- Deep dependency graph analysis or supply chain attacks
- Adversarial code review or penetration testing
- Network-level security or infrastructure hardening

**If you need those capabilities, you want a real SAST pipeline and human security review - not a Bash script.**

-----

## Supported Platforms

Rivus is designed for static sites and web projects, including:

- **Hugo** - Go-based static site generator
- **Jekyll** - Ruby-based static site generator
- **Astro** - Modern web framework with island architecture
- **Next.js** - React framework with static export capability (output: `out/` or `.next/`)
- **Eleventy (11ty)** - Flexible Node-based static site generator
- **Generic static output** - Detects common output directories (`public/`, `dist/`, `_site/`, `out/`, `build/`)

The script attempts to auto-detect your generator and output directory so checks run safely and accurately.

-----

## Requirements

### Operating System

- **Linux** (Debian, Ubuntu, and similar distributions)
- **macOS** (basic compatibility - some checks may need adjustment)

### Minimal Requirements

These tools must be available in your `PATH`:

- `bash` (version 4.0 or higher recommended)
- `grep`
- `find`
- `sed`
- `cut`
- `wc`
- `du`

### Optional Dependencies

These tools enable additional checks when present:

- **git** - Enables Git history and tracked-file checks
- **npm** - Enables dependency audit section (CHECK 16)
- **gitleaks** - Best-in-class secret scanning (optional external scanner)
- **detect-secrets** - Yelp’s secrets detection (optional external scanner)
- **git-secrets** - AWS Labs secrets prevention (optional external scanner)

-----

## Installation

### Quick Install

1. Download the script:

```bash
curl -O https://raw.githubusercontent.com/oob-skulden/rivus/main/rivus.sh
```

1. Make it executable:

```bash
chmod +x rivus.sh
```

1. Run it:

```bash
./rivus.sh
```

### System-Wide Install

To make Rivus available system-wide:

```bash
sudo mv rivus.sh /usr/local/bin/rivus
sudo chmod +x /usr/local/bin/rivus
```

Then run from anywhere:

```bash
rivus
```

### Git Hook Integration

To run Rivus automatically before every push:

```bash
# From your repository root
cat > .git/hooks/pre-push << 'EOF'
#!/bin/bash
./rivus.sh
exit $?
EOF

chmod +x .git/hooks/pre-push
```

-----

## Usage

### Basic Usage

Run from your repository root:

```bash
./rivus.sh
```

This scans the current directory with default settings.

### Scan Specific Directory

```bash
./rivus.sh /path/to/your/repo
```

### Check Version

```bash
./rivus.sh --version
```

### Get Help

```bash
./rivus.sh --help
```

-----

## Options and Flags

### Scan Only Output Directory: `--only-output`

Scan **only** the output directory (public/, dist/, out/, _site/), skipping all source code checks.

Useful for validating a clean build before deployment.

**Usage:**

```bash
./rivus.sh --only-output
```

**What gets checked:**

- Sensitive files in output
- Internal URLs/IPs in output
- Email/phone scraping risk
- Mixed content
- Default/demo content
- Sensitive HTML comments
- RSS/sitemap disclosure

**What gets skipped:**

- All source code checks (private keys, env files, credentials, etc.)
- Git history analysis
- Dependency audits
- .gitignore validation

-----

### Skip Output Directory Scanning: `--skip-output`

Skip all output directory checks, scanning **only** source code.

Useful when you don’t have a build yet or want to focus on source security.

**Usage:**

```bash
./rivus.sh --skip-output
```

**What gets skipped:**

- All output-based checks (internal URLs, mixed content, etc.)

**What still runs:**

- Private key detection
- Environment file checks
- Hardcoded credential scanning
- Git history analysis
- All source code security checks

-----

### Allow Output in Git: `--include-output-in-source`

Suppresses the warning when output directory is tracked by git.

Use this for projects that intentionally commit build output (GitHub Pages, etc.).

**Usage:**

```bash
./rivus.sh --include-output-in-source
```

**Note:** Most Netlify/Vercel deployments should **not** commit output - they build on deploy.

-----

### Combining Flags

Flags can be combined in a single command:

```bash
# Scan only output, allow it to be tracked
./rivus.sh --only-output --include-output-in-source

# Skip output checks entirely
./rivus.sh --skip-output
```

-----

## Exit Codes

Rivus exits with severity-aware codes so results can be interpreted consistently by humans, shell scripts, or automation pipelines.

|Exit Code|Severity  |Meaning                                                             |Action                                     |
|--------:|----------|--------------------------------------------------------------------|-------------------------------------------|
|`0`      |None      |No issues found                                                     |✅ Safe to push                             |
|`1`      |Low/Medium|Non-blocking issues detected                                        |⚠️ Review findings; push only if intentional|
|`2`      |High      |High-severity issues detected                                       |🛑 Fix before pushing                       |
|`3`      |Critical  |Critical issues detected (credentials, private keys, major exposure)|🚨 **DO NOT PUSH**                          |

### Using Exit Codes in Scripts

```bash
#!/bin/bash

./rivus.sh

case $? in
  0)
    echo "✅ Security checks passed - proceeding with deployment"
    git push
    ;;
  1)
    echo "⚠️ Minor security issues found - review recommended"
    read -p "Proceed anyway? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      git push
    fi
    ;;
  2)
    echo "🛑 High-severity issues found - fix required"
    exit 2
    ;;
  3)
    echo "🚨 CRITICAL security issues found - DO NOT PUSH"
    exit 3
    ;;
esac
```

-----

## Generator Detection

Rivus automatically detects your static site generator and expected output directory:

|Generator   |Detection Method                         |Typical Output Dir                            |
|------------|-----------------------------------------|----------------------------------------------|
|**Hugo**    |`config.toml`, `config.yaml`, `hugo.toml`|`public/`                                     |
|**Jekyll**  |`_config.yml`, `_config.yaml`            |`_site/`                                      |
|**Astro**   |`astro.config.*` (mjs/js/ts)             |`dist/`                                       |
|**Next.js** |`next.config.*` (js/mjs/ts)              |`out/` (or `.next/`)                          |
|**Eleventy**|`.eleventy.js`, `eleventy.config.js`     |`_site/`                                      |
|**Generic** |Fallback detection                       |`public/`, `dist/`, `build/`, `_site/`, `out/`|

### Output Directory Resolution

Rivus checks for output directories in this priority order:

1. **Environment variable override:** `OUTPUT_DIR=custom/path ./rivus.sh`
1. Generator-specific default (e.g., `public/` for Hugo)
1. Common alternatives scanned in order

**If no output directory is found:**

- Output-based checks are skipped
- A warning is displayed
- Only repository-level checks run

-----

## Security Checks Reference

Rivus performs **24 distinct security checks** organized by severity. Each check is documented below with detection patterns, severity rationale, and remediation actions.

### CHECK 1: Private Keys (HARD STOP)

**Severity:** 🚨 CRITICAL  
**Exit Code:** 3

**What it detects:**

- SSH private keys (`.pem`, `.key` files)
- TLS/SSL certificates (`.p12`, `.pfx` files)
- Any file containing `-----BEGIN PRIVATE KEY-----`
- Any file containing `-----BEGIN RSA PRIVATE KEY-----`

**Why it matters:**

Private key exposure means immediate compromise. Attackers can impersonate your servers, decrypt traffic, or gain unauthorized access.

**Actions on finding:**

- Remove immediately from repository
- Rotate/revoke all exposed keys
- Purge from git history using `git filter-repo` or BFG Repo Cleaner
- Investigate if keys were already pushed to public repos

-----

### CHECK 2: Environment / Secrets Files

**Severity:** 🚨 CRITICAL  
**Exit Code:** 3

**What it detects:**

- Any `.env` file (`.env.local`, `.env.production`, `.env.development`, etc.)

**Why it matters:**

Environment files typically contain database credentials, API keys, and other secrets. They should **never** be committed to version control.

**Actions on finding:**

- Remove from repository immediately
- Add `.env*` to `.gitignore`
- Rotate any exposed credentials
- Use environment variables or secret managers instead

-----

### CHECK 3: Hardcoded Credentials

**Severity:** ⚠️ HIGH  
**Exit Code:** 2

**What it detects:**

Patterns like:

```
password = "actual_password_here"
api_key: "sk_live_xxxxxxxxxx"
secret = 'my-secret-value'
token: "ghp_xxxxxxxxxxxx"
```

**Why it matters:**

Hardcoded credentials in config files are easily discovered by attackers scanning public repositories.

**Actions on finding:**

- Replace with environment variable references
- Rotate all exposed values
- Use secret management tools (Vault, AWS Secrets Manager, etc.)

-----

### CHECK X: Enhanced Secret Scanning (Optional External Tools)

**Severity:** 🚨 CRITICAL (if findings detected)  
**Exit Code:** 3

**What it does:**

Integrates with best-in-class secret scanning tools:

- **gitleaks** - High-accuracy secret detection with verification
- **detect-secrets** - Yelp’s baseline-driven approach
- **git-secrets** - AWS Labs prevention tool

**Configuration:**

Set via `SECRET_TOOL` environment variable:

```bash
# Auto-detect (default)
./rivus.sh

# Force specific tool
SECRET_TOOL=gitleaks ./rivus.sh
SECRET_TOOL=detect-secrets ./rivus.sh
SECRET_TOOL=git-secrets ./rivus.sh

# Disable external scanning
SECRET_TOOL=none ./rivus.sh
```

**Custom configuration files:**

- **gitleaks:** `.gitleaks.toml` (auto-detected)
- **detect-secrets:** `.secrets.baseline` (auto-detected)

**Why it matters:**

External tools provide deeper, more accurate secret detection than regex patterns alone. They catch secrets you might miss manually.

-----

### CHECK 4: Sensitive Files in Output Directory

**Severity:** 🚨 CRITICAL  
**Exit Code:** 3

**What it detects:**

- `.git/` directory in output (exposes entire git history!)
- Config files (`.toml`, `.env`, `.yaml`)
- Private keys (`.key`, `.pem`, `.p12`, `.pfx`)
- Source maps (`.map` files) - MEDIUM severity

**Why it matters:**

Your output directory becomes publicly accessible when deployed. Any sensitive files there are immediately exposed to the internet.

**Actions on finding:**

- Ensure `.git/` never gets published (check build/deploy settings)
- Move config files outside output directory
- Disable source maps for production or restrict access via web server rules

-----

### CHECK 5: Internal URLs/IPs Exposed

**Severity:** ⚠️ MEDIUM (in output)  
**Exit Code:** 1

**What it detects:**

References to:

- `localhost`
- `127.0.0.1`
- `192.168.x.x` (RFC1918 Class C private networks)
- `10.x.x.x` (RFC1918 Class A private networks)
- `172.16-31.x.x` (RFC1918 Class B private networks)
- `.local` domains
- `.internal` domains
- `docker.sock` references

**Why it matters:**

Exposing internal infrastructure topology helps attackers map your network and identify attack targets.

**Actions on finding:**

- Verify `baseURL` setting is production URL
- Rebuild with production configuration flags
- Check for development-specific config leaking into builds

-----

### CHECK 6: Large Files (>10MB)

**Severity:** ⚠️ MEDIUM  
**Exit Code:** 1

**What it detects:**

Any file larger than 10MB in the repository

**Why it matters:**

Large files are often:

- Accidental database dumps
- Media files that should be in CDN/object storage
- Binary artifacts that bloat repository history

**Actions on finding:**

- If accidental: remove and clean git history
- If intentional: use Git LFS or move to CDN/object storage (S3, CloudFront, etc.)

-----

### CHECK 7: Debug/Test Files

**Severity:** ⚠️ HIGH  
**Exit Code:** 2

**What it detects:**

- `test.html`
- `debug.log`
- Editor swap files (`.swp`, `.swo`)
- OS-specific files (`.DS_Store`, `Thumbs.db`)
- `phpinfo.php` (extremely dangerous!)
- `.sql` files (database dumps)

**Why it matters:**

Debug artifacts reveal internal implementation details and may contain credentials or sensitive data.

**Actions on finding:**

- Remove debug artifacts
- Add patterns to `.gitignore`
- Verify `.sql` files aren’t database dumps with real data

-----

### CHECK 8: Email/Phone Scraping Risk

**Severity:** ℹ️ LOW  
**Exit Code:** 1

**What it detects:**

- Email addresses in output (`user@example.com`)
- Phone numbers in output (`(555) 123-4567`, `555-123-4567`)

**Why it matters:**

Publicly exposed contact info gets scraped by spammers and attackers for phishing campaigns.

**Actions on finding:**

- If intentional: consider email obfuscation or contact forms
- If unintentional: remove and rebuild

-----

### CHECK 9: Mixed Content (HTTP/HTTPS)

**Severity:** ⚠️ MEDIUM  
**Exit Code:** 1

**What it detects:**

- `http://` references in output (excluding W3C schema URLs)
- Protocol-relative URLs (`//cdn.example.com/script.js`) - LOW severity

**Why it matters:**

Mixed content warnings break browser security, downgrade HTTPS connections, and hurt SEO.

**Actions on finding:**

- Switch all assets to `https://` URLs
- Prefer explicit `https://` over protocol-relative URLs

-----

### CHECK 10: Default/Demo Content

**Severity:** ℹ️ LOW  
**Exit Code:** 1

**What it detects:**

Placeholder content like:

- `example.com`
- `Your Name Here`
- `Lorem ipsum`
- `Demo Site`
- `Test Site`

**Why it matters:**

Placeholder content makes your site look unprofessional and incomplete.

**Actions on finding:**

- Replace all placeholder text with real content

-----

### CHECK 11: .gitignore Configuration

**Severity:** ⚠️ MEDIUM (if missing) / ℹ️ LOW (if incomplete)  
**Exit Code:** 1

**What it detects:**

Missing `.gitignore` file or missing critical patterns:

- `*.bak`
- `*.backup*`
- `.env`
- `*.key`
- `*.pem`
- `*.log`
- `.DS_Store`

**Why it matters:**

Without proper `.gitignore`, sensitive files easily get committed accidentally.

**Actions on finding:**

- Create `.gitignore` if missing
- Add recommended patterns
- Consider generator-specific templates (Hugo, Jekyll, etc.)

-----

### CHECK 12: Hardcoded Credentials in Code Dirs

**Severity:** ⚠️ HIGH  
**Exit Code:** 2

**What it detects:**

Searches common code directories for hardcoded credentials:

**Directories scanned:** `content/`, `layouts/`, `themes/`, `static/`, `src/`, `app/`, `lib/`, `pages/`

**Patterns:**

```
password = "..."
api_key: "..."
secret = "..."
token: "..."
```

**Why it matters:**

Credentials in code are easier to miss than in config files, yet equally dangerous.

**Actions on finding:**

- Replace with environment variable references
- Rotate exposed credentials
- Use secret injection at build/runtime

-----

### CHECK 13: Sensitive HTML Comments

**Severity:** ℹ️ LOW  
**Exit Code:** 1

**What it detects:**

HTML comments containing:

- `TODO`
- `DEBUG`
- `FIXME`
- `XXX`
- `HACK`
- `password`, `token`, `key`

**Why it matters:**

Comments are visible in page source and may reveal sensitive information or internal details.

**Actions on finding:**

- Remove development comments before publishing
- Consider build-time comment stripping

-----

### CHECK 14: Security Headers in netlify.toml

**Severity:** ℹ️ LOW  
**Exit Code:** 1

**What it detects:**

Missing security headers in `netlify.toml`:

- `X-Frame-Options`
- `X-Content-Type-Options`
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `Permissions-Policy`
- `Referrer-Policy`

**Why it matters:**

Security headers protect against common web attacks (clickjacking, XSS, MIME sniffing).

**Actions on finding:**

- Add recommended security headers to Netlify configuration
- Test headers with security scanners (securityheaders.com)

-----

### CHECK 15: Metadata/Identity Leaks

**Severity:** ℹ️ LOW  
**Exit Code:** 1

**What it detects:**

- Git config name not set to brand identity
- Git config email not using noreply address
- Draft markers in content (`[TODO]`, `[DRAFT]`, `[PLACEHOLDER]`)

**Why it matters:**

Personal identity in git metadata can compromise pseudonymous publishing. Draft markers indicate incomplete content.

**Actions on finding:**

- Set per-repo git identity:
  
  ```bash
  git config user.name "Oob Skulden"
  git config user.email "noreply@github.com"
  ```
- Remove draft markers before publishing

-----

### CHECK 16: Dependency Vulnerabilities (npm audit)

**Severity:** ⚠️ MEDIUM (depends on vulnerability count)  
**Exit Code:** 1

**What it detects:**

Runs `npm audit --json` if `package.json` exists

Reports:

- Total vulnerability count
- Severity breakdown (critical/high/moderate/low)

**Why it matters:**

Known vulnerabilities in dependencies are low-hanging fruit for attackers.

**Actions on finding:**

- Run `npm audit fix` to auto-update
- Review breaking changes for major version bumps
- Consider `npm audit fix --force` for critical issues
- Update lockfile hygiene

-----

### CHECK 17: Git History Analysis

**Severity:** ⚠️ MEDIUM  
**Exit Code:** 1

**What it detects:**

Sensitive file extensions in git commit history:

- `.env`
- `.key`
- `.pem`
- `.p12`
- `.pfx`
- `.backup`
- `.bak`

**Why it matters:**

Even deleted files remain in git history forever (until force-purged). Secrets in history are still accessible to attackers.

**Actions on finding:**

- Use `git filter-repo` (recommended) or BFG Repo Cleaner
- Rotate all secrets that were ever in history
- Force push to rewrite remote history (coordinate with team!)

-----

### CHECK 18: Module/Theme Supply Chain

**Severity:** ⚠️ MEDIUM  
**Exit Code:** 1

**What it detects:**

**For Hugo projects with `go.mod`:**

- Third-party modules (non-gohugoio sources)

**For projects with `themes/` directory:**

- Git-tracked themes (good - version controlled)
- Copied themes without version tracking (bad - security risk)
- Missing LICENSE files
- GPL-licensed themes (license compatibility warning)

**Why it matters:**

Third-party themes and modules can:

- Inject malicious code
- Have unpatched vulnerabilities
- Create license compliance issues

**Actions on finding:**

- Pin module versions in `go.mod`
- Use git submodules or Hugo modules for themes (not copied files)
- Review theme/module source code before use
- Check license compatibility

-----

### CHECK 19: Custom Shortcode Injection Risks (Hugo)

**Severity:** ⚠️ MEDIUM  
**Exit Code:** 1

**What it detects:**

In `layouts/shortcodes/*.html`, looks for dynamic content functions:

- `.Get` (shortcode parameters)
- `.Inner` (shortcode content)
- `readFile` (filesystem reads)
- `getJSON` / `getCSV` (remote data fetching)

**Why it matters:**

Hugo shortcodes with dynamic input can create injection vulnerabilities if untrusted content is rendered.

**Actions on finding:**

- Sanitize shortcode parameters before rendering
- Avoid rendering untrusted external data
- Consider whether shortcode needs to be dynamic

-----

### CHECK 20: Netlify Build Env Exposure

**Severity:** ⚠️ HIGH  
**Exit Code:** 2

**What it detects:**

In `netlify.toml`, looks for build commands that echo environment variables:

```toml
[build]
  command = "echo $SECRET_KEY && npm run build"
```

**Why it matters:**

Netlify build logs are often public. Echoing env vars exposes secrets in logs.

**Additional checks:**

- Explicit `publish` directory setting (LOW if missing)

**Actions on finding:**

- Remove echo/print statements from build commands
- Set publish directory explicitly
- Review build logs for accidental secret exposure

-----

### CHECK 21: RSS/Sitemap Information Leaks

**Severity:** ⚠️ HIGH (drafts in RSS) / ⚠️ MEDIUM (sensitive paths)  
**Exit Code:** 2 or 1

**What it detects:**

**In `index.xml` (RSS feed):**

- Draft markers indicating unpublished content

**In `sitemap.xml`:**

- Sensitive path segments: `admin`, `private`, `internal`, `test`, `staging`

**Why it matters:**

RSS feeds and sitemaps are public discovery mechanisms. Including drafts or sensitive paths helps attackers map your site.

**Actions on finding:**

- Ensure drafts are excluded from production builds
- Remove sensitive paths from sitemap (or exclude via `robots.txt`)

-----

### CHECK 22: Front Matter Secrets

**Severity:** 🚨 CRITICAL  
**Exit Code:** 3

**What it detects:**

In Markdown front matter, looks for:

```yaml
---
api_key: "sk_live_xxxxxxxxxxxxxxxxxx"
token: "ghp_xxxxxxxxxxxxxxxxxxxx"
secret: "my-secret-value"
password: "actual-password"
---
```

**Why it matters:**

Front matter often gets overlooked during security reviews. Secrets here are just as exposed as anywhere else.

**Actions on finding:**

- Remove all secret values from front matter immediately
- Use environment variables or config files instead
- Rotate all exposed tokens/keys

-----

### CHECK 23: Pre-commit Hooks / Validation

**Severity:** ⚠️ MEDIUM (if missing) / ℹ️ LOW (if incomplete)  
**Exit Code:** 1

**What it detects:**

- Presence of `.git/hooks/pre-commit`
- Presence of `.pre-commit-config.yaml`
- Whether hooks include security keywords (secret, credential, key, token, trufflehog, gitleaks, detect-secrets)

**Why it matters:**

Pre-commit hooks provide automated prevention - the best kind of security.

**Actions on finding:**

- Install pre-commit framework: `pip install pre-commit`
- Add secret scanning hooks (gitleaks, detect-secrets, trufflehog)
- Add linting and formatting hooks
- Run `pre-commit install`

-----

### CHECK 24: Output Directory Committed (Build Artifact Hygiene)

**Severity:** ⚠️ HIGH  
**Exit Code:** 2

**What it detects:**

Whether output directory (public/, dist/, out/, _site/) is tracked by git

**Why it matters:**

For Netlify/Vercel deployments, committing build output is:

- Unnecessary (they build on deploy)
- Wasteful (bloats repo size)
- Risky (may contain environment-specific artifacts)

**Exceptions:**

GitHub Pages and some hosting platforms **do** require committed output. Use `--include-output-in-source` to suppress this warning.

**Actions on finding:**

```bash
# Remove tracked output
git rm -r --cached public/
echo "public/" >> .gitignore
git commit -m "Remove build output from version control"
```

-----

## Environment Variables

### `SHOW_MATCHES`

**Default:** 5  
**Purpose:** How many matching lines to display for each finding

```bash
# Show only 3 matches per finding
SHOW_MATCHES=3 ./rivus.sh

# Show all matches
SHOW_MATCHES=999 ./rivus.sh
```

-----

### `OUTPUT_DIR`

**Default:** Auto-detected based on generator  
**Purpose:** Override output directory detection

```bash
# Custom output directory
OUTPUT_DIR=build ./rivus.sh

# Multiple possible paths (first existing wins)
OUTPUT_DIR=dist ./rivus.sh
```

-----

### `SECRET_TOOL`

**Default:** `auto` (auto-detect available tool)  
**Purpose:** Select external secret scanning tool

**Options:**

- `auto` - Auto-detect (gitleaks → detect-secrets → git-secrets → none)
- `gitleaks` - Force gitleaks
- `detect-secrets` - Force detect-secrets
- `git-secrets` - Force git-secrets
- `none` - Disable external scanning

```bash
# Force gitleaks
SECRET_TOOL=gitleaks ./rivus.sh

# Disable external scanning
SECRET_TOOL=none ./rivus.sh
```

-----

### `SECRET_BASELINE`

**Default:** `.secrets.baseline`  
**Purpose:** Path to detect-secrets baseline file

```bash
SECRET_BASELINE=.secrets.custom.json ./rivus.sh
```

-----

### `GITLEAKS_CONFIG`

**Default:** `.gitleaks.toml`  
**Purpose:** Path to gitleaks configuration file

```bash
GITLEAKS_CONFIG=.gitleaks.custom.toml ./rivus.sh
```

-----

## Sample Output

Example output (abbreviated):

```text
==============================================
🔒 Rivus 🔒  (v0.42.1)
==============================================

Directory scanned: /home/user/my-site
Generator detected: hugo
Output dir detected: public

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

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CHECK 5: Internal URLs/IPs Exposed
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  Found 3 internal reference(s) [MEDIUM]
  public/index.html: http://localhost:1313/css/style.css
  public/about/index.html: http://192.168.1.100/api
  public/config.js: baseURL: 'http://localhost:1313'
Actions:
  • Verify baseURL / site URL settings for production
  • Rebuild with production flags

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

⚠️  Found 6 total security issue(s)

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

-----

## What This Does NOT Do

Rivus is **not** a complete SAST pipeline and does **not** replace:

### CI/CD Security Tools

- **GitHub Secret Scanning** - Deep secret detection with verified patterns
- **GitHub Push Protection** - Prevents commits with secrets from being pushed
- **Dependabot** - Automated dependency updates and vulnerability alerts
- **Snyk, Sonatype, WhiteSource** - Enterprise-grade dependency security

### Static Application Security Testing (SAST)

- **CodeQL** - Semantic code analysis for vulnerabilities
- **Semgrep** - Pattern-based code scanning with deep rules
- **SonarQube** - Code quality and security analysis
- **Checkmarx, Veracode, Fortify** - Commercial SAST platforms

### Advanced Security Analysis

- **Penetration testing** - Human-led security assessments
- **Code review** - Manual inspection for logic flaws
- **Runtime analysis** - DAST, IAST, RASP tooling
- **Threat modeling** - Architecture-level security design
- **Container scanning** - Docker/OCI image vulnerability detection

### What Rivus IS

A **pre-push gut check**: fast, local, opinionated, and useful.

- Catches common mistakes before they leave your machine
- Provides immediate feedback without waiting for CI
- Complements (not replaces) comprehensive security tooling
- Designed for solo operators and small teams
- Focused on **real-world exploitability** over theoretical risk

-----

## CI/CD Integration Guidance

While Rivus can run in CI/CD pipelines, **it’s designed as a local-first tool.**

### Why Local-First?

1. **Immediate feedback** - Catch issues before committing
1. **Faster iteration** - No waiting for CI to run
1. **Developer experience** - Fix locally, push clean code
1. **Cost savings** - Fewer CI minutes wasted on failing builds

### Recommended CI/CD Security Stack

Instead of relying solely on Rivus in CI, use:

1. **GitHub Secret Scanning + Push Protection** (or GitLab/Bitbucket equivalent)
1. **Dependabot** (or Renovate, WhiteSource Renovate)
1. **SAST tooling** (CodeQL, Semgrep, Snyk Code)
1. **Dependency scanning** (Snyk, npm audit, OWASP Dependency-Check)
1. **Rivus** (as pre-push local check OR supplementary CI step)

### If You DO Use Rivus in CI

Example GitHub Actions workflow:

```yaml
name: Security Audit

on: [push, pull_request]

jobs:
  rivus-audit:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full history for git-based checks
      
      - name: Set up Node.js (if using npm audit)
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install dependencies
        run: npm ci
        if: hashFiles('package.json') != ''
      
      - name: Install gitleaks (optional)
        run: |
          wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
          tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
          sudo mv gitleaks /usr/local/bin/
        
      - name: Run Rivus Security Audit
        run: |
          chmod +x rivus.sh
          ./rivus.sh
        env:
          SECRET_TOOL: gitleaks
      
      - name: Upload audit results (on failure)
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: rivus-audit-results
          path: |
            gitleaks-report-*.json
            .secrets.baseline
```

**Key points:**

- Use `fetch-depth: 0` for full Git history checks
- Install dependencies before running npm audit
- Install external secret scanners (gitleaks, detect-secrets) if desired
- Upload results as artifacts for review
- Consider `continue-on-error: true` for non-blocking warnings

-----

## Future Enhancements

Planned improvements that keep Rivus lean and opinionated:

### Short-Term (Next Release)

- **JSON output mode (`--json`)**
  - Emit structured JSON for CI pipelines, scripting, and automation
  - Keep human-readable output as default
  - Example: `./rivus.sh --json > results.json`
- **Fail-on threshold flag (`--fail-on high|critical`)**
  - Allow severity-based exit behavior
  - Enable stricter CI gates without changing check logic
  - Example: `./rivus.sh --fail-on critical` (exits non-zero only on CRITICAL findings)
- **Common fixes quick reference**
  - Print concise remediation guide after final summary
  - Actionable next steps for frequent findings

### Medium-Term

- **Configuration file support**
  - `.rivus.yml` or `rivus.config.json` for project-specific settings
  - Customize check severity, exclusions, thresholds
- **Parallel scanning for large repos**
  - Multi-threaded file scanning for repos with 10,000+ files
- **Additional generator support**
  - Docusaurus, VuePress, Gatsby, Nuxt.js static export

### Long-Term

- **Plugin system for custom checks**
- **Interactive mode** with fix/ignore/defer prompts
- **Integration with security dashboards**

-----

## Contributing

Contributions welcome for bug fixes, additional generators, secret patterns, and documentation.

**Guidelines:**

1. Keep the script opinionated and focused
1. Prioritize real-world exploitability over theoretical risks
1. Maintain backward compatibility for flags and exit codes
1. Document all new checks with severity rationale
1. Respect the Oob Skulden™ trademark usage rules

**Before submitting a PR:**

1. Test against multiple static site generators
1. Verify exit codes remain consistent
1. Update this README if adding features
1. Run the script against itself: `./rivus.sh`

-----

## License

**Published by Oob Skulden™**

Open Source: MIT License (script code)  
Trademark: Oob Skulden™ is a trademark pending USPTO registration.

-----

## Support and Contact

- **Issue Tracker:** https://github.com/oob-skulden/rivus/issues
- **Discussions:** https://github.com/oob-skulden/rivus/discussions
- **Security Guides:** https://oobskulden.com/security-guides

**Found a security issue in Rivus itself?**

Report privately to: security@oobskulden.com

-----

## Acknowledgments

Rivus builds on lessons from real-world incidents, open-source security tooling (gitleaks, detect-secrets, git-secrets), OWASP guidance, and practitioner feedback.

Special thanks to the gitleaks, detect-secrets, and git-secrets projects, and to the static site generator communities.

-----

**Published by Oob Skulden™**  
**“The threats you don’t see coming”**  
**🦛 95% underwater 🦛**
