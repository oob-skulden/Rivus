**Zimara Security Checks Reference**  
**Version 0.47.1**  
**Published by Oob Skulden™**

This document explains every security check Zimara runs, why it matters, and what to do when it finds something.

**Related Documentation:**
- [README.md](README.md) - Overview and quick start
- [INTEGRATION.md](INTEGRATION.md) - Git hooks and CI/CD setup


-----

## Table of Contents

- [How to Read This Guide](#how-to-read-this-guide)
- [Severity Levels](#severity-levels)
- [The Checks](#the-checks)
  - [Critical Severity](#critical-severity)
  - [High Severity](#high-severity)
  - [Medium Severity](#medium-severity)
  - [Low Severity](#low-severity)
  - [Informational](#informational)

-----

## How to Read This Guide

Each check follows the same structure:

**CHECK XX: Brief Description**  
**Severity:** Critical/High/Medium/Low/Info  
**Exit Code:** What Zimara returns if this check finds issues  
**What it detects:** Specific patterns and files  
**Why it matters:** Real-world impact  
**What to do:** Concrete remediation steps

We’ve organized checks by severity because that’s how you should prioritize fixes.

-----

## Severity Levels

**Critical (Exit 3)**: Drop everything and fix this. Do not push. Do not pass go.

**High (Exit 2)**: Fix before you push. These are real security problems.

**Medium (Exit 1)**: Should fix, but won’t burn down the house if you push first. Address soon.

**Low (Exit 1)**: Nice to clean up. More hygiene than emergency.

**Info (Exit 0)**: Just letting you know. No action required.

-----

## The Checks

### Critical Severity

These findings will stop you cold. Exit code 3. Non-negotiable.

-----

#### CHECK 03: Private Keys (Hard Stop)

**Severity:** Critical  
**Exit Code:** 3

**What it detects:**

Searches your entire repository for private key material:

- Files containing `BEGIN RSA PRIVATE KEY`
- Files containing `BEGIN DSA PRIVATE KEY`
- Files containing `BEGIN EC PRIVATE KEY`
- Files containing `BEGIN OPENSSH PRIVATE KEY`

The check scans source code (unless you use `--only-output`) and looks everywhere except `.git/`, `node_modules/`, and `vendor/`.

**Why it matters:**

Finding a private key in your repo means someone can impersonate your servers, decrypt your traffic, or gain unauthorized access to systems. This is a “stop the presses” moment.

Even if you delete the key in the next commit, it’s still in git history forever until you rewrite that history. Attackers scan public repos constantly looking for exactly this.

**What to do:**

1. Remove the key immediately from all files
1. Delete it from git history using `git filter-repo` or BFG Repo Cleaner:
   
   ```bash
   # Using git filter-repo (recommended)
   git filter-repo --path path/to/key.pem --invert-paths
   
   # Or using BFG (older but works)
   bfg --delete-files key.pem
   ```
1. Rotate/regenerate the exposed key on all systems
1. If you already pushed to a public repo, assume the key is compromised
1. Add the key pattern to `.gitignore` to prevent recurrence

**Prevention:**

Never store private keys in your repository. Use:

- Environment variables
- Secret management systems (Vault, AWS Secrets Manager, etc.)
- Encrypted key stores outside the repo
- SSH agent forwarding for deployment

-----

#### CHECK 07: Build Output Exposure

**Severity:** Critical (for .git or private keys in output)  
**Exit Code:** 3

**What it detects:**

Scans your build output directory for catastrophic exposure:

- `.git/` directory present in output
- Private key material in output files

**Why it matters:**

Your output directory becomes publicly accessible when you deploy. If `.git/` is in there, you’ve just published your entire git history to the internet. Every commit, every secret, every mistake—all public.

Private keys in output are equally bad. Your build process somehow copied sensitive material into what becomes your public website.

**What to do:**

If `.git/` is in output:

1. Check your build configuration to ensure it excludes `.git/`
1. Most build tools do this by default, so something’s misconfigured
1. Clean your output directory and rebuild
1. Review your deploy logs to see if this made it to production

If private keys are in output:

1. Figure out how they got there (bad copy command? misconfigured build step?)
1. Remove them and fix the build process
1. Rotate those keys immediately
1. Check if this already deployed (if yes, assume compromised)

**Prevention:**

For Hugo:

```toml
# hugo.toml
ignoreFiles = ["\\.git$"]
```

For most static site generators, this is default behavior. If you’re hitting this check, you’ve probably got a custom build script doing something wrong.

-----

#### CHECK 24: Exposed Config Files (Output)

**Severity:** Critical  
**Exit Code:** 3

**What it detects:**

Searches build output for sensitive file types:

- `.env` files (all variants)
- `.pem` files
- `.key` files
- `.p12` / `.pfx` files
- `.bak` / `.old` files

**Why it matters:**

These files have no business in your build output. They’re source-only artifacts that contain credentials, private keys, or sensitive configuration.

If your build process is copying them to output, your deployment makes them publicly accessible.

**What to do:**

1. Find out why these files ended up in output (check your build scripts)
1. Remove them and fix the build configuration
1. Verify these file types are excluded from builds
1. Check if this already deployed (especially `.env` files)
1. Rotate any secrets that were exposed

**Prevention:**

Ensure your static site generator config excludes these patterns:

```toml
# Hugo example
ignoreFiles = ["\.env$", "\.key$", "\.pem$", "\.p12$", "\.pfx$", "\.bak$", "\.old$"]
```

Most generators exclude these by default. If you’re hitting this, you likely have a manual copy step that’s too broad.

-----

### High Severity

Fix these before you push. Exit code 2.

-----

#### CHECK 04: Secrets Pattern Scan

**Severity:** High  
**Exit Code:** 2

**What it detects:**

Searches source code for common secret patterns:

- AWS access keys: `AKIA[0-9A-Z]{16}` or `ASIA[0-9A-Z]{16}`
- Slack tokens: `xox[baprs]-[0-9A-Za-z-]{10,}`
- GitHub tokens: `ghp_[0-9A-Za-z]{30,}` or `github_pat_[0-9A-Za-z_]{20,}`
- Google API keys: `AIza[0-9A-Za-z\-_]{35}`
- Generic private key headers
- `SECRET_KEY=` assignments
- `AWS_SECRET_ACCESS_KEY` references

**Why it matters:**

These patterns catch the most common “oh crap” moments: accidentally committing API keys, tokens, or secrets into code.

The patterns are conservative (high precision, lower recall) to minimize false positives. If Zimara flags something, take it seriously.

**What to do:**

1. Verify each match—are these real secrets or test/placeholder values?
1. For real secrets:

- Remove from code immediately
- Move to environment variables or secret management
- Rotate the exposed values

1. For test/placeholder values that look like secrets:

- Consider making them obviously fake (e.g., `AKIA00000000EXAMPLE`)
- Or move them to a documented test fixtures directory

**Prevention:**

Never hardcode secrets. Use:

```bash
# .env (gitignored)
API_KEY=actual_secret_value

# Code
api_key = os.getenv('API_KEY')
```

-----

#### CHECK 16: Risky Debug Artifacts (Output)

**Severity:** High  
**Exit Code:** 2

**What it detects:**

Scans output directory for dangerous debug files:

- `debug.log`
- `phpinfo.php` (extremely dangerous)
- `*.sql` files (potential database dumps)

**Why it matters:**

These files shouldn’t exist in production output:

- `phpinfo.php` exposes your entire PHP configuration (paths, versions, env vars)
- `.sql` files might be full database dumps with real data
- `debug.log` files often contain stack traces, credentials, or internal details

**What to do:**

1. Remove these files from output immediately
1. Check if they exist in source (if yes, add to `.gitignore`)
1. For SQL files: verify they’re not real data dumps
1. Review your build process to ensure debug artifacts are excluded
1. If this already deployed, check logs for exploitation attempts

**Prevention:**

Add to `.gitignore`:

```
*.log
*.sql
phpinfo.php
debug.*
```

Consider a pre-build cleanup step:

```bash
# Before building
find . -name "debug.log" -delete
find . -name "*.sql" -delete
```

-----

#### CHECK 19: Known Sensitive Filenames

**Severity:** High  
**Exit Code:** 2

**What it detects:**

Searches for common private key and certificate filenames:

- `id_rsa` (SSH private key)
- `id_ed25519` (modern SSH private key)
- `*.pem` (certificates, private keys)
- `*.p12` / `*.pfx` (PKCS#12 key containers)

**Why it matters:**

These are standard names for sensitive cryptographic material. They should never be in your repository.

Even if they’re not real keys (maybe they’re examples or documentation), having files named like this is a bad smell. Attackers will try to access them.

**What to do:**

1. Verify whether these are real keys or just unfortunately named files
1. For real keys:

- Remove immediately
- Purge from git history
- Rotate everywhere they were used

1. For non-keys with unfortunate names:

- Rename them to something obviously safe (e.g., `example-key.txt`)

**Prevention:**

Add to `.gitignore`:

```
id_rsa
id_ed25519
*.pem
*.p12
*.pfx
*.key
```

-----

#### CHECK 20: Output JS Key Exposure (Heuristic)

**Severity:** High  
**Exit Code:** 2

**What it detects:**

Scans JavaScript and HTML in output for API keys:

- Google API keys: `AIza[0-9A-Za-z\-_]{35}`
- AWS keys: `AKIA[0-9A-Z]{16}`
- Slack tokens: `xox[baprs]-[0-9A-Za-z-]{10,}`
- GitHub tokens: `ghp_[0-9A-Za-z]{30,}`

**Why it matters:**

Client-side JavaScript is public. Anyone can view source, and anyone can extract keys from it.

If you have API keys in your bundled JavaScript, those keys are now public. This is especially bad for keys that have broad permissions or access to paid services.

**What to do:**

1. Remove keys from client-side code immediately
1. Move API calls to a backend service or serverless function
1. Use API key restrictions (domain/IP whitelist) as a temporary mitigation
1. Rotate the exposed keys
1. Review your build process—are secrets leaking during bundle?

**Prevention:**

Don’t put secrets in frontend code. Ever. Use:

- Backend proxy endpoints for API calls
- Serverless functions (Netlify Functions, Vercel Edge Functions)
- Domain-restricted API keys as last resort (still not ideal)

-----

#### CHECK 25: Netlify Env Leak Heuristic

**Severity:** High  
**Exit Code:** 2

**What it detects:**

Scans `netlify.toml` for potential secret assignments:

- Lines matching `API_KEY=`
- Lines matching `SECRET=`
- Lines matching `TOKEN=`
- Lines matching `PASSWORD=`

**Why it matters:**

Your `netlify.toml` is typically committed to git. If you’re setting secrets directly in it, those secrets are in your repository history.

Netlify provides environment variables specifically to avoid this problem.

**What to do:**

1. Remove secret assignments from `netlify.toml`
1. Move them to Netlify’s environment variable UI (Site settings → Environment variables)
1. Update your build to reference env vars instead
1. Rotate any secrets that were in the file
1. Consider using Netlify’s secrets feature if available

**Prevention:**

In `netlify.toml`, reference env vars without defining them:

```toml
[build]
  command = "npm run build"
  
[build.environment]
  # Don't do this:
  # API_KEY = "actual_secret_value"
  
  # Instead, just document that the var is needed:
  # Required env vars (set in Netlify UI):
  # - API_KEY
  # - DATABASE_URL
```

Set actual values in Netlify dashboard, not in the file.

-----

### Medium Severity

Should fix, but won’t explode immediately. Exit code 1.

-----

#### CHECK 05: Backup/Temp Artifacts

**Severity:** Medium  
**Exit Code:** 1

**What it detects:**

Finds backup and temporary files:

- `*.bak`
- `*.old`
- `*.backup`
- `*.tmp`
- `*~` (Emacs/Vim backup files)

**Why it matters:**

Backup files often contain old versions of configuration with credentials that were “only temporary” but never removed. They’re also clutter that bloats your repository.

While not as immediately dangerous as active secrets, they represent security debt and technical debt.

**What to do:**

1. Review each backup file—does it contain anything sensitive?
1. Delete all backup/temp files from the repository
1. Add patterns to `.gitignore`
1. Configure your editor to not create backup files in the repo

**Prevention:**

Add to `.gitignore`:

```
*.bak
*.old
*.backup
*.tmp
*~
*.swp
*.swo
```

Configure your editor:

```bash
# Vim: put backup files elsewhere
set backupdir=~/.vim/backup//
set directory=~/.vim/swap//

# Or disable backup files in repos
autocmd BufNewFile,BufRead /path/to/repos/* set nobackup nowritebackup
```

-----

#### CHECK 06: Dotenv Files

**Severity:** Medium  
**Exit Code:** 1

**What it detects:**

Finds `.env` files in any form:

- `.env`
- `.env.local`
- `.env.production`
- `.env.development`
- `*.env`

**Why it matters:**

Environment files contain secrets. They’re useful for local development but should never be committed.

Even if your current `.env` doesn’t have real secrets, committing it establishes a bad pattern. Someone will eventually put real secrets in it.

**What to do:**

1. Remove all `.env` files from git:
   
   ```bash
   git rm --cached .env .env.*
   ```
1. Add to `.gitignore`:
   
   ```
   .env
   .env.*
   *.env
   ```
1. Create `.env.example` with dummy values as documentation:
   
   ```bash
   # .env.example
   API_KEY=your_api_key_here
   DATABASE_URL=postgresql://localhost/mydb
   ```
1. Document in README that developers should copy `.env.example` to `.env`

**Prevention:**

Always gitignore `.env` files. Always. Include this in your project setup checklist.

-----

#### CHECK 08: Mixed Content (Output)

**Severity:** Medium  
**Exit Code:** 1

**What it detects:**

Scans output for HTTP resources loaded from HTTPS pages:

- `href="http://` (excluding W3C schema URLs)
- `src="http://`
- `url("http://`

**Why it matters:**

Mixed content (HTTP resources on HTTPS pages) causes:

- Browser security warnings
- Blocked resources in modern browsers
- SEO penalties
- User trust issues

Your HTTPS connection is only as secure as the insecure HTTP resources you’re loading.

**What to do:**

1. Change all `http://` references to `https://`
1. Verify those resources actually support HTTPS
1. For external resources, find HTTPS CDN alternatives if needed
1. Rebuild and verify in browser console (no mixed content warnings)

**Prevention:**

Set your base URL to HTTPS in your site config:

```toml
# Hugo
baseURL = "https://example.com"

# Jekyll
url: "https://example.com"
```

Most modern CDNs and resources support HTTPS. If something doesn’t, find an alternative or host it yourself.

-----

#### CHECK 14: npm audit (Optional)

**Severity:** Medium (varies by vulnerability count)  
**Exit Code:** 1

**What it detects:**

Runs `npm audit --audit-level=high` if `package.json` exists.

Reports vulnerabilities at high or critical severity in your dependencies.

**Why it matters:**

Known vulnerabilities in dependencies are low-hanging fruit for attackers. If npm knows about it, so do attackers.

Many vulnerabilities have public exploits available within hours of disclosure.

**What to do:**

1. Run `npm audit` to see detailed vulnerability report
1. Run `npm audit fix` to auto-update where possible
1. For breaking changes, review manually:
   
   ```bash
   npm audit fix --force  # Applies breaking updates
   ```
1. For vulnerabilities without fixes:

- Check if you actually use the vulnerable code path
- Consider alternative packages
- Monitor for patches

**Prevention:**

- Enable Dependabot or Renovate for automated updates
- Run `npm audit` regularly (weekly at minimum)
- Consider `npm audit` in your CI pipeline
- Review dependencies before adding them

-----

#### CHECK 17: Git History — Sensitive Extensions

**Severity:** Medium  
**Exit Code:** 1

**What it detects:**

Scans your git commit history for references to sensitive file types:

- `.env` files
- `.key` files
- `.pem` files
- `.p12` / `.pfx` files
- `.backup` / `.bak` files

Counts how many times these appear across all commits, all branches.

**Why it matters:**

Even deleted files remain in git history forever (until you rewrite history). If someone committed secrets then deleted them, those secrets are still accessible to anyone who clones the repo.

Attackers actively scan git history for exactly this.

**What to do:**

1. Use `git filter-repo` to purge sensitive files from history:
   
   ```bash
   # Install git-filter-repo
   pip install git-filter-repo
   
   # Remove all .env files from history
   git filter-repo --path-glob '*.env' --invert-paths
   
   # Remove specific files
   git filter-repo --path secrets.key --invert-paths
   ```
1. Or use BFG Repo Cleaner (older but works):
   
   ```bash
   bfg --delete-files '*.env'
   ```
1. After rewriting history:

- Force push to all remotes
- Coordinate with team (everyone needs to re-clone)
- Rotate any secrets that were in history
- Consider repo as compromised if it was public

**Prevention:**

- Proper `.gitignore` from day one
- Pre-commit hooks that block sensitive files
- Regular audits before repo goes public

-----

#### CHECK 18: Git Remote URL Hygiene

**Severity:** Medium  
**Exit Code:** 1

**What it detects:**

Checks if any git remotes use `http://` instead of `https://` or `ssh://`.

**Why it matters:**

HTTP git remotes are unencrypted. Anyone on the network can:

- See what you’re pushing/pulling
- Potentially inject malicious code (MITM attacks)
- Capture credentials if using HTTP auth

**What to do:**

Switch to HTTPS or SSH:

```bash
# Check current remotes
git remote -v

# Switch to HTTPS
git remote set-url origin https://github.com/user/repo.git

# Or switch to SSH (preferred)
git remote set-url origin git@github.com:user/repo.git
```

**Prevention:**

Always use HTTPS or SSH for git remotes. Never HTTP.

If you’re on a network that blocks SSH (port 22), GitHub supports SSH over HTTPS (port 443):

```bash
# ~/.ssh/config
Host github.com
  Hostname ssh.github.com
  Port 443
```

-----

#### CHECK 29: Eleventy eval/Function (Hint)

**Severity:** Medium  
**Exit Code:** 1

**What it detects:**

For Eleventy projects, scans for dangerous dynamic code execution:

- `eval(` calls
- `Function(` constructor calls

**Why it matters:**

Dynamic code execution (`eval`, `Function`) is a common source of injection vulnerabilities. If untrusted input reaches these functions, attackers can execute arbitrary code.

In build tools, this is less immediately dangerous than runtime, but still represents risky patterns.

**What to do:**

1. Review each use of `eval` or `Function`:

- Can you rewrite without dynamic execution?
- Is the input fully trusted?
- Is there a safer alternative?

1. Common safer alternatives:
   
   ```javascript
   // Instead of eval
   const result = eval(userInput);
   
   // Use Function constructor with bound context
   const fn = new Function('param', 'return param * 2');
   
   // Or use JSON.parse for data
   const data = JSON.parse(jsonString);
   ```
1. If you must use dynamic execution, isolate it and validate inputs heavily

**Prevention:**

Avoid `eval` and `Function` constructor unless absolutely necessary. There’s almost always a better way.

-----

#### CHECK 34: GitHub Actions Foot-guns

**Severity:** Medium  
**Exit Code:** 1

**What it detects:**

Scans `.github/workflows/` for dangerous patterns:

- `pull_request_target` (often misunderstood, can execute attacker code)
- `curl | bash` or `wget | bash` (remote code execution)
- `set -x` (may echo secrets to logs)
- `env |` or `printenv` (dumps all env vars including secrets)
- `secrets.` references (may be echoed unsafely)

**Why it matters:**

GitHub Actions workflows run with powerful permissions. Common mistakes:

- `pull_request_target` gives untrusted PR code access to secrets
- `curl | bash` downloads and executes arbitrary code
- Echoing env vars or secrets puts them in public logs

These patterns are often copied from tutorials without understanding the security implications.

**What to do:**

1. For `pull_request_target`:

- Understand the trust boundary (PR code vs. base branch code)
- Use `pull_request` instead unless you absolutely need secrets
- If you need `pull_request_target`, carefully isolate untrusted code

1. For `curl | bash` patterns:

- Download scripts first, verify integrity, then execute
- Use official GitHub Actions from marketplace instead
- Pin to specific versions/commits

1. For secret leakage:

- Remove `set -x` from scripts that handle secrets
- Don’t echo env vars or secrets
- Use GitHub’s secret masking (happens automatically, but can be bypassed)

**Prevention:**

Use GitHub’s official actions where possible:

```yaml
# Don't do this
- run: curl https://install.sh | bash

# Do this
- uses: official/action@v1.2.3
```

Be very careful with `pull_request_target`:

```yaml
# Dangerous: runs untrusted PR code with secrets
on:
  pull_request_target:
    
# Safe for most cases: runs without secrets
on:
  pull_request:
```

-----

#### CHECK 35: Actions Pinning & Permissions

**Severity:** Medium  
**Exit Code:** 1

**What it detects:**

Three GitHub Actions security issues:

1. **Unpinned actions**: Using tag names instead of commit SHAs
   
   ```yaml
   # Detects this (unpinned)
   uses: actions/checkout@v3
   
   # Not this (pinned)
   uses: actions/checkout@f43a0e5ff2bd294095638e18286ca9a3d1956744
   ```
1. **`permissions: write-all`**: Overly broad permissions
1. **Missing permissions block**: Workflows without explicit permissions

**Why it matters:**

- **Unpinned actions**: Tags can be moved. An attacker who compromises an action repo can update the tag to point to malicious code.
- **`write-all`**: Violates least privilege. Most workflows don’t need write access to everything.
- **No permissions block**: Defaults may be broader than intended.

**What to do:**

1. Pin actions to commit SHAs:
   
   ```yaml
   # Bad
   uses: actions/checkout@v3
   
   # Good
   uses: actions/checkout@f43a0e5ff2bd294095638e18286ca9a3d1956744  # v3
   ```
   
   Keep a comment with the tag for human readability.
1. Replace `write-all` with specific permissions:
   
   ```yaml
   # Bad
   permissions: write-all
   
   # Good
   permissions:
     contents: read
     pull-requests: write
   ```
1. Add explicit permissions to every workflow:
   
   ```yaml
   name: CI
   
   on: [push, pull_request]
   
   permissions:
     contents: read
   
   jobs:
     test:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@f43a0e5...
   ```

**Prevention:**

- Use Dependabot to keep actions updated (it can pin to SHAs)
- Start every workflow with a permissions block
- Use least privilege (grant only what’s needed)

-----

#### CHECK 36: Lockfile Hygiene

**Severity:** Medium  
**Exit Code:** 1

**What it detects:**

Checks if `package.json` exists but no lockfile is present:

- `package-lock.json` (npm)
- `pnpm-lock.yaml` (pnpm)
- `yarn.lock` (Yarn)

**Why it matters:**

Without a lockfile:

- Builds are not reproducible (different installs get different versions)
- Supply chain attacks are easier (attacker publishes malicious version, you install it)
- Debugging is harder (“works on my machine” problems)
- CI/CD may install different versions than you tested locally

**What to do:**

1. Generate and commit the appropriate lockfile:
   
   ```bash
   # npm
   npm install
   git add package-lock.json
   
   # pnpm
   pnpm install
   git add pnpm-lock.yaml
   
   # Yarn
   yarn install
   git add yarn.lock
   ```
1. Never add lockfiles to `.gitignore`
1. Configure CI to use lockfile:
   
   ```yaml
   # Use npm ci instead of npm install
   - run: npm ci
   ```

**Prevention:**

Always commit lockfiles. They’re part of your source code.

-----

#### CHECK 40: robots.txt & sitemap.xml Sanity (Output)

**Severity:** Medium (for sensitive paths in sitemap)  
**Exit Code:** 1

**What it detects:**

Two checks in your build output:

1. Missing `robots.txt`
1. Sensitive paths in `sitemap.xml`:

- `/draft`
- `/internal`
- `/admin`
- `/.env`
- `/.git`

**Why it matters:**

**robots.txt**: Controls what search engines index. Without it, you have no say in what gets indexed (especially important for staging sites).

**Sensitive paths in sitemap**: You’re actively telling search engines to index your admin panels, drafts, or internal tools.

**What to do:**

1. Add `robots.txt` to your static directory:
   
   ```
   # Disallow nothing (allow everything)
   User-agent: *
   Allow: /
   
   # Or for staging/dev sites
   User-agent: *
   Disallow: /
   ```
1. Fix sitemap generation to exclude sensitive paths:
   
   ```toml
   # Hugo example
   [sitemap]
     changefreq = "monthly"
     filename = "sitemap.xml"
     priority = 0.5
   
   # In front matter, exclude pages:
   ---
   sitemap_exclude: true
   ---
   ```
1. Review your sitemap and remove any paths that shouldn’t be public

**Prevention:**

- Always include `robots.txt` (even if it’s permissive)
- Review generated sitemap before first deploy
- Use `draft: true` in front matter to exclude from builds

-----

#### CHECK 43: Exfiltration Indicators

**Severity:** Medium  
**Exit Code:** 1

**What it detects:**

Searches entire repository for references to services commonly used for data exfiltration or testing:

- `webhook.site`
- `requestbin`
- `ngrok.io`
- `hookdeck.com`
- `pipedream.net`
- `pastebin.com`
- `discord.com/api/webhooks` or `discordapp.com/api/webhooks`

**Why it matters:**

These services are legitimate tools for testing webhooks and debugging. They’re also commonly used by attackers to exfiltrate data.

Finding them in your codebase could mean:

- Leftover test code that sends data to public endpoints
- Actual compromise (attacker added data exfiltration)
- Developer debugging that was never cleaned up

**What to do:**

1. Investigate each reference:

- Is this test code that should be removed?
- Is it in documentation/comments as an example?
- Is it in dependencies (probably fine)?
- Is it in active code with real data (problem!)?

1. For legitimate test webhooks:

- Use local alternatives (webhook.localhost or self-hosted tools)
- Ensure test code is clearly marked and excluded from production
- Use feature flags to disable in production

1. If you don’t recognize the reference:

- Treat as potential compromise
- Check git history to see who added it
- Review what data is being sent

**Prevention:**

Use environment variables for webhook URLs and fail safely:

```javascript
const webhookUrl = process.env.WEBHOOK_URL;

if (!webhookUrl || webhookUrl.includes('webhook.site')) {
  throw new Error('Production webhook not configured');
}
```

-----

#### CHECK 44: Git Hook Permissions

**Severity:** Medium (for world-writable hooks)  
**Exit Code:** 1

**What it detects:**

If `.git/hooks/pre-commit` exists, checks:

1. Whether it’s executable (should be)
1. Whether it’s world-writable or group-writable (shouldn’t be)

**Why it matters:**

Git hooks run code on your machine. If a hook is writable by others:

- Other users on the system can modify it
- Malware can inject code into your hooks
- Attackers with limited access can escalate privileges

Even on single-user systems, proper permissions are defense-in-depth.

**What to do:**

1. Make hooks executable:
   
   ```bash
   chmod +x .git/hooks/pre-commit
   ```
1. Remove world/group write permissions:
   
   ```bash
   chmod 700 .git/hooks/pre-commit
   ```
1. Check all hooks:
   
   ```bash
   chmod 700 .git/hooks/*
   ```

**Prevention:**

When creating hooks, set permissions explicitly:

```bash
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
./zimara.sh
EOF

chmod 700 .git/hooks/pre-commit
```

-----

### Low Severity

Nice to fix. More hygiene than emergency. Exit code 1.

-----

#### CHECK 01: Repo Structure

**Severity:** Low  
**Exit Code:** 1

**What it detects:**

Checks if `.git/` directory exists.

**Why it matters:**

Zimara is designed for git repositories. Without `.git/`, some checks (git history, git remotes) won’t work.

This isn’t a security issue, just a heads-up that you’re running Zimara on a non-git directory.

**What to do:**

Nothing if intentional. If you meant to scan a git repo, you’re in the wrong directory.

-----

#### CHECK 02: .gitignore Hygiene

**Severity:** Low  
**Exit Code:** 1

**What it detects:**

Checks if `.gitignore` file exists.

**Why it matters:**

Without `.gitignore`, it’s very easy to accidentally commit secrets, build artifacts, or temporary files.

While not an immediate security issue, it’s like driving without a seatbelt—fine until it isn’t.

**What to do:**

Create `.gitignore`:

```bash
# Common patterns for all projects
.env
.env.*
*.log
*.bak
*.tmp
node_modules/
.DS_Store

# Add generator-specific patterns
# Hugo
/public/
/resources/

# Jekyll
/_site/
/.jekyll-cache/

# Next.js
/.next/
/out/

# General
/dist/
/build/
```

**Prevention:**

Include `.gitignore` in your project templates and checklists.

-----

#### CHECK 10: Security Headers (Netlify) — Basic

**Severity:** Low  
**Exit Code:** 1

**What it detects:**

If `netlify.toml` exists, checks for basic security headers:

- `Strict-Transport-Security` (HSTS)
- `X-Content-Type-Options`

**Why it matters:**

These headers provide defense-in-depth:

- HSTS forces HTTPS connections (prevents SSL stripping)
- X-Content-Type-Options prevents MIME sniffing attacks

Modern browsers benefit from these, though they’re not critical for static sites.

**What to do:**

Add security headers to `netlify.toml`:

```toml
[[headers]]
  for = "/*"
  [headers.values]
    Strict-Transport-Security = "max-age=63072000; includeSubDomains; preload"
    X-Content-Type-Options = "nosniff"
    X-Frame-Options = "DENY"
    X-XSS-Protection = "1; mode=block"
    Referrer-Policy = "strict-origin-when-cross-origin"
```

**Prevention:**

Include security headers in your deployment template.

-----

#### CHECK 23: Server Config Artifacts (.htaccess)

**Severity:** Low  
**Exit Code:** 1

**What it detects:**

Searches for `.htaccess` files in the repository.

**Why it matters:**

`.htaccess` files are Apache-specific. If you’re deploying to Netlify, Vercel, or other modern platforms, they’re ignored (but their presence suggests confusion).

More importantly, `.htaccess` files can contain sensitive directives (auth rules, redirects) that shouldn’t be public.

**What to do:**

1. If deploying to Apache, verify `.htaccess` rules are safe
1. If not using Apache, delete `.htaccess` and use platform-specific config
1. Check if `.htaccess` contains any sensitive information

**Prevention:**

Use platform-native configuration:

- Netlify: `netlify.toml`
- Vercel: `vercel.json`
- Nginx: separate config file outside repo

-----

#### CHECK 27: Jekyll Plugins (Hint)

**Severity:** Low  
**Exit Code:** 1

**What it detects:**

For Jekyll projects, checks if `_config.yml` contains a `plugins:` section.

**Why it matters:**

Third-party Jekyll plugins can:

- Introduce vulnerabilities
- Execute arbitrary code during build
- Have supply chain risks

This is informational—just making sure you’re aware of what’s in your plugin chain.

**What to do:**

1. Review the plugins list in `_config.yml`
1. Verify each plugin is from a trusted source
1. Check for known vulnerabilities in plugins
1. Consider whether you need each plugin

**Prevention:**

- Minimize plugin usage
- Prefer built-in Jekyll features when possible
- Keep plugins updated
- Use well-maintained, popular plugins

-----

#### CHECK 28: Astro Integrations (Hint)

**Severity:** Low  
**Exit Code:** 1

**What it detects:**

For Astro projects, scans `astro.config.*` for `integrations:` array.

**Why it matters:**

Same as Jekyll plugins—third-party integrations are supply chain risk.

**What to do:**

1. Review integrations list
1. Verify trusted sources (official Astro integrations are safer)
1. Check for vulnerabilities
1. Minimize integration count

**Prevention:**

Prefer official Astro integrations. Review integration code before adding.

-----

#### CHECK 31: Large Files

**Severity:** Low  
**Exit Code:** 1

**What it detects:**

Finds files larger than 20MB anywhere in the repository.

**Why it matters:**

Large files in git are usually mistakes:

- Database dumps
- Media files that should be in CDN
- Accidentally committed binaries
- Build artifacts

They bloat your repository and slow down clones.

**What to do:**

1. Identify what the large files are
1. If accidental, remove and clean from history:
   
   ```bash
   git filter-repo --path-glob 'large-file.zip' --invert-paths
   ```
1. If intentional, consider Git LFS or external storage:
   
   ```bash
   git lfs track "*.zip"
   ```

**Prevention:**

- Use `.gitignore` to prevent large files
- Store media in CDN or object storage
- Use Git LFS for necessary large files

-----

#### CHECK 37: security.txt Presence

**Severity:** Low  
**Exit Code:** 1

**What it detects:**

Checks for `security.txt` file in:

- `/.well-known/security.txt`
- `/security.txt`
- Output directory versions of above

**Why it matters:**

`security.txt` tells security researchers how to contact you about vulnerabilities. It’s industry best practice but not critical for small sites.

**What to do:**

Create `.well-known/security.txt` in your static directory:

```
Contact: security@example.com
Expires: 2026-12-31T23:59:59Z
Preferred-Languages: en
```

Or use a generator: <https://securitytxt.org/>

**Prevention:**

Include `security.txt` in your deployment checklist.

-----

#### CHECK 38: CSP Quality (Netlify)

**Severity:** Low  
**Exit Code:** 1

**What it detects:**

If `netlify.toml` exists, checks for:

1. Presence of `Content-Security-Policy` header
1. Whether CSP includes `unsafe-inline` or `unsafe-eval`

**Why it matters:**

Content Security Policy is defense-in-depth against XSS attacks. For static sites, it’s less critical than for dynamic apps, but still good practice.

`unsafe-inline` and `unsafe-eval` in CSP defeat much of its purpose.

**What to do:**

Add a CSP header:

```toml
[[headers]]
  for = "/*"
  [headers.values]
    Content-Security-Policy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
```

If you have `unsafe-inline` or `unsafe-eval`:

1. Try to remove by refactoring inline scripts/styles
1. If unavoidable, use nonces or hashes instead

**Prevention:**

Start with a strict CSP and relax only as needed. Test in browser console for violations.

-----

#### CHECK 39: Browser Hardening Headers (Netlify)

**Severity:** Low  
**Exit Code:** 1

**What it detects:**

For `netlify.toml`, checks for additional security headers:

- `Referrer-Policy`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy`
- `Cross-Origin-Embedder-Policy`

**Why it matters:**

These headers provide additional browser-level security:

- **Referrer-Policy**: Controls what referrer info is sent
- **Permissions-Policy**: Disables unnecessary browser features
- **COOP/COEP**: Enables cross-origin isolation (needed for some APIs)

For static sites, these are nice-to-have rather than critical.

**What to do:**

Add recommended headers:

```toml
[[headers]]
  for = "/*"
  [headers.values]
    Referrer-Policy = "strict-origin-when-cross-origin"
    Permissions-Policy = "geolocation=(), microphone=(), camera=()"
    Cross-Origin-Opener-Policy = "same-origin"
    Cross-Origin-Embedder-Policy = "require-corp"
```

**Prevention:**

Include in deployment template. Adjust based on your site’s needs.

-----

#### CHECK 40: robots.txt & sitemap.xml Sanity (Output)

**Severity:** Low (for missing robots.txt)  
**Exit Code:** 1

**What it detects:**

Checks if `robots.txt` exists in build output.

**Why it matters:**

See CHECK 40 in Medium section for full details. Missing robots.txt is low severity (you just have no control over indexing). Sensitive paths in sitemap is medium severity.

-----

#### CHECK 41: Public Storage Endpoints (Output)

**Severity:** Low  
**Exit Code:** 1

**What it detects:**

Scans output for references to cloud storage endpoints:

- `s3.amazonaws.com` or `.s3.amazonaws.com`
- `storage.googleapis.com`
- `.blob.core.windows.net`

**Why it matters:**

References to cloud storage buckets could indicate:

- Properly configured CDN (fine)
- Accidentally exposed internal storage (problem)
- Leaking infrastructure topology

This is informational—just verify the buckets are intended to be public.

**What to do:**

1. Review each storage endpoint reference
1. Verify the bucket/container is meant to be public
1. Check bucket permissions (should be minimal)
1. Consider using a CDN in front of storage

**Prevention:**

Use CDN URLs instead of direct storage URLs when possible. This also makes migration easier.

-----

#### CHECK 42: Recon Breadcrumbs (Output)

**Severity:** Low  
**Exit Code:** 1

**What it detects:**

Scans output for references to common admin/internal paths:

- `/wp-admin`
- `/phpmyadmin`
- `/admin`
- `/graphql`
- `/.env`
- `/.git`

**Why it matters:**

These references help attackers map your infrastructure. Even if the paths don’t exist, mentioning them indicates:

- Old CMS migration (leftover links)
- Development environment references
- Internal tooling exposed

**What to do:**

1. Remove references to admin paths that don’t exist
1. For paths that do exist, verify they’re properly secured
1. Check if these are in documentation (okay) vs. live pages (not great)

**Prevention:**

Clean up after CMS migrations. Don’t hardcode admin paths in templates.

-----

#### CHECK 45: Dependabot Config

**Severity:** Low  
**Exit Code:** 1

**What it detects:**

If dependency manifests exist (`package.json`, `go.mod`, `requirements.txt`, `Gemfile`), checks for:

- `.github/dependabot.yml`
- `.github/dependabot.yaml`

**Why it matters:**

Dependabot provides automated dependency updates, which help keep your dependencies secure without manual work.

This is convenience automation rather than a security requirement, but it makes security easier.

**What to do:**

Create `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

Adjust `package-ecosystem` based on your stack:

- `npm` for Node.js
- `gomod` for Go
- `pip` for Python
- `bundler` for Ruby

**Prevention:**

Include Dependabot config in project templates.

-----

### Informational

Just letting you know. No action required. Exit code 0.

-----

#### CHECK 09: Netlify Config Presence

**Exit Code:** 0

**What it detects:**

Checks if `netlify.toml` exists.

**Why it matters:**

This is purely informational. If you’re deploying to Netlify and don’t have `netlify.toml`, configuration comes from the Netlify dashboard. That’s fine, but explicit config in the repo is often better for reproducibility.

**What to do:**

Nothing required. If you want explicit config, create `netlify.toml`:

```toml
[build]
  command = "npm run build"
  publish = "public"

[[headers]]
  for = "/*"
  [headers.values]
    X-Frame-Options = "DENY"
    X-Content-Type-Options = "nosniff"
```

-----

#### CHECK 11: GitHub Directory

**Exit Code:** 0

**What it detects:**

Checks if `.github/` directory exists.

**Why it matters:**

Informational. The `.github/` directory holds GitHub-specific config (Actions, issue templates, etc.). Its presence indicates the project uses GitHub features.

**What to do:**

Nothing. This is just confirming the directory exists.

-----

#### CHECK 12: Gitleaks Scan (Optional)

**Exit Code:** 0 (if clean) / varies (if findings)

**What it detects:**

If `gitleaks` is installed, runs it to scan for secrets.

**Why it matters:**

Gitleaks is one of the best secret scanners available. This check only runs if you have it installed—it’s optional but recommended.

**What to do:**

Install gitleaks for more thorough secret scanning:

```bash
# macOS
brew install gitleaks

# Linux
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
```

-----

#### CHECK 13: detect-secrets (Optional)

**Exit Code:** 0 (if clean) / varies (if findings)

**What it detects:**

If `detect-secrets` is installed, runs it to create a baseline of potential secrets.

**Why it matters:**

Another good secret scanner, uses a different approach than gitleaks. Optional but recommended.

**What to do:**

Install detect-secrets:

```bash
pip install detect-secrets
```

-----

#### CHECK 15: Working Tree Cleanliness

**Exit Code:** 0

**What it detects:**

Runs `git status --porcelain` to check for uncommitted changes.

**Why it matters:**

Purely informational. Uncommitted changes are fine; this just lets you know they exist.

**What to do:**

Nothing. This is just status info.

-----

#### CHECK 21: Netlify Redirects (Hint)

**Exit Code:** 0

**What it detects:**

If `netlify.toml` exists, checks for redirect rules (status 301 or 302).

**Why it matters:**

Informational. Just confirming whether redirects are configured.

**What to do:**

Nothing required. If you need redirects:

```toml
[[redirects]]
  from = "/old-path"
  to = "/new-path"
  status = 301

[[redirects]]
  from = "/old-path/*"
  to = "/new-path/:splat"
  status = 301
```

-----

#### CHECK 22: CNAME / GitHub Pages File

**Exit Code:** 0

**What it detects:**

Checks if `CNAME` file exists (used by GitHub Pages for custom domains).

**Why it matters:**

Informational. If you’re using GitHub Pages with a custom domain, you need this file. Otherwise, you don’t.

**What to do:**

Nothing unless you need it. For GitHub Pages custom domains:

```bash
echo "example.com" > CNAME
```

-----

#### CHECK 26: Hugo Modules / Themes

**Exit Code:** 0

**What it detects:**

For Hugo projects, checks if `go.mod` exists (Hugo Modules).

**Why it matters:**

Informational. Hugo Modules are the modern way to manage themes and dependencies. Their presence indicates a well-configured Hugo project.

**What to do:**

Nothing required. If you want to use Hugo Modules:

```bash
hugo mod init github.com/user/repo
```

-----

#### CHECK 30: Next.js Export Output

**Exit Code:** 0

**What it detects:**

For Next.js projects, checks if `out/` directory exists.

**Why it matters:**

Informational. The `out/` directory indicates Next.js static export has been run. Just confirming the output exists.

**What to do:**

Nothing. This confirms your build output is present.

-----

#### CHECK 32: Git Hooks (pre-commit)

**Exit Code:** 0

**What it detects:**

Checks if `.git/hooks/pre-commit` file exists.

**Why it matters:**

Informational. Pre-commit hooks are great for automation, but their absence isn’t a security issue.

**What to do:**

Consider adding a pre-commit hook to run Zimara automatically:

```bash
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
./zimara.sh
exit $?
EOF

chmod +x .git/hooks/pre-commit
```

-----

#### CHECK 33: README Presence

**Exit Code:** 0

**What it detects:**

Checks if `README.md` or `readme.md` exists.

**Why it matters:**

Informational. READMEs are good practice but not a security concern.

**What to do:**

---

## Summary

That's all 45 checks. Remember:
- **Critical**: Fix immediately, do not push
- **High**: Fix before pushing
- **Medium**: Should fix soon
- **Low**: Nice to clean up
- **Info**: Just FYI

Zimara exits with the highest severity found, so even one Critical finding will exit with code 3.

---

**Need setup help?**  
See [INTEGRATION.md](INTEGRATION.md) for Git hooks, CI/CD configuration, and team adoption strategies.

**Want the big picture?**  
Head back to [README.md](README.md) for overview and philosophy.

**Questions? Issues?**  
Open an issue on your project tracker or review the main README.

**Published by Oob Skulden™**  
The threats you don't see coming.
