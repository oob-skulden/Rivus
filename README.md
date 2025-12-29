# Zimara

**Version:** 0.47.1  
**Status:** Active development — stable for production use  
**Published by:** Oob Skulden™

Zimara is a local security audit script you run before your code leaves your laptop.

It exists to catch the stuff that always bites later: secrets that were “temporary,” files that “weren’t supposed to be committed,” and configs that quietly expose more than you think.

It runs fast, stays local, and doesn’t try to be cleverer than it needs to be.

-----

## Why This Exists

Most security problems don’t start in CI. They start locally, right before a commit or push, in that moment where everything looks fine but absolutely isn’t.

Zimara sits in that gap.

It’s the friend who asks “hey, are you sure you want to commit that?” before GitHub Actions has a chance to judge you.

-----

## What Zimara Does

Zimara performs a read-only security sweep of your repository and flags the common, real-world mistakes that routinely turn into incidents nobody wants to explain.

It focuses on:

- Things developers accidentally commit (we’ve all done it)
- Things static sites accidentally expose (trust me, they do)
- Things Git history never, ever forgets (yes, even after you delete the file)

It does **not** modify files, install tools, or make network calls.

### 45 security checks covering:

- **Secrets and credentials** in files and configs (API keys, tokens, passwords, AWS keys, the usual suspects)
- **Hard stop detection** of private keys and crypto material (.pem, .key, .p12, .pfx, SSH keys, certificates — the stuff that ends careers)
- **Git history inspection** for sensitive file extensions (because deleting the file later is like closing the barn door after the horses have started a podcast)
- **Backup, temp, and debug artifacts** accidentally tracked by Git (.bak, .old, .backup, debug.log, database dumps)
- **Risky content inside build output** (public/, dist/, build/, _site/ — wherever your generator puts the goods)
- **Internal IPs, localhost, and private hostnames** leaking into output (because <http://192.168.1.47:3000> shouldn’t be in production HTML)
- **Mixed content** (HTTP links inside HTTPS pages — browsers hate this, users don’t trust it, attackers love it)
- **Accidental .git/, config, or key exposure** in generated output (yes, people deploy their entire .git directory to production. yes, really.)
- **Generator-aware sanity checks** (Hugo, Jekyll, Astro, Eleventy, Next.js static export, generic sites)
- **Environment variable misuse patterns** (hardcoded secrets pretending to be env vars)
- **Execution-safety checks** (so the script itself doesn’t do anything dumb while checking if you’re doing anything dumb)

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

## What Zimara Catches That CI Doesn’t

**Scenario:** You’re testing a Netlify function locally. You hardcode an API key “just for five minutes” to debug something.

Then you fix the bug, feel good about yourself, and commit.

**What happens next:**

- **CI:** Passes (you haven’t configured a secrets scanner yet because “we’ll do that next sprint”)
- **Netlify:** Deploys it
- **GitHub:** Indexes it
- **Google:** Crawls it within 48 hours
- **Some bot in Estonia:** Uses your API key to rack up $4,700 in charges over the weekend

**Zimara in a pre-commit hook:** Blocks the commit. Key never leaves your laptop. You get coffee instead of a postmortem.

That’s the whole point.

-----

## Supported Projects

Zimara automatically detects what it’s looking at.

Works well with:

- Hugo
- Jekyll
- Astro
- Eleventy
- Next.js (static export)
- Mixed or generic static repos
- That weird custom build system you inherited from the last team

No flags required to tell it what framework you’re using. It just figures it out and gets to work.

-----

## Requirements

- Bash 4+
- Standard Unix tools (grep, awk, sed, find)
- Git (for history and hook usage)

**Typical runtime:** Under 5 seconds for repos under 10,000 files

No internet access required. No installs beyond the script itself. No sudo. No telemetry. No “please create an account to continue.”

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

That’s it. No config files, no setup wizard, no “getting started” documentation that’s somehow 47 pages long.

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
```

-----

## Interactive vs Non-Interactive

### Interactive (default)

- You’ll be prompted on Medium and Low findings
- High and Critical findings stop execution immediately
- Best for local development when you want a conversation, not a verdict

### Non-Interactive

```bash
zimara --non-interactive
```

- No prompts
- Deterministic exit codes
- Designed for Git hooks and CI environments where humans aren’t around to answer questions

-----

## Output-Only Mode

```bash
zimara --only-output
```

Skips source scanning and focuses exclusively on generated output directories.

Useful when you want to sanity-check what you’re about to deploy without re-scanning the entire repo for the third time today.

-----

## Exit Codes

|Code|Meaning                         |
|----|--------------------------------|
|0   |No findings, you’re clean       |
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

Now every commit gets checked before it’s created. Critical or High issues block immediately. No surprises after you push.

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

If it breaks, it fails closed and tells you why. If you find a way to make it do something dangerous, that’s a bug — please report it.

-----

## When You Should Not Use Zimara

- You want vulnerability scores and CVE feeds - use a SAST tool
- You need compliance paperwork - hire an auditor
- You expect it to fix problems for you - it won’t, by design
- You want cloud or runtime analysis - wrong layer entirely
- You think bash scripts are “unprofessional” - we can’t be friends

Zimara is a flashlight, not an autopilot.

-----

## Philosophy

Most security tools assume you already messed up.

Zimara assumes you’re trying not to.

It’s not here to shame you. It’s here to save you from yourself before the internet does.

Run it early. Run it often. Let it be annoying **now** instead of explaining it to your CISO **later**.

Or worse: explaining it to Reddit.

-----

## What’s Not Planned

Zimara will not:

- Become a SaaS
- Add ML/AI “smart” detection (it’s grep, not GPT)
- Require account creation or telemetry
- Grow beyond what fits in one bash script
- Pivot to blockchain
- Get acquired and then ruined

If you need enterprise features, fork it. If you want to contribute, keep it simple. If you want to sell it, you can’t — it’s not for sale.

-----

## Documentation

- **<CHECKS.md>** - Complete reference for all 45 security checks
- **<INTEGRATION.md>** - Git hooks, CI/CD setup, and team adoption
- **<LICENSE>** - MIT License

-----

## Contributing

PRs welcome for:

- New checks that catch real issues
- Bug fixes
- Performance improvements
- Better documentation

Not welcome:

- Scope creep
- Dependencies on tools most people don’t have
- “Wouldn’t it be cool if…” features that triple the runtime
- Anything that requires `npm install`

Keep it fast. Keep it local. Keep it honest.

-----

## License

MIT License — see LICENSE file.

TL;DR: Use it however you want. Don’t blame me if something breaks. Credit appreciated but not required.

-----

## Credits

Written by a security engineer who got fed up with fixing the same “how did this get committed?” problems, built while working on his own site, and completed over five nights of truly questionable sleep hygiene.

Published by Oob Skulden™.

If this saved you from a bad day, you can say thanks by:

- Not committing secrets
- Actually running it before you push
- Telling other developers it exists

That’s it. No donations (unless you want to cover a coffee or a five-dollar afternoon tea), no GitHub stars required (nice, but not mandatory), and no newsletter signups.

Maybe a YouTube video about it one day. Still not starting a newsletter.

Just… be careful out there. Things get spicy fast.

-----

**Questions?**  
Read the script. It’s extensively commented.  
Still confused? Open an issue.  
Need consulting? You’re on your own — this is a free tool, not a business.

**Published by Oob Skulden™**  
The threats you don’t see coming.​​​​​​​​​​​​​​​​