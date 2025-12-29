**Zimara Integration Guide**  
**Version 0.47.1**  
**Published by Oob Skulden™**

This guide covers running Zimara as a Git hook, in CI/CD pipelines, and integrating it into your development workflow without making everyone on your team hate you.

**Related Documentation:**
- [README.md](README.md) - Overview and quick start
- [CHECKS.md](CHECKS.md) - Complete check reference with remediation steps


-----

## Table of Contents

- [Git Hooks Integration](#git-hooks-integration)
- [CI/CD Integration](#cicd-integration)
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

-----

## Team Adoption Strategies

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

Show them the finding. Explain why it’s flagged. Most “false positives” are real issues that don’t feel important until they become important very suddenly.

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

- Zimara (quick hygiene checks)
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

---

## Final Thoughts on Integration

The best security tool is the one that actually runs.

Zimara is simple on purpose. It doesn't require accounts, APIs, or approval from procurement. You can add it to a project in under a minute and it starts providing value immediately.

For many projects, that's enough. For larger projects, it's a foundation.

Either way, run it early and run it often. Most security problems are boring mistakes that could have been caught with grep and a little paranoia.

Zimara is grep with paranoia built in.

Use it.

---

**Need check details?**  
See [CHECKS.md](CHECKS.md) for what each finding means and how to fix it.

**Want the big picture?**  
Head back to [README.md](README.md) for overview and philosophy.

**Published by Oob Skulden™**  
The threats you don't see coming.
