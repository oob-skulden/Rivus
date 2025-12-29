#!/usr/bin/env bash
# ============================================================
# Zimara Script (v0.44.0)
# Pre-push security sweep for static sites & web projects
#
# Supports: Hugo, Jekyll, Astro, Next export, Eleventy, generic
#
# Published by Oob Skulden™
# "The threats you don't see coming"
# 
# BUGFIX in v0.43.1:
# - Fixed line 950 git history syntax error
# - Improved error handling in git log parsing
# ============================================================

set -euo pipefail

# ============================================================
# CORE HELPERS (REQUIRED)
# ============================================================

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

say()  { printf '%s\n' "$*"; }
sayc() { printf '%b\n' "$*"; }

hr() { sayc "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

SHOW_MATCHES="${SHOW_MATCHES:-5}"

CRITICAL_ISSUES=0
HIGH_ISSUES=0
MEDIUM_ISSUES=0
LOW_ISSUES=0

# flags
ONLY_OUTPUT=0
SKIP_OUTPUT=0
INCLUDE_OUTPUT_IN_SOURCE=0
NON_INTERACTIVE=0

# ============================================================
# CLI / USAGE
# ============================================================

usage() {
  cat <<'EOF'
zimara.sh

Usage:
  ./zimara.sh [path] [options]

Options:
  --only-output                 Scan only the output dir (public/dist/out/_site)
  --skip-output                 Skip scanning output dir
  --include-output-in-source     Allow output dir to be git-tracked without warning
  --non-interactive              Skip prompts, fail on CRITICAL/HIGH (for CI/CD)
  --version                      Print version

Env:
  SHOW_MATCHES=5                How many matching lines to show (default 5)
  OUTPUT_DIR=public             Override detected output directory
  SECRET_TOOL=auto|gitleaks|detect-secrets|git-secrets|none

Exit Codes:
  0  - Success (no issues or user accepted risks)
  1  - MEDIUM issues found (user declined to proceed)
  2  - HIGH issues found (blocked or user declined)
  3  - CRITICAL issues found (always blocked)
  99 - Invalid usage/directory not found
EOF
}

VERSION="0.44.0"

if [[ "${1:-}" == "--version" ]]; then
  echo "$VERSION"
  exit 0
fi

SCAN_DIR="${1:-.}"
if [[ "${SCAN_DIR:-}" == "--help" || "${SCAN_DIR:-}" == "-h" ]]; then
  usage
  exit 0
fi

ARGS=("$@")
for arg in "${ARGS[@]}"; do
  case "$arg" in
    --only-output) ONLY_OUTPUT=1 ;;
    --skip-output) SKIP_OUTPUT=1 ;;
    --include-output-in-source) INCLUDE_OUTPUT_IN_SOURCE=1 ;;
    --non-interactive) NON_INTERACTIVE=1 ;;
    --help|-h) usage; exit 0 ;;
    --version) echo "$VERSION"; exit 0 ;;
  esac
done

if [[ ! -d "$SCAN_DIR" ]]; then
  sayc "${RED}✗ Directory not found: $SCAN_DIR${NC}"
  exit 99
fi

cd "$SCAN_DIR"

# ============================================================
# COMMON EXCLUSIONS
# ============================================================

GREP_EXCLUDES=(
  --exclude-dir=.git
  --exclude-dir=node_modules
  --exclude-dir=public
  --exclude-dir=dist
  --exclude-dir=build
  --exclude-dir=vendor
  --exclude-dir=.next
  --exclude-dir=.cache
)

find_prune_args() {
  printf '%s ' \
    -path "./.git" -o \
    -path "./node_modules" -o \
    -path "./public" -o \
    -path "./dist" -o \
    -path "./build" -o \
    -path "./vendor" -o \
    -path "./.next" -o \
    -path "./.cache" \
    -prune
}

_has_cmd() { command -v "$1" >/dev/null 2>&1; }

# ============================================================
# INTERACTIVE PROMPT HELPER
# ============================================================

prompt_user() {
  local severity="$1"
  local count="$2"
  
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    return 1  # Always fail in non-interactive mode
  fi
  
  say ""
  hr
  sayc "${YELLOW}⚠️  SECURITY DECISION REQUIRED ⚠️${NC}"
  hr
  say ""
  sayc "${YELLOW}Found ${count} ${severity} severity issue(s).${NC}"
  say ""
  
  case "$severity" in
    MEDIUM)
      say "These issues should be addressed but are not immediately critical."
      say "They represent potential vulnerabilities or security weaknesses."
      ;;
    LOW)
      say "These are minor security improvements or best practice recommendations."
      say "They represent good security hygiene but low immediate risk."
      ;;
  esac
  
  say ""
  sayc "${YELLOW}Do you want to proceed anyway? [y/N]${NC}"
  read -r -p "> " response
  
  case "$response" in
    [yY]|[yY][eE][sS])
      say ""
      sayc "${YELLOW}⚠️  Proceeding with ${severity} issues acknowledged${NC}"
      say ""
      return 0
      ;;
    *)
      say ""
      sayc "${RED}❌ Deployment blocked by user${NC}"
      say ""
      return 1
      ;;
  esac
}

# ============================================================
# GENERATOR + OUTPUT DETECTION
# ============================================================

GENERATOR="generic"
OUTPUT_DIR_DETECTED=""

if [[ -f "hugo.toml" || -f "hugo.yaml" || -f "hugo.yml" || -f "config.toml" || -f "config.yaml" || -f "config.yml" ]]; then
  GENERATOR="hugo"
  OUTPUT_DIR_DETECTED="public"
elif [[ -f "_config.yml" || -f "_config.yaml" ]]; then
  GENERATOR="jekyll"
  OUTPUT_DIR_DETECTED="_site"
elif [[ -f "astro.config.mjs" || -f "astro.config.js" || -f "astro.config.ts" ]]; then
  GENERATOR="astro"
  OUTPUT_DIR_DETECTED="dist"
elif [[ -f "next.config.js" || -f "next.config.mjs" || -f "next.config.ts" ]]; then
  GENERATOR="next-export"
  OUTPUT_DIR_DETECTED="out"
elif [[ -f ".eleventy.js" || -f "eleventy.config.js" || -f ".eleventy.cjs" ]]; then
  GENERATOR="eleventy"
  OUTPUT_DIR_DETECTED="_site"
fi

OUTPUT_DIR="${OUTPUT_DIR:-$OUTPUT_DIR_DETECTED}"
OUTPUT_BASENAME="$(basename "${OUTPUT_DIR:-}" 2>/dev/null || true)"

# ============================================================
# HEADER
# ============================================================

say ""
sayc "${PURPLE}==============================================${NC}"
sayc "${PURPLE}🔒 Zimara 🔒  (v${VERSION})${NC}"
sayc "${PURPLE}==============================================${NC}"
say ""
say "Directory scanned: $(pwd)"
say "Generator detected: $GENERATOR"
[[ -n "${OUTPUT_DIR:-}" ]] && say "Output dir detected: $OUTPUT_DIR"
[[ "$NON_INTERACTIVE" -eq 1 ]] && say "Mode: Non-interactive (CI/CD)"
say ""

# ============================================================
# CHECK 1: Private Keys (HARD STOP)
# ============================================================

hr
sayc "${PURPLE}CHECK 1: Private Keys (HARD STOP)${NC}"
hr

KEYS=$(find . \( $(find_prune_args) \) -type f \
  \( -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" \) \
  -print 2>/dev/null || true)

if [[ -n "$KEYS" ]]; then
  sayc "${RED}✗ CRITICAL: Private key material found${NC}"
  printf '%s\n' "$KEYS" | sed 's/^/  /'
  say "Actions:"
  say "  • REMOVE immediately"
  say "  • Rotate/revoke keys"
  say "  • Purge git history (git filter-repo/BFG)"
  CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
else
  sayc "${GREEN}✓ No private keys found${NC}"
fi
say ""

# ============================================================
# CHECK 2: Environment / Secrets Files
# ============================================================

hr
sayc "${PURPLE}CHECK 2: Environment / Secrets Files${NC}"
hr

ENV_FILES=$(find . \( $(find_prune_args) \) -type f -name ".env*" -print 2>/dev/null || true)

if [[ -n "$ENV_FILES" ]]; then
  sayc "${RED}✗ Found environment files [CRITICAL]${NC}"
  printf '%s\n' "$ENV_FILES" | sed 's/^/  /'
  say "Actions:"
  say "  • Remove from repo"
  say "  • Add to .gitignore"
  CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
else
  sayc "${GREEN}✓ No .env files found${NC}"
fi
say ""

# ============================================================
# CHECK 3: Hardcoded Credentials
# ============================================================

hr
sayc "${PURPLE}CHECK 3: Hardcoded Credentials${NC}"
hr

CREDS=$(grep -riE "(password|api[_-]?key|secret|token)[[:space:]]*[:=][[:space:]]*['\"][^'\"]{8,}" . \
  "${GREP_EXCLUDES[@]}" 2>/dev/null || true)

if [[ -n "$CREDS" ]]; then
  sayc "${YELLOW}⚠️  Possible hardcoded credentials [HIGH]${NC}"
  printf '%s\n' "$CREDS" | head -"$SHOW_MATCHES" | sed 's/^/  /'
  say "Actions:"
  say "  • Replace with env vars / secret manager references"
  say "  • Rotate exposed values"
  HIGH_ISSUES=$((HIGH_ISSUES + 1))
else
  sayc "${GREEN}✓ No obvious hardcoded credentials${NC}"
fi
say ""

# ============================================================
# DROP-IN: Optional best-in-class secret scanning
# ============================================================

SECRET_TOOL="${SECRET_TOOL:-auto}"
SECRET_BASELINE="${SECRET_BASELINE:-.secrets.baseline}"
GITLEAKS_CONFIG="${GITLEAKS_CONFIG:-.gitleaks.toml}"

run_secret_scanner() {
  local dir="${1:-.}"
  local tool="${SECRET_TOOL,,}"

  if [[ "$tool" == "auto" ]]; then
    if _has_cmd gitleaks; then tool="gitleaks"
    elif _has_cmd detect-secrets; then tool="detect-secrets"
    elif _has_cmd git-secrets; then tool="git-secrets"
    else tool="none"
    fi
  fi

  hr
  sayc "${PURPLE}CHECK X: Enhanced Secret Scanning (optional tools)${NC}"
  hr

  case "$tool" in
    none)
      sayc "${BLUE}ℹ️  No external secret scanner found (gitleaks/detect-secrets/git-secrets).${NC}"
      say "  Using built-in checks only."
      say ""
      return 0
      ;;

    gitleaks)
      sayc "${BLUE}ℹ️  Using gitleaks${NC}"
      local report
      report="$(mktemp -t gitleaks-report.XXXXXX.json 2>/dev/null || mktemp "/tmp/gitleaks-report.XXXXXX.json")"
      local -a args
      args=( detect --source "$dir" --report-format json --report-path "$report" )

      if [[ -f "$dir/$GITLEAKS_CONFIG" ]]; then
        args+=( --config "$dir/$GITLEAKS_CONFIG" )
      elif [[ -f "$GITLEAKS_CONFIG" ]]; then
        args+=( --config "$GITLEAKS_CONFIG" )
      fi

      if gitleaks "${args[@]}" >/dev/null 2>&1; then
        sayc "${GREEN}✓ gitleaks: no secrets found${NC}"
        rm -f "$report" >/dev/null 2>&1 || true
        say ""
        return 0
      else
        if [[ -s "$report" ]]; then
          local count
          count="$(grep -c '"RuleID"' "$report" 2>/dev/null || echo 0)"
          sayc "${RED}✗ gitleaks: found ${count} potential secret(s) [CRITICAL]${NC}"
          say "  Report: $report"
          say "Actions:"
          say "  • Validate findings, then rotate/revoke anything real"
          say "  • Consider adding a .gitleaks.toml to reduce false positives"
          CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
          say ""
          return 1
        else
          sayc "${YELLOW}⚠️  gitleaks: scan failed (no report generated).${NC}"
          say "  Tip: run: gitleaks detect --source \"$dir\" -v"
          rm -f "$report" >/dev/null 2>&1 || true
          say ""
          return 3
        fi
      fi
      ;;

    detect-secrets)
      sayc "${BLUE}ℹ️  Using detect-secrets${NC}"
      if [[ -f "$dir/$SECRET_BASELINE" ]]; then
        say "  Baseline: $dir/$SECRET_BASELINE"
        if detect-secrets audit --baseline "$dir/$SECRET_BASELINE" >/dev/null 2>&1; then
          sayc "${GREEN}✓ detect-secrets: baseline audit clean${NC}"
          say ""
          return 0
        else
          sayc "${RED}✗ detect-secrets: potential secrets found vs baseline [CRITICAL]${NC}"
          say "Actions:"
          say "  • Run: detect-secrets audit --baseline \"$dir/$SECRET_BASELINE\""
          CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
          say ""
          return 1
        fi
      else
        local tmp_baseline
        tmp_baseline="$(mktemp -t secrets-baseline.XXXXXX.json 2>/dev/null || mktemp "/tmp/secrets-baseline.XXXXXX.json")"
        if (cd "$dir" && detect-secrets scan) >"$tmp_baseline" 2>/dev/null; then
          local findings
          findings="$(grep -c '"type":' "$tmp_baseline" 2>/dev/null || echo 0)"
          if [[ "${findings:-0}" -gt 0 ]]; then
            sayc "${YELLOW}⚠️  detect-secrets: findings present (baseline not adopted) [HIGH]${NC}"
            say "  Temp baseline: $tmp_baseline"
            say "Actions:"
            say "  • Review + rotate/revoke if real"
            say "  • Or adopt baseline:"
            say "      mv \"$tmp_baseline\" \"$dir/$SECRET_BASELINE\""
            say "      detect-secrets audit --baseline \"$dir/$SECRET_BASELINE\""
            HIGH_ISSUES=$((HIGH_ISSUES + 1))
            say ""
            return 1
          else
            sayc "${GREEN}✓ detect-secrets: no secrets found${NC}"
            rm -f "$tmp_baseline" >/dev/null 2>&1 || true
            say ""
            return 0
          fi
        else
          sayc "${YELLOW}⚠️  detect-secrets: scan failed.${NC}"
          say "  Tip: run: (cd \"$dir\" && detect-secrets scan)"
          rm -f "$tmp_baseline" >/dev/null 2>&1 || true
          say ""
          return 3
        fi
      fi
      ;;

    git-secrets)
      sayc "${BLUE}ℹ️  Using git-secrets${NC}"
      if [[ ! -d "$dir/.git" ]]; then
        sayc "${YELLOW}⚠️  git-secrets works best in a git repo; skipping.${NC}"
        say ""
        return 2
      fi
      if (cd "$dir" && git secrets --scan) >/dev/null 2>&1; then
        sayc "${GREEN}✓ git-secrets: no matches${NC}"
        say ""
        return 0
      else
        sayc "${RED}✗ git-secrets: potential secrets found [CRITICAL]${NC}"
        say "Actions:"
        say "  • Run: (cd \"$dir\" && git secrets --scan) for details"
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        say ""
        return 1
      fi
      ;;

    *)
      sayc "${YELLOW}⚠️  Unknown SECRET_TOOL='$SECRET_TOOL' — skipping external scanner.${NC}"
      say ""
      return 2
      ;;
  esac
}

run_secret_scanner "."

# ============================================================
# CHECK 4: Sensitive Files in Output Directory
# ============================================================

hr
sayc "${PURPLE}CHECK 4: Sensitive Files in Output Directory${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Output scanning disabled (--skip-output)${NC}"
  say ""
else
  if [[ -n "${OUTPUT_DIR:-}" && -d "${OUTPUT_DIR:-}" ]]; then
    if [[ -d "$OUTPUT_DIR/.git" ]]; then
      sayc "${RED}✗ CRITICAL: .git directory found in output dir!${NC}"
      say "  This can expose your entire git history to the web."
      say "Actions:"
      say "  • Ensure publish folder never includes .git"
      say "  • Confirm host rules prevent serving hidden directories"
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    fi

    OUTPUT_CONFIGS=$(find "$OUTPUT_DIR" -type f \( \
      -name "*.toml" -o -name "*.env" -o -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" \
    \) 2>/dev/null | wc -l | tr -d ' ')

    if [[ ${OUTPUT_CONFIGS:-0} -gt 0 ]]; then
      sayc "${RED}✗ Found $OUTPUT_CONFIGS config/key file(s) in output dir [CRITICAL]${NC}"
      find "$OUTPUT_DIR" -type f \( -name "*.toml" -o -name "*.env" -o -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" \) 2>/dev/null | sed 's/^/  /'
      say "Actions:"
      say "  • Remove sensitive files from output and rebuild"
      say "  • Ensure they live outside publish dir"
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    else
      sayc "${GREEN}✓ No critical files found in output dir${NC}"
    fi

    SOURCEMAPS=$(find "$OUTPUT_DIR" -name "*.map" 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${SOURCEMAPS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $SOURCEMAPS source map file(s) in output dir [MEDIUM]${NC}"
      say "  Source maps can expose original source code and internal paths."
      say "Actions:"
      say "  • Disable sourcemaps for production or restrict access"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  else
    sayc "${YELLOW}⚠️  No output directory found - skipping${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 5: Internal URLs/IPs in Output
# ============================================================

hr
sayc "${PURPLE}CHECK 5: Internal URLs/IPs Exposed${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Output scanning disabled (--skip-output)${NC}"
  say ""
else
  if [[ -n "${OUTPUT_DIR:-}" && -d "${OUTPUT_DIR:-}" ]]; then
    INTERNAL_URLS=$(grep -riE "(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|\.local|\.internal|docker\.sock)" "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${INTERNAL_URLS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $INTERNAL_URLS internal reference(s) [MEDIUM]${NC}"
      grep -riE "(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|\.local|\.internal|docker\.sock)" "$OUTPUT_DIR" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /' || true
      say "Actions:"
      say "  • Verify baseURL / site URL settings for production"
      say "  • Rebuild with production flags"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    else
      sayc "${GREEN}✓ No internal URLs/IPs found in output${NC}"
    fi
  else
    sayc "${YELLOW}⚠️  No output directory found - skipping${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 6: Large Files (>10MB)
# ============================================================

hr
sayc "${PURPLE}CHECK 6: Large Files (>10MB)${NC}"
hr

LARGE_FILE_LIST=$(find . \( $(find_prune_args) \) -type f -size +10M -print 2>/dev/null || true)
if [[ -n "$LARGE_FILE_LIST" ]]; then
  LARGE_FILES=$(printf '%s\n' "$LARGE_FILE_LIST" | wc -l | tr -d ' ')
  sayc "${YELLOW}⚠️  Found $LARGE_FILES file(s) larger than 10MB [MEDIUM]${NC}"
  printf '%s\n' "$LARGE_FILE_LIST" | while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    size=$(du -h "$file" 2>/dev/null | cut -f1 || echo "?")
    say "  $file ($size)"
  done
  say "Actions:"
  say "  • If accidental: remove + clean history if needed"
  say "  • If intentional: Git LFS or CDN/object storage"
  MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
else
  sayc "${GREEN}✓ No files larger than 10MB${NC}"
fi
say ""

# ============================================================
# CHECK 7: Debug/Test Files
# ============================================================

hr
sayc "${PURPLE}CHECK 7: Debug/Test Files${NC}"
hr

DEBUG_FILES=$(find . \( $(find_prune_args) \) -type f \( \
  -name "test.html" -o -name "debug.log" -o -name "*.swp" -o -name "*.swo" -o \
  -name ".DS_Store" -o -name "Thumbs.db" -o -name "phpinfo.php" -o -name "*.sql" \
\) -print 2>/dev/null || true)

if [[ -n "$DEBUG_FILES" ]]; then
  COUNT=$(printf '%s\n' "$DEBUG_FILES" | wc -l | tr -d ' ')
  sayc "${YELLOW}⚠️  Found $COUNT debug/test file(s) [HIGH]${NC}"
  printf '%s\n' "$DEBUG_FILES" | sed 's/^/  /'
  say "Actions:"
  say "  • Remove debug artifacts from repo"
  say "  • Add patterns to .gitignore"
  HIGH_ISSUES=$((HIGH_ISSUES + 1))
else
  sayc "${GREEN}✓ No debug/test files found${NC}"
fi
say ""

# ============================================================
# CHECK 8: Email/Phone in Output
# ============================================================

hr
sayc "${PURPLE}CHECK 8: Email/Phone Scraping Risk${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  EMAIL_COUNT=$(grep -roE "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}" "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)
  PHONE_COUNT=$(grep -roE "\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}" "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)

  if [[ ${EMAIL_COUNT:-0} -gt 0 || ${PHONE_COUNT:-0} -gt 0 ]]; then
    sayc "${BLUE}ℹ️  Contact info present in output:${NC}"
    [[ ${EMAIL_COUNT:-0} -gt 0 ]] && say "  • $EMAIL_COUNT email address(es)"
    [[ ${PHONE_COUNT:-0} -gt 0 ]] && say "  • $PHONE_COUNT phone number(s)"
    say "Actions:"
    say "  • If intentional: consider obfuscation or a contact form"
    say "  • If unintentional: remove and rebuild"
    LOW_ISSUES=$((LOW_ISSUES + 1))
  else
    sayc "${GREEN}✓ No email/phone numbers in output${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 9: Mixed Content
# ============================================================

hr
sayc "${PURPLE}CHECK 9: Mixed Content (HTTP/HTTPS)${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  HTTP_REFS=$(grep -roE "http://[^\"' ]+" "$OUTPUT_DIR" 2>/dev/null | grep -v "http://www.w3.org" | wc -l | tr -d ' ' || true)
  PROTO_RELATIVE=$(grep -roE "//[^\"' ]+\.(js|css|png|jpg|gif|svg|webp|woff|woff2)" "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)

  if [[ ${HTTP_REFS:-0} -gt 0 ]]; then
    sayc "${YELLOW}⚠️  Found $HTTP_REFS http:// references [MEDIUM]${NC}"
    grep -roE "http://[^\"' ]+" "$OUTPUT_DIR" 2>/dev/null | grep -v "http://www.w3.org" | head -"$SHOW_MATCHES" | sed 's/^/  /' || true
    say "Actions:"
    say "  • Switch assets to https:// URLs"
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
  fi

  if [[ ${PROTO_RELATIVE:-0} -gt 0 ]]; then
    sayc "${BLUE}ℹ️  Found $PROTO_RELATIVE protocol-relative URLs (//...) [LOW]${NC}"
    say "Actions:"
    say "  • Prefer explicit https://"
    LOW_ISSUES=$((LOW_ISSUES + 1))
  fi

  if [[ ${HTTP_REFS:-0} -eq 0 && ${PROTO_RELATIVE:-0} -eq 0 ]]; then
    sayc "${GREEN}✓ No mixed content indicators found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 10: Default/Demo Content
# ============================================================

hr
sayc "${PURPLE}CHECK 10: Default/Demo Content${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  DEMO_REFS=$(grep -rIEn \
    --include="*.html" --include="*.htm" --include="*.xml" --include="*.json" --include="*.txt" \
    "(example\.com|Your Name Here|Lorem ipsum|Demo Site|Test Site)" \
    "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)

  if [[ ${DEMO_REFS:-0} -gt 0 ]]; then
    sayc "${YELLOW}⚠️  Found $DEMO_REFS placeholder reference(s) [LOW]${NC}"
    grep -rIEn \
      --include="*.html" --include="*.htm" --include="*.xml" --include="*.json" --include="*.txt" \
      "(example\.com|Your Name Here|Lorem ipsum|Demo Site|Test Site)" \
      "$OUTPUT_DIR" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /' || true
    say "Actions:"
    say "  • Replace placeholder content"
    LOW_ISSUES=$((LOW_ISSUES + 1))
  else
    sayc "${GREEN}✓ No obvious demo content found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 11: .gitignore Coverage
# ============================================================

hr
sayc "${PURPLE}CHECK 11: .gitignore Configuration${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -f ".gitignore" ]]; then
    REQUIRED_PATTERNS=(
      "*.bak"
      "*.backup*"
      ".env"
      "*.key"
      "*.pem"
      "*.log"
      ".DS_Store"
    )

    MISSING_PATTERNS=()
    for pattern in "${REQUIRED_PATTERNS[@]}"; do
      if ! grep -qF "$pattern" ".gitignore" 2>/dev/null; then
        MISSING_PATTERNS+=("$pattern")
      fi
    done

    if [[ ${#MISSING_PATTERNS[@]} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Missing recommended .gitignore patterns [LOW]${NC}"
      printf '  %s\n' "${MISSING_PATTERNS[@]}"
      say "Actions:"
      say "  • Add missing patterns"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    else
      sayc "${GREEN}✓ .gitignore has good coverage${NC}"
    fi
  else
    sayc "${RED}✗ No .gitignore file found [MEDIUM]${NC}"
    say "Actions:"
    say "  • Create a .gitignore for secrets, build output, caches, OS files"
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
  fi
  say ""
fi

# ============================================================
# CHECK 12: Hardcoded Credentials in Common Code Dirs
# ============================================================

hr
sayc "${PURPLE}CHECK 12: Hardcoded Credentials in Code Dirs${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  HARDCODED_FOUND=0
  CODE_DIRS=("content" "layouts" "themes" "static" "src" "app" "lib" "pages")

  for d in "${CODE_DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    MATCHES=$(grep -riE "(password|api[_-]?key|secret|token)[[:space:]]*[:=][[:space:]]*['\"][^'\"]{8,}" "$d" \
      "${GREP_EXCLUDES[@]}" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${MATCHES:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $MATCHES potential credential(s) in $d/ [HIGH]${NC}"
      grep -riE "(password|api[_-]?key|secret|token)[[:space:]]*[:=][[:space:]]*['\"][^'\"]{8,}" "$d" \
        "${GREP_EXCLUDES[@]}" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /' || true
      HARDCODED_FOUND=$((HARDCODED_FOUND + MATCHES))
    fi
  done

  if [[ $HARDCODED_FOUND -gt 0 ]]; then
    say "Actions:"
    say "  • Replace hardcoded secrets with env vars"
    say "  • Rotate exposed values"
    HIGH_ISSUES=$((HIGH_ISSUES + 1))
  else
    sayc "${GREEN}✓ No obvious hardcoded secrets in common code dirs${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 13: Sensitive HTML Comments
# ============================================================

hr
sayc "${PURPLE}CHECK 13: Sensitive HTML Comments${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  DEV_COMMENTS=$(grep -rIEn --include="*.html" --include="*.htm" \
    "<!--.*\b(TODO|DEBUG|FIXME|XXX|HACK|password|token|key)\b" \
    "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)

  if [[ ${DEV_COMMENTS:-0} -gt 0 ]]; then
    sayc "${YELLOW}⚠️  Found $DEV_COMMENTS development comment(s) in output HTML [LOW]${NC}"
    grep -rIEn --include="*.html" --include="*.htm" \
      "<!--.*\b(TODO|DEBUG|FIXME|XXX|HACK|password|token|key)\b" \
      "$OUTPUT_DIR" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /' || true
    say "Actions:"
    say "  • Remove sensitive comments before publishing"
    LOW_ISSUES=$((LOW_ISSUES + 1))
  else
    sayc "${GREEN}✓ No sensitive comments in output HTML${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 14: Security Headers in netlify.toml
# ============================================================

hr
sayc "${PURPLE}CHECK 14: Security Headers in netlify.toml${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -f "netlify.toml" ]]; then
    SECURITY_HEADERS=("X-Frame-Options" "X-Content-Type-Options" "Content-Security-Policy" "Strict-Transport-Security" "Permissions-Policy" "Referrer-Policy")
    MISSING_HEADERS=()
    for header in "${SECURITY_HEADERS[@]}"; do
      if ! grep -qi "$header" "netlify.toml"; then
        MISSING_HEADERS+=("$header")
      fi
    done

    if [[ ${#MISSING_HEADERS[@]} -gt 0 ]]; then
      sayc "${BLUE}ℹ️  Missing recommended headers in netlify.toml [LOW]${NC}"
      printf '  %s\n' "${MISSING_HEADERS[@]}"
      say "Actions:"
      say "  • Add common security headers"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    else
      sayc "${GREEN}✓ netlify.toml appears to include common security headers${NC}"
    fi
  else
    sayc "${BLUE}ℹ️  No netlify.toml found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 15: Metadata/Identity Leaks
# ============================================================

hr
sayc "${PURPLE}CHECK 15: Metadata/Identity Leaks${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  IDENTITY_REFS=0

  if [[ -d ".git" ]]; then
    GIT_USER=$(git config user.name 2>/dev/null || echo "")
    GIT_EMAIL=$(git config user.email 2>/dev/null || echo "")

    if [[ -n "$GIT_USER" && "${GIT_USER,,}" != "oob" && "${GIT_USER,,}" != "oob skulden" ]]; then
      sayc "${BLUE}ℹ️  Git config name: $GIT_USER${NC}"
      say "Actions:"
      say "  • Consider per-repo identity:"
      say "      git config user.name \"Oob Skulden\""
      IDENTITY_REFS=$((IDENTITY_REFS + 1))
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi

    if [[ -n "$GIT_EMAIL" && "$GIT_EMAIL" != *"noreply"* ]]; then
      sayc "${BLUE}ℹ️  Git config email: $GIT_EMAIL${NC}"
      say "Actions:"
      say "  • Use GitHub noreply email for public repos"
      IDENTITY_REFS=$((IDENTITY_REFS + 1))
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
  fi

  if [[ -d "content" ]]; then
    DRAFT_MARKERS=$(grep -riE "\[TODO\]|\[DRAFT\]|\[PLACEHOLDER\]" "content" "${GREP_EXCLUDES[@]}" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${DRAFT_MARKERS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $DRAFT_MARKERS draft marker(s) in content [LOW]${NC}"
      say "Actions:"
      say "  • Ensure drafts/placeholders aren't published"
      LOW_ISSUES=$((LOW_ISSUES + 1))
      IDENTITY_REFS=$((IDENTITY_REFS + 1))
    fi
  fi

  if [[ $IDENTITY_REFS -eq 0 ]]; then
    sayc "${GREEN}✓ No obvious identity leaks detected${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 16: Dependency Vulnerabilities (npm audit)
# ============================================================

hr
sayc "${PURPLE}CHECK 16: Dependency Vulnerabilities (npm audit)${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -f "package.json" ]]; then
    sayc "${BLUE}ℹ️  package.json found${NC}"
    if _has_cmd npm; then
      say "  Running npm audit (may take a moment)..."
      AUDIT_OUTPUT=$((npm audit --json 2>/dev/null) || echo '{"error": true}')
      if printf '%s' "$AUDIT_OUTPUT" | grep -q '"error"'; then
        sayc "${YELLOW}⚠️  npm audit had issues (deps may not be installed) [LOW]${NC}"
        say "Actions:"
        say "  • Run: npm ci then re-run audit"
        LOW_ISSUES=$((LOW_ISSUES + 1))
      else
        VULNS=$(printf '%s' "$AUDIT_OUTPUT" | grep -o '"total":[0-9]*' | head -1 | cut -d: -f2 || echo "0")
        if [[ ${VULNS:-0} -gt 0 ]]; then
          sayc "${YELLOW}⚠️  Found $VULNS vulnerability/vulnerabilities [MEDIUM]${NC}"
          say "Actions:"
          say "  • Upgrade dependencies / lockfile hygiene"
          MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
        else
          sayc "${GREEN}✓ No vulnerabilities reported by npm audit${NC}"
        fi
      fi
    else
      sayc "${BLUE}ℹ️  npm not installed — skipping${NC}"
    fi
  else
    sayc "${GREEN}✓ No package.json found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 17: Git History Analysis (FIXED)
# ============================================================

hr
sayc "${PURPLE}CHECK 17: Git History Analysis${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -d ".git" ]] && _has_cmd git; then
    # FIX: Properly capture and count sensitive files in history
    SENSITIVE_HISTORY=0
    if git log --all --oneline --name-only 2>/dev/null | grep -qE '\.(env|key|pem|p12|pfx|backup|bak)$'; then
      SENSITIVE_HISTORY=$(git log --all --oneline --name-only 2>/dev/null \
        | grep -E '\.(env|key|pem|p12|pfx|backup|bak)$' \
        | sort -u \
        | wc -l | tr -d ' ')
    fi

    if [[ ${SENSITIVE_HISTORY:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $SENSITIVE_HISTORY sensitive-file reference(s) in git history [MEDIUM]${NC}"
      say "Actions:"
      say "  • Secrets may remain in history even if deleted"
      say "  • Use git filter-repo (preferred) or BFG"
      say "  • Rotate secrets anyway"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    else
      sayc "${GREEN}✓ No obvious sensitive extensions in git history${NC}"
    fi
  else
    sayc "${BLUE}ℹ️  Not a git repository — skipping${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 18: Module/Theme Supply Chain
# ============================================================

hr
sayc "${PURPLE}CHECK 18: Module/Theme Supply Chain${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -f "go.mod" ]]; then
    sayc "${BLUE}ℹ️  go.mod found (Hugo modules possible)${NC}"
    NON_OFFICIAL=$(
      grep -E "github\.com/[^/]+/[^/]+" "go.mod" 2>/dev/null \
        | grep -vi "gohugoio" \
        | wc -l | tr -d ' ' \
        || echo 0
    )

    if [[ "${NON_OFFICIAL:-0}" -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $NON_OFFICIAL third-party module(s) [MEDIUM]${NC}"
      grep -E "github\.com/[^/]+/[^/]+" "go.mod" 2>/dev/null \
        | grep -vi "gohugoio" \
        | head -"$SHOW_MATCHES" \
        | sed 's/^/  /'
      say "Actions:"
      say "  • Pin versions; review upstream repos"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    else
      sayc "${GREEN}✓ No obvious third-party modules in go.mod${NC}"
    fi
    say ""
  fi

  if [[ -d "themes" ]]; then
    if ! compgen -G "themes/*" >/dev/null 2>&1; then
      sayc "${GREEN}✓ No themes detected${NC}"
      say ""
    else
      THEME_COUNT=$(find "themes" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ' || echo 0)
      sayc "${BLUE}ℹ️  Found ${THEME_COUNT:-0} theme(s)${NC}"

      for theme_dir in themes/*; do
        [[ -d "$theme_dir" ]] || continue
        theme_name=$(basename "$theme_dir")

        if [[ -d "$theme_dir/.git" ]] && _has_cmd git; then
          REMOTE=$(cd "$theme_dir" && git remote get-url origin 2>/dev/null || echo "unknown")
          sayc "  ${GREEN}✓${NC} $theme_name: git-tracked ($REMOTE)"

          LICENSE_FILE=""
          [[ -f "$theme_dir/LICENSE" ]] && LICENSE_FILE="$theme_dir/LICENSE"
          [[ -f "$theme_dir/LICENSE.md" ]] && LICENSE_FILE="$theme_dir/LICENSE.md"

          if [[ -n "$LICENSE_FILE" ]]; then
            LICENSE_TYPE=$(grep -iE "(MIT|Apache|GPL|BSD)" "$LICENSE_FILE" 2>/dev/null | head -1 || echo "Unknown")
            if printf '%s' "$LICENSE_TYPE" | grep -qi "GPL"; then
              sayc "    ${YELLOW}⚠️${NC} GPL-ish license detected [LOW]"
              LOW_ISSUES=$((LOW_ISSUES + 1))
            else
              sayc "    ${GREEN}✓${NC} License hint: $LICENSE_TYPE"
            fi
          else
            sayc "    ${YELLOW}⚠️${NC} No LICENSE file found [LOW]"
            LOW_ISSUES=$((LOW_ISSUES + 1))
          fi
        else
          sayc "  ${YELLOW}⚠️${NC} $theme_name: copied theme (no version tracking) [MEDIUM]"
          say "    Actions: prefer submodule or Hugo module tracking"
          MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
        fi
      done
      say ""
    fi
  else
    sayc "${GREEN}✓ No themes directory found${NC}"
    say ""
  fi
fi

# ============================================================
# CHECK 19: Custom Shortcode Security (Hugo)
# ============================================================

hr
sayc "${PURPLE}CHECK 19: Custom Shortcode Injection Risks${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -d "layouts/shortcodes" ]]; then
    SHORTCODE_COUNT=$(find "layouts/shortcodes" -name "*.html" 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${SHORTCODE_COUNT:-0} -gt 0 ]]; then
      sayc "${BLUE}ℹ️  Found $SHORTCODE_COUNT custom shortcode(s)${NC}"
      UNSAFE=$(grep -rE "(\.Get|\.Inner|readFile|getJSON|getCSV)" "layouts/shortcodes" --include="*.html" 2>/dev/null | wc -l | tr -d ' ' || true)
      if [[ ${UNSAFE:-0} -gt 0 ]]; then
        sayc "${YELLOW}⚠️  Found $UNSAFE dynamic shortcode usage(s) [MEDIUM]${NC}"
        grep -rE "(\.Get|\.Inner|readFile|getJSON|getCSV)" "layouts/shortcodes" --include="*.html" -n 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
        say "Actions:"
        say "  • Avoid rendering untrusted input directly"
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
      else
        sayc "${GREEN}✓ Shortcodes appear safe${NC}"
      fi
    else
      sayc "${GREEN}✓ No shortcodes found${NC}"
    fi
  else
    sayc "${GREEN}✓ No custom shortcodes directory found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 20: Netlify Build Logs / Env Leaks
# ============================================================

hr
sayc "${PURPLE}CHECK 20: Netlify Build Env Exposure${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -f "netlify.toml" ]]; then
    ECHO_COMMANDS=$(grep -E "(echo|print|console\.log).*\\\$" "netlify.toml" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${ECHO_COMMANDS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Build commands may leak env vars [HIGH]${NC}"
      grep -E "(echo|print|console\.log).*\\\$" "netlify.toml" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      say "Actions:"
      say "  • Remove echo/print of env vars in build steps"
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    else
      sayc "${GREEN}✓ No obvious env-var echoing in netlify.toml${NC}"
    fi

    if ! grep -qiE 'publish[[:space:]]*=' "netlify.toml"; then
      sayc "${YELLOW}⚠️  Publish dir not explicitly set [LOW]${NC}"
      say "Actions:"
      say "  • Set publish directory explicitly"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
  else
    sayc "${GREEN}✓ No netlify.toml found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 21: RSS/Sitemap Unintended Disclosure
# ============================================================

hr
sayc "${PURPLE}CHECK 21: RSS/Sitemap Information Leaks${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  RSS_SITEMAP_ISSUES=0

  if [[ -f "$OUTPUT_DIR/index.xml" ]]; then
    DRAFT_IN_RSS=$(grep -i "draft" "$OUTPUT_DIR/index.xml" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${DRAFT_IN_RSS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  RSS feed may include draft markers [HIGH]${NC}"
      say "Actions:"
      say "  • Ensure drafts excluded in prod builds"
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
      RSS_SITEMAP_ISSUES=$((RSS_SITEMAP_ISSUES + 1))
    fi
  fi

  if [[ -f "$OUTPUT_DIR/sitemap.xml" ]]; then
    SENSITIVE_PATHS=$(grep -E "(admin|private|internal|test|staging)" "$OUTPUT_DIR/sitemap.xml" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${SENSITIVE_PATHS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Sitemap includes sensitive-looking paths [MEDIUM]${NC}"
      grep -E "(admin|private|internal|test|staging)" "$OUTPUT_DIR/sitemap.xml" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      say "Actions:"
      say "  • Remove sensitive paths from sitemap"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
      RSS_SITEMAP_ISSUES=$((RSS_SITEMAP_ISSUES + 1))
    fi
  fi

  if [[ $RSS_SITEMAP_ISSUES -eq 0 ]]; then
    sayc "${GREEN}✓ RSS and sitemap look clean${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 22: Front Matter Secrets
# ============================================================

hr
sayc "${PURPLE}CHECK 22: Front Matter Secrets${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -d "content" ]]; then
    FRONTMATTER_SECRETS=$(grep -rE "^(api_key|apikey|token|secret|password):[[:space:]]*['\"]?[A-Za-z0-9._-]{20,}" "content" --include="*.md" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${FRONTMATTER_SECRETS:-0} -gt 0 ]]; then
      sayc "${RED}✗ Found $FRONTMATTER_SECRETS potential secret(s) in front matter [CRITICAL]${NC}"
      grep -rE "^(api_key|apikey|token|secret|password):" "content" --include="*.md" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      say "Actions:"
      say "  • Remove secret values from front matter"
      say "  • Rotate tokens/keys"
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    else
      sayc "${GREEN}✓ No obvious secrets in content front matter${NC}"
    fi
  else
    sayc "${BLUE}ℹ️  No content/ directory found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 23: Git Hooks / Pre-commit Validation
# ============================================================

hr
sayc "${PURPLE}CHECK 23: Pre-commit Hooks / Validation${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -d ".git/hooks" ]]; then
    HAS_ANY=0
    if [[ -f ".git/hooks/pre-commit" ]]; then
      HAS_ANY=1
      sayc "${GREEN}✓ .git/hooks/pre-commit exists${NC}"
      if grep -qiE "(secret|credential|key|token|trufflehog|gitleaks|detect-secrets)" ".git/hooks/pre-commit" 2>/dev/null; then
        sayc "${GREEN}✓ Pre-commit includes security keywords${NC}"
      else
        sayc "${YELLOW}⚠️  Pre-commit exists but no secret scanning detected [LOW]${NC}"
        LOW_ISSUES=$((LOW_ISSUES + 1))
      fi
    fi

    if [[ -f ".pre-commit-config.yaml" ]]; then
      HAS_ANY=1
      sayc "${GREEN}✓ .pre-commit-config.yaml found${NC}"
      if grep -qiE "(trufflehog|gitleaks|detect-secrets|secret)" ".pre-commit-config.yaml" 2>/dev/null; then
        sayc "${GREEN}✓ Pre-commit config includes security hooks${NC}"
      else
        sayc "${YELLOW}⚠️  Pre-commit config missing secrets hooks [LOW]${NC}"
        LOW_ISSUES=$((LOW_ISSUES + 1))
      fi
    fi

    if [[ $HAS_ANY -eq 0 ]]; then
      sayc "${YELLOW}⚠️  No pre-commit hooks configured [MEDIUM]${NC}"
      say "Actions:"
      say "  • Add pre-commit with at least secrets scanning + lint"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  else
    sayc "${BLUE}ℹ️  No .git/hooks directory found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 24: Output directory committed (hygiene)
# ============================================================

hr
sayc "${PURPLE}CHECK 24: Output Directory Committed (Build Artifact Hygiene)${NC}"
hr

if [[ -d ".git" && -n "${OUTPUT_DIR:-}" && -d "${OUTPUT_DIR:-}" && "$ONLY_OUTPUT" -eq 0 ]]; then
  if [[ "$INCLUDE_OUTPUT_IN_SOURCE" -eq 0 ]]; then
    if _has_cmd git; then
      OUTPUT_TRACKED_COUNT=$(git ls-files "$OUTPUT_BASENAME" 2>/dev/null | wc -l | tr -d ' ' || true)
      if [[ ${OUTPUT_TRACKED_COUNT:-0} -gt 0 ]]; then
        sayc "${YELLOW}⚠️  Output dir '$OUTPUT_BASENAME/' appears tracked by git [HIGH]${NC}"
        say "Actions:"
        say "  • Usually do NOT commit build output for Netlify builds"
        say "  • Remove tracked output:"
        say "      git rm -r --cached \"$OUTPUT_BASENAME\""
        say "      echo \"$OUTPUT_BASENAME/\" >> .gitignore"
        HIGH_ISSUES=$((HIGH_ISSUES + 1))
      else
        sayc "${GREEN}✓ Output dir '$OUTPUT_BASENAME/' is not tracked by git${NC}"
      fi
    else
      sayc "${BLUE}ℹ️  git not installed — cannot check tracked output${NC}"
    fi
  else
    sayc "${BLUE}ℹ️  Output tracking allowed (--include-output-in-source)${NC}"
  fi
else
  sayc "${BLUE}ℹ️  Not applicable (no git repo or no output dir detected)${NC}"
fi
say ""

# ============================================================
# CHECK 25: CI/CD Secret Leakage Patterns
# ============================================================

hr
sayc "${PURPLE}CHECK 25: CI/CD Secret Leakage Patterns${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  CI_CD_ISSUES=0
  
  # GitHub Actions
  if [[ -d ".github/workflows" ]]; then
    sayc "${BLUE}ℹ️  GitHub Actions detected${NC}"
    
    # Check for secrets in echo/print commands
    SECRET_ECHO=$(grep -rE "(echo|print).*\\\$\{\{.*secrets\." ".github/workflows" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${SECRET_ECHO:-0} -gt 0 ]]; then
      sayc "${RED}✗ CRITICAL: Secrets echoed in GitHub Actions [CRITICAL]${NC}"
      grep -rE "(echo|print).*\\\$\{\{.*secrets\." ".github/workflows" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      say "  GitHub Actions logs are PUBLIC for public repos!"
      CI_CD_ISSUES=$((CI_CD_ISSUES + 1))
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    fi
    
    # Check for hardcoded tokens in workflow files
    HARDCODED_TOKENS=$(grep -rE "(github_token|GITHUB_TOKEN|GH_TOKEN):[[:space:]]*['\"][a-zA-Z0-9_-]{20,}" ".github/workflows" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${HARDCODED_TOKENS:-0} -gt 0 ]]; then
      sayc "${RED}✗ Found hardcoded tokens in workflow files [CRITICAL]${NC}"
      grep -rE "(github_token|GITHUB_TOKEN|GH_TOKEN):[[:space:]]*['\"][a-zA-Z0-9_-]{20,}" ".github/workflows" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      CI_CD_ISSUES=$((CI_CD_ISSUES + 1))
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    fi
    
    # Check for AWS keys patterns
    AWS_KEYS=$(grep -rE "(AWS_ACCESS_KEY|AWS_SECRET|AKIA[0-9A-Z]{16})" ".github/workflows" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${AWS_KEYS:-0} -gt 0 ]]; then
      sayc "${RED}✗ AWS credentials pattern detected [CRITICAL]${NC}"
      grep -rE "(AWS_ACCESS_KEY|AWS_SECRET|AKIA[0-9A-Z]{16})" ".github/workflows" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      CI_CD_ISSUES=$((CI_CD_ISSUES + 1))
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    fi
    
    # Check for base64-encoded secrets (common obfuscation attempt)
    BASE64_SECRETS=$(grep -rE "echo.*base64|base64.*secrets\." ".github/workflows" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${BASE64_SECRETS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Base64 encoding used with secrets [HIGH]${NC}"
      say "  Base64 is encoding, not encryption - still visible in logs!"
      grep -rE "echo.*base64|base64.*secrets\." ".github/workflows" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      CI_CD_ISSUES=$((CI_CD_ISSUES + 1))
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    fi
  fi
  
  # GitLab CI
  if [[ -f ".gitlab-ci.yml" ]]; then
    sayc "${BLUE}ℹ️  GitLab CI detected${NC}"
    
    SECRET_ECHO=$(grep -E "(echo|print).*\\\$" ".gitlab-ci.yml" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${SECRET_ECHO:-0} -gt 0 ]]; then
      sayc "${RED}✗ Variables echoed in GitLab CI [HIGH]${NC}"
      grep -E "(echo|print).*\\\$" ".gitlab-ci.yml" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      CI_CD_ISSUES=$((CI_CD_ISSUES + 1))
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    fi
    
    # Check for hardcoded values in variables section
    HARDCODED_VARS=$(grep -A5 "^variables:" ".gitlab-ci.yml" 2>/dev/null | grep -E ":[[:space:]]*['\"][^'\"]{20,}" | wc -l | tr -d ' ' || true)
    if [[ ${HARDCODED_VARS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Hardcoded values in variables section [MEDIUM]${NC}"
      say "  Use GitLab CI/CD variables for secrets, not .gitlab-ci.yml"
      CI_CD_ISSUES=$((CI_CD_ISSUES + 1))
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  fi
  
  # CircleCI
  if [[ -f ".circleci/config.yml" ]]; then
    sayc "${BLUE}ℹ️  CircleCI detected${NC}"
    
    SECRET_ECHO=$(grep -rE "(echo|print).*\\\$" ".circleci/" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${SECRET_ECHO:-0} -gt 0 ]]; then
      sayc "${RED}✗ Variables echoed in CircleCI config [HIGH]${NC}"
      grep -rE "(echo|print).*\\\$" ".circleci/" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      CI_CD_ISSUES=$((CI_CD_ISSUES + 1))
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    fi
  fi
  
  if [[ $CI_CD_ISSUES -gt 0 ]]; then
    say ""
    say "Actions:"
    say "  • NEVER echo/print secrets in CI/CD logs"
    say "  • Use masked/protected variables in CI/CD settings"
    say "  • Review public build logs for exposed secrets"
    say "  • Rotate any exposed credentials immediately"
    say "  • Use tools like: git-secrets, talisman, or detect-secrets in pre-commit"
  else
    sayc "${GREEN}✓ No obvious CI/CD secret leakage patterns${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 26: Serverless Function Exposure
# ============================================================

hr
sayc "${PURPLE}CHECK 26: Serverless Function Exposure${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  SERVERLESS_ISSUES=0
  
  # Netlify Functions
  FUNCTION_DIRS=("netlify/functions" ".netlify/functions" "functions")
  
  for func_dir in "${FUNCTION_DIRS[@]}"; do
    if [[ -d "$func_dir" ]]; then
      sayc "${BLUE}ℹ️  Serverless functions found: $func_dir/${NC}"
      
      # Check for CORS wildcard (*)
      CORS_WILDCARD=$(grep -rE "Access-Control-Allow-Origin.*\*" "$func_dir" 2>/dev/null | wc -l | tr -d ' ' || true)
      if [[ ${CORS_WILDCARD:-0} -gt 0 ]]; then
        sayc "${YELLOW}⚠️  CORS wildcard (*) found in functions [HIGH]${NC}"
        grep -rE "Access-Control-Allow-Origin.*\*" "$func_dir" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
        say "  Allows any domain to call your function"
        SERVERLESS_ISSUES=$((SERVERLESS_ISSUES + 1))
        HIGH_ISSUES=$((HIGH_ISSUES + 1))
      fi
      
      # Check for missing rate limiting
      HAS_RATE_LIMIT=$(grep -rE "(rateLimit|rate-limit|throttle)" "$func_dir" 2>/dev/null | wc -l | tr -d ' ' || true)
      FUNCTION_COUNT=$(find "$func_dir" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.go" -o -name "*.py" \) 2>/dev/null | wc -l | tr -d ' ')
      
      if [[ ${HAS_RATE_LIMIT:-0} -eq 0 && ${FUNCTION_COUNT:-0} -gt 0 ]]; then
        sayc "${YELLOW}⚠️  No rate limiting detected in functions [MEDIUM]${NC}"
        say "  Functions are publicly accessible and can be abused"
        SERVERLESS_ISSUES=$((SERVERLESS_ISSUES + 1))
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
      fi
      
      # Check for environment variables used without validation
      ENV_USAGE=$(grep -rE "process\.env\.|os\.getenv|os\.environ" "$func_dir" 2>/dev/null | wc -l | tr -d ' ' || true)
      ENV_VALIDATION=$(grep -rE "(validate|check|assert|throw.*undefined)" "$func_dir" 2>/dev/null | wc -l | tr -d ' ' || true)
      
      if [[ ${ENV_USAGE:-0} -gt 0 && ${ENV_VALIDATION:-0} -eq 0 ]]; then
        sayc "${YELLOW}⚠️  Environment variables used without validation [MEDIUM]${NC}"
        say "  Missing env vars can cause runtime errors or unexpected behavior"
        SERVERLESS_ISSUES=$((SERVERLESS_ISSUES + 1))
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
      fi
      
      # Check for external API calls without input sanitization
      EXTERNAL_CALLS=$(grep -rE "(fetch\(|axios\.|http\.|https\.)" "$func_dir" 2>/dev/null | wc -l | tr -d ' ' || true)
      INPUT_SANITIZE=$(grep -rE "(sanitize|escape|validate|xss)" "$func_dir" 2>/dev/null | wc -l | tr -d ' ' || true)
      
      if [[ ${EXTERNAL_CALLS:-0} -gt 0 && ${INPUT_SANITIZE:-0} -eq 0 ]]; then
        sayc "${YELLOW}⚠️  External API calls without obvious input validation [MEDIUM]${NC}"
        say "  User input to external APIs = potential SSRF/injection"
        grep -rE "(fetch\(|axios\.|http\.|https\.)" "$func_dir" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
        SERVERLESS_ISSUES=$((SERVERLESS_ISSUES + 1))
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
      fi
      
      # Check for SQL queries (potential injection)
      SQL_QUERIES=$(grep -rE "(SELECT|INSERT|UPDATE|DELETE).*FROM" "$func_dir" 2>/dev/null | wc -l | tr -d ' ' || true)
      if [[ ${SQL_QUERIES:-0} -gt 0 ]]; then
        sayc "${RED}✗ SQL queries detected in functions [HIGH]${NC}"
        say "  Ensure parameterized queries are used (not string concatenation)"
        grep -rE "(SELECT|INSERT|UPDATE|DELETE).*FROM" "$func_dir" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
        SERVERLESS_ISSUES=$((SERVERLESS_ISSUES + 1))
        HIGH_ISSUES=$((HIGH_ISSUES + 1))
      fi
      
      # Check for hardcoded credentials in functions
      FUNCTION_CREDS=$(grep -rE "(password|api[_-]?key|secret|token)[[:space:]]*[:=][[:space:]]*['\"][^'\"]{8,}" "$func_dir" 2>/dev/null | wc -l | tr -d ' ' || true)
      if [[ ${FUNCTION_CREDS:-0} -gt 0 ]]; then
        sayc "${RED}✗ CRITICAL: Hardcoded credentials in serverless functions [CRITICAL]${NC}"
        grep -rE "(password|api[_-]?key|secret|token)[[:space:]]*[:=][[:space:]]*['\"][^'\"]{8,}" "$func_dir" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
        SERVERLESS_ISSUES=$((SERVERLESS_ISSUES + 1))
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
      fi
    fi
  done
  
  if [[ $SERVERLESS_ISSUES -gt 0 ]]; then
    say ""
    say "Actions:"
    say "  • Implement rate limiting (e.g., @netlify/functions + rate-limit library)"
    say "  • Use CORS allowlist instead of wildcard (*)"
    say "  • Validate all environment variables at function startup"
    say "  • Sanitize user inputs before external API calls"
    say "  • Use parameterized queries for databases"
    say "  • Store secrets in Netlify environment variables, not code"
    say "  • Consider function authentication (Netlify Identity, JWT)"
  elif compgen -G "netlify/functions/*" >/dev/null 2>&1 || compgen -G ".netlify/functions/*" >/dev/null 2>&1 || compgen -G "functions/*" >/dev/null 2>&1; then
    sayc "${GREEN}✓ Serverless functions present with no obvious issues${NC}"
  else
    sayc "${GREEN}✓ No serverless functions found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 27: Third-Party Script Integrity (SRI)
# ============================================================

hr
sayc "${PURPLE}CHECK 27: Third-Party Script Integrity (SRI)${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  # Find all external script tags
  EXTERNAL_SCRIPTS=$(grep -roh '<script[^>]*src="https\?://[^"]*"[^>]*>' "$OUTPUT_DIR" --include="*.html" 2>/dev/null | sort -u || true)
  
  if [[ -n "$EXTERNAL_SCRIPTS" ]]; then
    TOTAL_EXTERNAL=$(printf '%s\n' "$EXTERNAL_SCRIPTS" | wc -l | tr -d ' ')
    
    # Count scripts WITHOUT integrity attribute
    NO_SRI=$(printf '%s\n' "$EXTERNAL_SCRIPTS" | grep -v "integrity=" | wc -l | tr -d ' ' || true)
    
    if [[ ${NO_SRI:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found ${NO_SRI}/${TOTAL_EXTERNAL} external scripts without SRI [MEDIUM]${NC}"
      
      # Show examples without SRI
      printf '%s\n' "$EXTERNAL_SCRIPTS" | grep -v "integrity=" | head -5 | sed 's/^/  /'
      
      say ""
      say "Third-party scripts without SRI are supply-chain risks:"
      
      # Identify common CDNs
      GOOGLE_CDN=$(printf '%s\n' "$EXTERNAL_SCRIPTS" | grep -c "googleapis.com\|gstatic.com" || true)
      CLOUDFLARE_CDN=$(printf '%s\n' "$EXTERNAL_SCRIPTS" | grep -c "cdnjs.cloudflare.com" || true)
      JSDELIVR_CDN=$(printf '%s\n' "$EXTERNAL_SCRIPTS" | grep -c "jsdelivr.net" || true)
      UNPKG_CDN=$(printf '%s\n' "$EXTERNAL_SCRIPTS" | grep -c "unpkg.com" || true)
      GA_ANALYTICS=$(printf '%s\n' "$EXTERNAL_SCRIPTS" | grep -c "google-analytics.com\|googletagmanager.com" || true)
      
      [[ ${GOOGLE_CDN:-0} -gt 0 ]] && say "  • Google CDN scripts: $GOOGLE_CDN"
      [[ ${CLOUDFLARE_CDN:-0} -gt 0 ]] && say "  • Cloudflare CDN scripts: $CLOUDFLARE_CDN"
      [[ ${JSDELIVR_CDN:-0} -gt 0 ]] && say "  • jsDelivr CDN scripts: $JSDELIVR_CDN"
      [[ ${UNPKG_CDN:-0} -gt 0 ]] && say "  • unpkg CDN scripts: $UNPKG_CDN"
      [[ ${GA_ANALYTICS:-0} -gt 0 ]] && say "  • Google Analytics/Tag Manager: $GA_ANALYTICS"
      
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    else
      sayc "${GREEN}✓ All ${TOTAL_EXTERNAL} external scripts have SRI hashes${NC}"
    fi
    
    # Check for CSP
    CSP_FOUND=$(grep -roh "Content-Security-Policy" "$OUTPUT_DIR" --include="*.html" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${CSP_FOUND:-0} -eq 0 ]] && [[ ! -f "netlify.toml" || $(grep -c "Content-Security-Policy" "netlify.toml" 2>/dev/null || echo 0) -eq 0 ]]; then
      sayc "${BLUE}ℹ️  No Content-Security-Policy detected [LOW]${NC}"
      say "  CSP provides defense-in-depth against compromised scripts"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
    
    say ""
    say "Actions:"
    say "  • Generate SRI hashes: https://www.srihash.org/"
    say "  • Add integrity + crossorigin attributes to <script> tags"
    say "  • Example:"
    say "      <script src=\"https://cdn.example.com/lib.js\""
    say "              integrity=\"sha384-oqVu...\" crossorigin=\"anonymous\"></script>"
    say "  • Consider Content-Security-Policy header to enforce SRI"
    say "  • Pin CDN versions (avoid /latest or version ranges)"
  else
    sayc "${GREEN}✓ No external scripts found in output${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 28: Form Action Endpoints
# ============================================================

hr
sayc "${PURPLE}CHECK 28: Form Action Endpoints${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  FORM_ISSUES=0
  
  # Find all forms
  FORMS=$(grep -roh '<form[^>]*>' "$OUTPUT_DIR" --include="*.html" 2>/dev/null || true)
  
  if [[ -n "$FORMS" ]]; then
    TOTAL_FORMS=$(printf '%s\n' "$FORMS" | wc -l | tr -d ' ')
    sayc "${BLUE}ℹ️  Found $TOTAL_FORMS form(s)${NC}"
    
    # Check for non-HTTPS action URLs
    HTTP_FORMS=$(printf '%s\n' "$FORMS" | grep -i 'action="http://' | wc -l | tr -d ' ' || true)
    if [[ ${HTTP_FORMS:-0} -gt 0 ]]; then
      sayc "${RED}✗ Found ${HTTP_FORMS} form(s) submitting over HTTP [HIGH]${NC}"
      printf '%s\n' "$FORMS" | grep -i 'action="http://' | head -"$SHOW_MATCHES" | sed 's/^/  /'
      FORM_ISSUES=$((FORM_ISSUES + 1))
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    fi
    
    # Check for mailto: actions (email harvesting risk)
    MAILTO_FORMS=$(printf '%s\n' "$FORMS" | grep -i 'action="mailto:' | wc -l | tr -d ' ' || true)
    if [[ ${MAILTO_FORMS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found ${MAILTO_FORMS} form(s) using mailto: action [MEDIUM]${NC}"
      say "  mailto: forms expose email addresses and provide poor UX"
      printf '%s\n' "$FORMS" | grep -i 'action="mailto:' | head -"$SHOW_MATCHES" | sed 's/^/  /'
      FORM_ISSUES=$((FORM_ISSUES + 1))
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
    
    # Check for third-party form processors
    THIRD_PARTY_FORMS=$(printf '%s\n' "$FORMS" | grep -iE 'action="https?://(formspree\.io|getform\.io|forms\.google\.com|docs\.google\.com|formcarry\.com|formspark\.io|basin\.com|usebasin\.com|kwes\.io|formsubmit\.co|staticforms\.xyz)' | wc -l | tr -d ' ' || true)
    if [[ ${THIRD_PARTY_FORMS:-0} -gt 0 ]]; then
      sayc "${BLUE}ℹ️  Found ${THIRD_PARTY_FORMS} third-party form processor(s) [LOW]${NC}"
      say "  Data flows to external service - verify GDPR/privacy compliance"
      printf '%s\n' "$FORMS" | grep -iE 'action="https?://(formspree|getform|forms\.google|formcarry|formspark|basin|usebasin|kwes|formsubmit|staticforms)' | head -"$SHOW_MATCHES" | sed 's/^/  /'
      FORM_ISSUES=$((FORM_ISSUES + 1))
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
    
    # Check for CSRF protection (very basic check)
    FORMS_WITH_TOKEN=$(grep -roh '<input[^>]*name="[^"]*\(csrf\|token\|_token\)[^"]*"' "$OUTPUT_DIR" --include="*.html" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${FORMS_WITH_TOKEN:-0} -eq 0 ]] && [[ $TOTAL_FORMS -gt 0 ]]; then
      sayc "${BLUE}ℹ️  No obvious CSRF tokens detected [LOW]${NC}"
      say "  Consider CSRF protection for state-changing forms"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
    
    # Check for honeypot fields (bot protection)
    HONEYPOT=$(grep -roh '<input[^>]*\(style="display:\s*none"\|class="[^"]*hidden\)' "$OUTPUT_DIR" --include="*.html" 2>/dev/null | grep -i 'name=' | wc -l | tr -d ' ' || true)
    if [[ ${HONEYPOT:-0} -eq 0 ]] && [[ $TOTAL_FORMS -gt 0 ]]; then
      sayc "${BLUE}ℹ️  No honeypot fields detected [LOW]${NC}"
      say "  Honeypot fields help prevent spam bot submissions"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
    
    if [[ $FORM_ISSUES -gt 0 ]]; then
      say ""
      say "Actions:"
      say "  • Use HTTPS for all form actions"
      say "  • Replace mailto: with proper form backend (Netlify Forms, serverless)"
      say "  • Add CSRF tokens for state-changing operations"
      say "  • Implement honeypot fields for bot protection"
      say "  • Review third-party processors for GDPR compliance"
      say "  • Consider Netlify Forms (built-in spam protection + HTTPS)"
    else
      sayc "${GREEN}✓ Forms appear secure${NC}"
    fi
  else
    sayc "${GREEN}✓ No forms found in output${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 29: Analytics & Tag Manager Data Leakage
# ============================================================

hr
sayc "${PURPLE}CHECK 29: Analytics & Tag Manager Data Leakage${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  ANALYTICS_ISSUES=0
  
  # Check for Google Tag Manager
  GTM=$(grep -roh "googletagmanager\.com/gtm\.js\?id=GTM-[A-Z0-9]*" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | sort -u || true)
  if [[ -n "$GTM" ]]; then
    GTM_COUNT=$(printf '%s\n' "$GTM" | wc -l | tr -d ' ')
    sayc "${BLUE}ℹ️  Google Tag Manager detected ($GTM_COUNT container(s))${NC}"
    
    # Check for dataLayer.push with PII patterns
    DATALAYER_PII=$(grep -rE "dataLayer\.push.*\{[^}]*(email|phone|ssn|password|credit|card)" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${DATALAYER_PII:-0} -gt 0 ]]; then
      sayc "${RED}✗ Potential PII in dataLayer.push() [HIGH]${NC}"
      grep -rE "dataLayer\.push.*\{[^}]*(email|phone|ssn|password|credit|card)" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      say "  PII in analytics = GDPR violation + data breach risk"
      ANALYTICS_ISSUES=$((ANALYTICS_ISSUES + 1))
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    fi
  fi
  
  # Check for Google Analytics
  GA=$(grep -roh "google-analytics\.com/analytics\.js\|googletagmanager\.com/gtag/js" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | wc -l | tr -d ' ' || true)
  if [[ ${GA:-0} -gt 0 ]]; then
    sayc "${BLUE}ℹ️  Google Analytics detected${NC}"
    
    # Check for user ID tracking
    USER_ID=$(grep -rE "ga\(.*'set'.*'userId'" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${USER_ID:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  User ID tracking detected [MEDIUM]${NC}"
      say "  Ensure user IDs are anonymized/hashed (not email or real ID)"
      grep -rE "ga\(.*'set'.*'userId'" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      ANALYTICS_ISSUES=$((ANALYTICS_ISSUES + 1))
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  fi
  
  # Check for Segment
  SEGMENT=$(grep -roh "cdn\.segment\.com/analytics\.js" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | wc -l | tr -d ' ' || true)
  if [[ ${SEGMENT:-0} -gt 0 ]]; then
    sayc "${BLUE}ℹ️  Segment detected${NC}"
    
    # Check for identify() calls with PII
    SEGMENT_PII=$(grep -rE "analytics\.identify.*\{[^}]*(email|phone|address)" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${SEGMENT_PII:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  PII in Segment identify() [MEDIUM]${NC}"
      grep -rE "analytics\.identify.*\{[^}]*(email|phone|address)" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      ANALYTICS_ISSUES=$((ANALYTICS_ISSUES + 1))
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  fi
  
  # Check for Mixpanel
  MIXPANEL=$(grep -roh "mixpanel\.com/libs/mixpanel" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | wc -l | tr -d ' ' || true)
  if [[ ${MIXPANEL:-0} -gt 0 ]]; then
    sayc "${BLUE}ℹ️  Mixpanel detected${NC}"
  fi
  
  # Check for email addresses in URL parameters (common mistake)
  EMAIL_IN_URL=$(grep -roE "https?://[^\"' ]*[?&](email|user|utm_email)=[^&\"' ]*@[^&\"' ]*" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | wc -l | tr -d ' ' || true)
  if [[ ${EMAIL_IN_URL:-0} -gt 0 ]]; then
    sayc "${YELLOW}⚠️  Email addresses in URL parameters [MEDIUM]${NC}"
    say "  URLs with emails = logged in analytics, referrer headers, browser history"
    grep -roE "https?://[^\"' ]*[?&](email|user|utm_email)=[^&\"' ]*@[^&\"' ]*" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
    ANALYTICS_ISSUES=$((ANALYTICS_ISSUES + 1))
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
  fi
  
  # Check for internal user IDs as analytics properties
  INTERNAL_IDS=$(grep -rE "(userId|user_id|customerId|customer_id)['\"]?\s*:\s*[0-9]{5,}" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | wc -l | tr -d ' ' || true)
  if [[ ${INTERNAL_IDS:-0} -gt 0 ]]; then
    sayc "${BLUE}ℹ️  Internal IDs sent to analytics [LOW]${NC}"
    say "  Consider hashing user IDs before sending to third-party analytics"
    LOW_ISSUES=$((LOW_ISSUES + 1))
  fi
  
  if [[ $ANALYTICS_ISSUES -gt 0 ]]; then
    say ""
    say "Actions:"
    say "  • Remove PII (email, phone, SSN) from analytics events"
    say "  • Hash user IDs before sending to third parties"
    say "  • Never include email in URL parameters"
    say "  • Anonymize IP addresses (GA: anonymizeIp)"
    say "  • Review GDPR compliance for data collection"
    say "  • Use consent management platform (CMP) for opt-in/opt-out"
    say "  • Consider server-side tracking for sensitive data"
  elif [[ ${GA:-0} -gt 0 || ${GTM:-0} -gt 0 || ${SEGMENT:-0} -gt 0 || ${MIXPANEL:-0} -gt 0 ]]; then
    sayc "${GREEN}✓ Analytics configured with no obvious PII leakage${NC}"
  else
    sayc "${GREEN}✓ No third-party analytics detected${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 30: DNS/Subdomain Takeover Risk
# ============================================================

hr
sayc "${PURPLE}CHECK 30: DNS/Subdomain Takeover Risk${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  DNS_ISSUES=0
  
  # Check netlify.toml for custom domains
  if [[ -f "netlify.toml" ]]; then
    CUSTOM_DOMAINS=$(grep -E "^\s*domain\s*=" "netlify.toml" 2>/dev/null || true)
    if [[ -n "$CUSTOM_DOMAINS" ]]; then
      sayc "${BLUE}ℹ️  Custom domain(s) configured in netlify.toml${NC}"
      printf '%s\n' "$CUSTOM_DOMAINS" | sed 's/^/  /'
      say ""
      say "  Manual verification required:"
      say "  • Ensure DNS CNAME points to active Netlify site"
      say "  • Verify domain is claimed in Netlify dashboard"
      say "  • Check for orphaned DNS records to deleted sites"
      LOW_ISSUES=$((LOW_ISSUES + 1))
      DNS_ISSUES=$((DNS_ISSUES + 1))
    fi
  fi
  
  # Check for _redirects file with external domains
  if [[ -f "_redirects" || -f "public/_redirects" || -f "$OUTPUT_DIR/_redirects" ]]; then
    REDIRECT_FILE=""
    [[ -f "_redirects" ]] && REDIRECT_FILE="_redirects"
    [[ -f "public/_redirects" ]] && REDIRECT_FILE="public/_redirects"
    [[ -f "$OUTPUT_DIR/_redirects" ]] && REDIRECT_FILE="$OUTPUT_DIR/_redirects"
    
    if [[ -n "$REDIRECT_FILE" ]]; then
      # Look for redirects to external domains
      EXTERNAL_REDIRECTS=$(grep -E "https?://" "$REDIRECT_FILE" 2>/dev/null | grep -v "^#" || true)
      if [[ -n "$EXTERNAL_REDIRECTS" ]]; then
        sayc "${BLUE}ℹ️  External redirects found in _redirects${NC}"
        printf '%s\n' "$EXTERNAL_REDIRECTS" | head -5 | sed 's/^/  /'
        say ""
        say "  Verify target domains are:"
        say "  • Still active and under your control"
        say "  • Not vulnerable to takeover"
        LOW_ISSUES=$((LOW_ISSUES + 1))
        DNS_ISSUES=$((DNS_ISSUES + 1))
      fi
    fi
  fi
  
  # Check for common vulnerable CNAME patterns in docs
  VULNERABLE_PATTERNS=$(grep -rE "(\.s3\.amazonaws\.com|\.herokuapp\.com|\.azurewebsites\.net|\.github\.io|\.gitlab\.io|\.bitbucket\.io|\.surge\.sh|\.ghost\.io)" . \
    --include="*.md" --include="*.txt" --include="README*" --include="*.toml" --include="*.yml" --include="*.yaml" \
    "${GREP_EXCLUDES[@]}" 2>/dev/null | wc -l | tr -d ' ' || true)
  
  if [[ ${VULNERABLE_PATTERNS:-0} -gt 0 ]]; then
    sayc "${YELLOW}⚠️  References to takeover-vulnerable services found [MEDIUM]${NC}"
    say "  Common takeover targets: S3, Heroku, Azure, GitHub Pages, GitLab Pages"
    grep -rE "(\.s3\.amazonaws\.com|\.herokuapp\.com|\.azurewebsites\.net|\.github\.io|\.gitlab\.io)" . \
      --include="*.md" --include="*.txt" --include="README*" --include="*.toml" --include="*.yml" --include="*.yaml" \
      "${GREP_EXCLUDES[@]}" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /' || true
    DNS_ISSUES=$((DNS_ISSUES + 1))
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
  fi
  
  # Check for old Netlify site references
  OLD_NETLIFY=$(grep -rE "[a-z0-9-]+\.netlify\.(com|app)" . \
    --include="*.md" --include="*.txt" --include="README*" \
    "${GREP_EXCLUDES[@]}" 2>/dev/null | grep -v "$(basename "$PWD")" | wc -l | tr -d ' ' || true)
  
  if [[ ${OLD_NETLIFY:-0} -gt 0 ]]; then
    sayc "${BLUE}ℹ️  References to Netlify subdomains found [LOW]${NC}"
    say "  Verify these sites are still active and under your control"
    LOW_ISSUES=$((LOW_ISSUES + 1))
    DNS_ISSUES=$((DNS_ISSUES + 1))
  fi
  
  if [[ $DNS_ISSUES -gt 0 ]]; then
    say ""
    say "Actions:"
    say "  • Audit DNS records for orphaned CNAME entries"
    say "  • Remove DNS records pointing to deleted services"
    say "  • Use Netlify DNS for automatic cleanup"
    say "  • Monitor with: https://github.com/EdOverflow/can-i-take-over-xyz"
    say "  • Set up subdomain monitoring (e.g., SecurityTrails, DNSDumpster)"
    say "  • Delete unused subdomains from DNS provider"
  else
    sayc "${GREEN}✓ No obvious subdomain takeover risks${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 31: Stale OAuth Tokens in Static Content
# ============================================================

hr
sayc "${PURPLE}CHECK 31: Stale OAuth Tokens in Static Content${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  OAUTH_ISSUES=0
  
  # Check for OAuth redirect URIs in JavaScript
  REDIRECT_URIS=$(grep -roE "redirect_uri['\"]?\s*[:=]\s*['\"]https?://[^'\"]*['\"]" "$OUTPUT_DIR" --include="*.js" --include="*.html" 2>/dev/null || true)
  if [[ -n "$REDIRECT_URIS" ]]; then
    REDIRECT_COUNT=$(printf '%s\n' "$REDIRECT_URIS" | wc -l | tr -d ' ')
    sayc "${BLUE}ℹ️  Found $REDIRECT_COUNT OAuth redirect_uri reference(s)${NC}"
    
    # Check for localhost/development URIs
    DEV_REDIRECTS=$(printf '%s\n' "$REDIRECT_URIS" | grep -E "(localhost|127\.0\.0\.1|\.local|\.dev)" | wc -l | tr -d ' ' || true)
    if [[ ${DEV_REDIRECTS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Development redirect URIs in production code [MEDIUM]${NC}"
      printf '%s\n' "$REDIRECT_URIS" | grep -E "(localhost|127\.0\.0\.1|\.local|\.dev)" | head -"$SHOW_MATCHES" | sed 's/^/  /'
      OAUTH_ISSUES=$((OAUTH_ISSUES + 1))
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  fi
  
  # Check for Client IDs (even without secrets, still sensitive)
  CLIENT_IDS=$(grep -roE "(client_id|clientId|client-id)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9._-]{20,}['\"]" "$OUTPUT_DIR" --include="*.js" --include="*.html" 2>/dev/null | wc -l | tr -d ' ' || true)
  if [[ ${CLIENT_IDS:-0} -gt 0 ]]; then
    sayc "${BLUE}ℹ️  Found $CLIENT_IDS OAuth client_id reference(s) [LOW]${NC}"
    say "  Client IDs in frontend code are normal, but verify:"
    say "  • They're for public OAuth flows (implicit/PKCE)"
    say "  • Redirect URIs are properly configured"
    say "  • No client_secret is present (would be CRITICAL)"
    LOW_ISSUES=$((LOW_ISSUES + 1))
    
    # Check for client_secret (CRITICAL if found)
    CLIENT_SECRETS=$(grep -roE "(client_secret|clientSecret|client-secret)['\"]?\s*[:=]\s*['\"][^'\"]{10,}['\"]" "$OUTPUT_DIR" --include="*.js" --include="*.html" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${CLIENT_SECRETS:-0} -gt 0 ]]; then
      sayc "${RED}✗ CRITICAL: OAuth client_secret found in frontend code [CRITICAL]${NC}"
      grep -roE "(client_secret|clientSecret|client-secret)['\"]?\s*[:=]\s*['\"][^'\"]{10,}['\"]" "$OUTPUT_DIR" --include="*.js" --include="*.html" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      OAUTH_ISSUES=$((OAUTH_ISSUES + 1))
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    fi
  fi
  
  # Check for deprecated implicit grant flow
  IMPLICIT_FLOW=$(grep -rE "response_type['\"]?\s*[:=]\s*['\"]token" "$OUTPUT_DIR" --include="*.js" --include="*.html" 2>/dev/null | wc -l | tr -d ' ' || true)
  if [[ ${IMPLICIT_FLOW:-0} -gt 0 ]]; then
    sayc "${YELLOW}⚠️  Deprecated OAuth implicit flow detected [MEDIUM]${NC}"
    say "  Implicit flow is deprecated - use Authorization Code + PKCE instead"
    grep -rE "response_type['\"]?\s*[:=]\s*['\"]token" "$OUTPUT_DIR" --include="*.js" --include="*.html" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
    OAUTH_ISSUES=$((OAUTH_ISSUES + 1))
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
  fi
  
  # Check for access tokens in localStorage (common mistake)
  LOCALSTORAGE_TOKENS=$(grep -rE "localStorage\.(setItem|getItem).*['\"].*(token|access|refresh)" "$OUTPUT_DIR" --include="*.js" --include="*.html" 2>/dev/null | wc -l | tr -d ' ' || true)
  if [[ ${LOCALSTORAGE_TOKENS:-0} -gt 0 ]]; then
    sayc "${YELLOW}⚠️  Tokens stored in localStorage [MEDIUM]${NC}"
    say "  localStorage is vulnerable to XSS - consider httpOnly cookies"
    grep -rE "localStorage\.(setItem|getItem).*['\"].*(token|access|refresh)" "$OUTPUT_DIR" --include="*.js" --include="*.html" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
    OAUTH_ISSUES=$((OAUTH_ISSUES + 1))
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
  fi
  
  if [[ $OAUTH_ISSUES -gt 0 ]]; then
    say ""
    say "Actions:"
    say "  • NEVER expose client_secret in frontend code"
    say "  • Use Authorization Code + PKCE flow (not implicit)"
    say "  • Store tokens in httpOnly cookies (not localStorage)"
    say "  • Implement token rotation and short expiry"
    say "  • Remove development redirect URIs from production"
    say "  • Verify OAuth provider's redirect URI allowlist"
    say "  • Consider backend-for-frontend (BFF) pattern"
  else
    sayc "${GREEN}✓ No obvious OAuth token issues${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 32: Build-Time Data Exfiltration
# ============================================================

hr
sayc "${PURPLE}CHECK 32: Build-Time Data Exfiltration${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  BUILD_ISSUES=0
  
  # Check package.json scripts
  if [[ -f "package.json" ]]; then
    sayc "${BLUE}ℹ️  Analyzing package.json scripts${NC}"
    
    # Check for curl/wget to non-official domains
    SUSPICIOUS_DOWNLOADS=$(grep -E "(curl|wget|fetch|download).*https?://" "package.json" 2>/dev/null | \
      grep -vE "(npmjs\.org|github\.com|githubusercontent\.com|cloudflare\.com|unpkg\.com|jsdelivr\.net|yarnpkg\.com)" || true)
    
    if [[ -n "$SUSPICIOUS_DOWNLOADS" ]]; then
      sayc "${YELLOW}⚠️  Network calls to non-standard domains in scripts [HIGH]${NC}"
      printf '%s\n' "$SUSPICIOUS_DOWNLOADS" | head -"$SHOW_MATCHES" | sed 's/^/  /'
      say "  Build scripts downloading from unknown sources = supply chain risk"
      BUILD_ISSUES=$((BUILD_ISSUES + 1))
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    fi
    
    # Check for postinstall hooks
    POSTINSTALL=$(grep -E "\"postinstall\":" "package.json" 2>/dev/null || true)
    if [[ -n "$POSTINSTALL" ]]; then
      sayc "${YELLOW}⚠️  postinstall hook detected [MEDIUM]${NC}"
      printf '%s\n' "$POSTINSTALL" | sed 's/^/  /'
      say "  postinstall runs automatically after npm install - verify it's safe"
      BUILD_ISSUES=$((BUILD_ISSUES + 1))
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
    
    # Check for preinstall hooks
    PREINSTALL=$(grep -E "\"preinstall\":" "package.json" 2>/dev/null || true)
    if [[ -n "$PREINSTALL" ]]; then
      sayc "${YELLOW}⚠️  preinstall hook detected [MEDIUM]${NC}"
      printf '%s\n' "$PREINSTALL" | sed 's/^/  /'
      BUILD_ISSUES=$((BUILD_ISSUES + 1))
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  fi
  
  # Check netlify.toml build commands
  if [[ -f "netlify.toml" ]]; then
    sayc "${BLUE}ℹ️  Analyzing netlify.toml build commands${NC}"
    
    # Check for network calls in build
    BUILD_DOWNLOADS=$(grep -E "^\s*command.*=.*(curl|wget|fetch)" "netlify.toml" 2>/dev/null | \
      grep -vE "(npmjs\.org|github\.com|githubusercontent\.com)" || true)
    
    if [[ -n "$BUILD_DOWNLOADS" ]]; then
      sayc "${YELLOW}⚠️  Network downloads in build commands [HIGH]${NC}"
      printf '%s\n' "$BUILD_DOWNLOADS" | head -"$SHOW_MATCHES" | sed 's/^/  /'
      BUILD_ISSUES=$((BUILD_ISSUES + 1))
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    fi
    
    # Check for executable downloads
    EXECUTABLE_DOWNLOADS=$(grep -E "^\s*command.*(\.sh|\.py|\.rb|\.pl|binary|executable)" "netlify.toml" 2>/dev/null || true)
    if [[ -n "$EXECUTABLE_DOWNLOADS" ]]; then
      sayc "${YELLOW}⚠️  Executable downloads in build [HIGH]${NC}"
      printf '%s\n' "$EXECUTABLE_DOWNLOADS" | head -"$SHOW_MATCHES" | sed 's/^/  /'
      say "  Downloading and running scripts = supply chain attack vector"
      BUILD_ISSUES=$((BUILD_ISSUES + 1))
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    fi
  fi
  
  # Check for suspicious npm packages (common typosquatting targets)
  if [[ -f "package.json" ]]; then
    SUSPICIOUS_PACKAGES=$(grep -oE "\"[^\"]*\":" "package.json" | grep -E "(crossenv|cross-env\.js|nodemailer\.js|bootstrap\.js)" || true)
    if [[ -n "$SUSPICIOUS_PACKAGES" ]]; then
      sayc "${RED}✗ Potential typosquatting packages detected [CRITICAL]${NC}"
      printf '%s\n' "$SUSPICIOUS_PACKAGES" | sed 's/^/  /'
      say "  These may be malicious lookalikes of legitimate packages"
      BUILD_ISSUES=$((BUILD_ISSUES + 1))
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    fi
  fi
  
  # Check for .npmrc with non-official registries
  if [[ -f ".npmrc" ]]; then
    CUSTOM_REGISTRY=$(grep -E "^registry\s*=" ".npmrc" 2>/dev/null | grep -v "registry.npmjs.org" || true)
    if [[ -n "$CUSTOM_REGISTRY" ]]; then
      sayc "${YELLOW}⚠️  Custom npm registry configured [MEDIUM]${NC}"
      printf '%s\n' "$CUSTOM_REGISTRY" | sed 's/^/  /'
      say "  Verify this is an official private registry"
      BUILD_ISSUES=$((BUILD_ISSUES + 1))
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  fi
  
  if [[ $BUILD_ISSUES -gt 0 ]]; then
    say ""
    say "Actions:"
    say "  • Audit all build-time network calls"
    say "  • Verify package sources (npm audit, Socket.dev)"
    say "  • Pin dependency versions with lockfiles"
    say "  • Review postinstall/preinstall hooks"
    say "  • Use npm audit / yarn audit regularly"
    say "  • Consider: Dependabot, Snyk, or Socket Security"
    say "  • Never download + execute unverified scripts in builds"
  else
    sayc "${GREEN}✓ No obvious build-time supply chain risks${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 33: API Key Rotation Age
# ============================================================

hr
sayc "${PURPLE}CHECK 33: API Key Rotation Age${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  ROTATION_ISSUES=0
  
  if [[ -f ".env.example" || -f ".env.sample" || -f ".env.template" ]]; then
    ENV_EXAMPLE=""
    [[ -f ".env.example" ]] && ENV_EXAMPLE=".env.example"
    [[ -f ".env.sample" ]] && ENV_EXAMPLE=".env.sample"
    [[ -f ".env.template" ]] && ENV_EXAMPLE=".env.template"
    
    sayc "${BLUE}ℹ️  Found environment template: $ENV_EXAMPLE${NC}"
    
    # Check git history for when this file was last changed
    if [[ -d ".git" ]] && _has_cmd git; then
      LAST_MODIFIED=$(git log -1 --format="%cr" -- "$ENV_EXAMPLE" 2>/dev/null || echo "unknown")
      sayc "  Last modified: $LAST_MODIFIED"
      
      # Check if older than 90 days
      if [[ "$LAST_MODIFIED" != "unknown" ]]; then
        DAYS_AGO=$(git log -1 --format="%ct" -- "$ENV_EXAMPLE" 2>/dev/null || echo "0")
        NOW=$(date +%s)
        AGE_DAYS=$(( (NOW - DAYS_AGO) / 86400 ))
        
        if [[ $AGE_DAYS -gt 90 ]]; then
          sayc "${YELLOW}⚠️  Environment template unchanged for ${AGE_DAYS} days [MEDIUM]${NC}"
          say "  Consider reviewing and rotating API keys quarterly"
          ROTATION_ISSUES=$((ROTATION_ISSUES + 1))
          MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
        else
          sayc "${GREEN}✓ Environment template recently updated ($AGE_DAYS days ago)${NC}"
        fi
      fi
      
      # Check for same keys across branches
      if git branch -a | grep -qE "main|master|develop|staging|production"; then
        sayc "${BLUE}ℹ️  Checking for key reuse across branches${NC}"
        
        # This is a simplified check - in reality, would need to compare actual key values
        BRANCHES=$(git branch -a | grep -E "remotes/origin/(main|master|develop|staging|production)" | sed 's/.*\///' | sort -u)
        if [[ $(printf '%s\n' "$BRANCHES" | wc -l) -gt 1 ]]; then
          sayc "${BLUE}ℹ️  Multiple environment branches detected [LOW]${NC}"
          say "  Verify each environment uses unique API keys"
          LOW_ISSUES=$((LOW_ISSUES + 1))
        fi
      fi
    else
      sayc "${BLUE}ℹ️  Not a git repo - cannot check rotation age${NC}"
    fi
    
    # Parse .env.example for key categories
    API_KEYS=$(grep -iE "^[A-Z_]*API[A-Z_]*KEY" "$ENV_EXAMPLE" 2>/dev/null | wc -l | tr -d ' ' || true)
    SECRETS=$(grep -iE "^[A-Z_]*SECRET" "$ENV_EXAMPLE" 2>/dev/null | wc -l | tr -d ' ' || true)
    TOKENS=$(grep -iE "^[A-Z_]*TOKEN" "$ENV_EXAMPLE" 2>/dev/null | wc -l | tr -d ' ' || true)
    
    if [[ ${API_KEYS:-0} -gt 0 || ${SECRETS:-0} -gt 0 || ${TOKENS:-0} -gt 0 ]]; then
      sayc "${BLUE}ℹ️  Secret types in environment template:${NC}"
      [[ ${API_KEYS:-0} -gt 0 ]] && say "  • API keys: $API_KEYS"
      [[ ${SECRETS:-0} -gt 0 ]] && say "  • Secrets: $SECRETS"
      [[ ${TOKENS:-0} -gt 0 ]] && say "  • Tokens: $TOKENS"
    fi
    
  else
    sayc "${BLUE}ℹ️  No .env.example/.env.sample found${NC}"
    say "  Consider creating one to document required environment variables"
    LOW_ISSUES=$((LOW_ISSUES + 1))
  fi
  
  # Check for test vs prod key confusion
  if [[ -f ".env.example" ]]; then
    TEST_PROD_MIX=$(grep -E "(test|dev|development|staging).*prod|prod.*(test|dev|development|staging)" ".env.example" -i 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${TEST_PROD_MIX:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Possible test/prod key mixing in template [MEDIUM]${NC}"
      grep -E "(test|dev|development|staging).*prod|prod.*(test|dev|development|staging)" ".env.example" -i 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      ROTATION_ISSUES=$((ROTATION_ISSUES + 1))
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  fi
  
  say ""
  say "Actions:"
  say "  • Rotate API keys quarterly (every 90 days minimum)"
  say "  • Use separate keys per environment (dev/staging/prod)"
  say "  • Document key rotation schedule in team runbook"
  say "  • Set up calendar reminders for key rotation"
  say "  • Use secret management tools (Vault, AWS Secrets Manager)"
  say "  • Track key creation dates in password manager"
  say "  • Implement automated rotation where possible"
  say ""
fi

# ============================================================

# ============================================================
# FINAL SUMMARY + INTERACTIVE DECISION LOGIC
# ============================================================

say "=============================================="
say "🔒 FINAL SECURITY SUMMARY 🔒"
say "=============================================="
say ""
say "Generator detected: $GENERATOR"
[[ -n "${OUTPUT_DIR:-}" ]] && say "Output dir detected: $OUTPUT_DIR"
say ""

TOTAL_ISSUES=$((CRITICAL_ISSUES + HIGH_ISSUES + MEDIUM_ISSUES + LOW_ISSUES))

# Display issue summary
if [[ $CRITICAL_ISSUES -gt 0 ]]; then
  sayc "${RED}🚨 CRITICAL: $CRITICAL_ISSUES issue(s) - DEPLOYMENT BLOCKED${NC}"
fi
if [[ $HIGH_ISSUES -gt 0 ]]; then
  sayc "${RED}⚠️  HIGH:     $HIGH_ISSUES issue(s) - DEPLOYMENT BLOCKED${NC}"
fi
if [[ $MEDIUM_ISSUES -gt 0 ]]; then
  sayc "${YELLOW}⚠️  MEDIUM:   $MEDIUM_ISSUES issue(s) - Review required${NC}"
fi
if [[ $LOW_ISSUES -gt 0 ]]; then
  sayc "${BLUE}ℹ️  LOW:      $LOW_ISSUES issue(s) - Nice to fix${NC}"
fi

say ""


# EXIT DECISION LOGIC
# ============================================================

# CRITICAL or HIGH: ALWAYS BLOCK
if [[ $CRITICAL_ISSUES -gt 0 || $HIGH_ISSUES -gt 0 ]]; then
  hr
  sayc "${RED}❌ DEPLOYMENT BLOCKED ❌${NC}"
  hr
  say ""
  say "CRITICAL and HIGH severity issues must be fixed before deployment."
  say ""
  say "Priority actions:"
  [[ $CRITICAL_ISSUES -gt 0 ]] && say "  1. 🚨 Fix $CRITICAL_ISSUES CRITICAL issue(s) immediately"
  [[ $HIGH_ISSUES -gt 0 ]] && say "  2. ⚠️  Fix $HIGH_ISSUES HIGH issue(s) before deploying"
  say ""
  say "Re-run this script after fixing issues."
  say ""
  say "=============================================="
  sayc "${PURPLE}Generated by: 🦛 Published by Oob Skulden™ 🦛${NC}"
  sayc "${PURPLE}\"The threats you don't see coming\"${NC}"
  say "=============================================="
  say ""
  
  if [[ $CRITICAL_ISSUES -gt 0 ]]; then
    exit 3
  else
    exit 2
  fi
fi

# MEDIUM: PROMPT USER (unless non-interactive)
if [[ $MEDIUM_ISSUES -gt 0 ]]; then
  if ! prompt_user "MEDIUM" "$MEDIUM_ISSUES"; then
    say ""
    say "=============================================="
    sayc "${PURPLE}Generated by: 🦛 Published by Oob Skulden™ 🦛${NC}"
    sayc "${PURPLE}\"The threats you don't see coming\"${NC}"
    say "=============================================="
    say ""
    exit 1
  fi
fi

# LOW: PROMPT USER (unless non-interactive)
if [[ $LOW_ISSUES -gt 0 ]]; then
  if ! prompt_user "LOW" "$LOW_ISSUES"; then
    say ""
    say "=============================================="
    sayc "${PURPLE}Generated by: 🦛 Published by Oob Skulden™ 🦛${NC}"
    sayc "${PURPLE}\"The threats you don't see coming\"${NC}"
    say "=============================================="
    say ""
    exit 1
  fi
fi

# NO ISSUES or USER ACCEPTED RISKS
if [[ $TOTAL_ISSUES -eq 0 ]]; then
  sayc "${GREEN}✅ EXCELLENT! No security issues found!${NC}"
  sayc "${GREEN}✅ Safe to deploy${NC}"
else
  sayc "${YELLOW}⚠️  Proceeding with acknowledged risks${NC}"
  say ""
  say "Issues accepted:"
  [[ $MEDIUM_ISSUES -gt 0 ]] && say "  • $MEDIUM_ISSUES MEDIUM issue(s)"
  [[ $LOW_ISSUES -gt 0 ]] && say "  • $LOW_ISSUES LOW issue(s)"
fi

say ""
say "=============================================="
sayc "${PURPLE}Generated by: 🦛 Published by Oob Skulden™ 🦛${NC}"
sayc "${PURPLE}\"The threats you don't see coming\"${NC}"
say "=============================================="
say ""

exit 0
#!/usr/bin/env bash
# ============================================================
# Zimara Script (v0.44.0)
# Pre-push security sweep for static sites & web projects
#
# Supports: Hugo, Jekyll, Astro, Next export, Eleventy, generic
#
# Published by Oob Skulden™
# "The threats you don't see coming"
# 
# BUGFIX in v0.43.1:
# - Fixed line 950 git history syntax error
# - Improved error handling in git log parsing
# ============================================================

set -euo pipefail

# ============================================================
# CORE HELPERS (REQUIRED)
# ============================================================

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

say()  { printf '%s\n' "$*"; }
sayc() { printf '%b\n' "$*"; }

hr() { sayc "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

SHOW_MATCHES="${SHOW_MATCHES:-5}"

CRITICAL_ISSUES=0
HIGH_ISSUES=0
MEDIUM_ISSUES=0
LOW_ISSUES=0

# flags
ONLY_OUTPUT=0
SKIP_OUTPUT=0
INCLUDE_OUTPUT_IN_SOURCE=0
NON_INTERACTIVE=0

# ============================================================
# CLI / USAGE
# ============================================================

usage() {
  cat <<'EOF'
zimara.sh

Usage:
  ./zimara.sh [path] [options]

Options:
  --only-output                 Scan only the output dir (public/dist/out/_site)
  --skip-output                 Skip scanning output dir
  --include-output-in-source     Allow output dir to be git-tracked without warning
  --non-interactive              Skip prompts, fail on CRITICAL/HIGH (for CI/CD)
  --version                      Print version

Env:
  SHOW_MATCHES=5                How many matching lines to show (default 5)
  OUTPUT_DIR=public             Override detected output directory
  SECRET_TOOL=auto|gitleaks|detect-secrets|git-secrets|none

Exit Codes:
  0  - Success (no issues or user accepted risks)
  1  - MEDIUM issues found (user declined to proceed)
  2  - HIGH issues found (blocked or user declined)
  3  - CRITICAL issues found (always blocked)
  99 - Invalid usage/directory not found
EOF
}

VERSION="0.44.0"

if [[ "${1:-}" == "--version" ]]; then
  echo "$VERSION"
  exit 0
fi

SCAN_DIR="${1:-.}"
if [[ "${SCAN_DIR:-}" == "--help" || "${SCAN_DIR:-}" == "-h" ]]; then
  usage
  exit 0
fi

ARGS=("$@")
for arg in "${ARGS[@]}"; do
  case "$arg" in
    --only-output) ONLY_OUTPUT=1 ;;
    --skip-output) SKIP_OUTPUT=1 ;;
    --include-output-in-source) INCLUDE_OUTPUT_IN_SOURCE=1 ;;
    --non-interactive) NON_INTERACTIVE=1 ;;
    --help|-h) usage; exit 0 ;;
    --version) echo "$VERSION"; exit 0 ;;
  esac
done

if [[ ! -d "$SCAN_DIR" ]]; then
  sayc "${RED}✗ Directory not found: $SCAN_DIR${NC}"
  exit 99
fi

cd "$SCAN_DIR"

# ============================================================
# COMMON EXCLUSIONS
# ============================================================

GREP_EXCLUDES=(
  --exclude-dir=.git
  --exclude-dir=node_modules
  --exclude-dir=public
  --exclude-dir=dist
  --exclude-dir=build
  --exclude-dir=vendor
  --exclude-dir=.next
  --exclude-dir=.cache
)

find_prune_args() {
  printf '%s ' \
    -path "./.git" -o \
    -path "./node_modules" -o \
    -path "./public" -o \
    -path "./dist" -o \
    -path "./build" -o \
    -path "./vendor" -o \
    -path "./.next" -o \
    -path "./.cache" \
    -prune
}

_has_cmd() { command -v "$1" >/dev/null 2>&1; }

# ============================================================
# INTERACTIVE PROMPT HELPER
# ============================================================

prompt_user() {
  local severity="$1"
  local count="$2"
  
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    return 1  # Always fail in non-interactive mode
  fi
  
  say ""
  hr
  sayc "${YELLOW}⚠️  SECURITY DECISION REQUIRED ⚠️${NC}"
  hr
  say ""
  sayc "${YELLOW}Found ${count} ${severity} severity issue(s).${NC}"
  say ""
  
  case "$severity" in
    MEDIUM)
      say "These issues should be addressed but are not immediately critical."
      say "They represent potential vulnerabilities or security weaknesses."
      ;;
    LOW)
      say "These are minor security improvements or best practice recommendations."
      say "They represent good security hygiene but low immediate risk."
      ;;
  esac
  
  say ""
  sayc "${YELLOW}Do you want to proceed anyway? [y/N]${NC}"
  read -r -p "> " response
  
  case "$response" in
    [yY]|[yY][eE][sS])
      say ""
      sayc "${YELLOW}⚠️  Proceeding with ${severity} issues acknowledged${NC}"
      say ""
      return 0
      ;;
    *)
      say ""
      sayc "${RED}❌ Deployment blocked by user${NC}"
      say ""
      return 1
      ;;
  esac
}

# ============================================================
# GENERATOR + OUTPUT DETECTION
# ============================================================

GENERATOR="generic"
OUTPUT_DIR_DETECTED=""

if [[ -f "hugo.toml" || -f "hugo.yaml" || -f "hugo.yml" || -f "config.toml" || -f "config.yaml" || -f "config.yml" ]]; then
  GENERATOR="hugo"
  OUTPUT_DIR_DETECTED="public"
elif [[ -f "_config.yml" || -f "_config.yaml" ]]; then
  GENERATOR="jekyll"
  OUTPUT_DIR_DETECTED="_site"
elif [[ -f "astro.config.mjs" || -f "astro.config.js" || -f "astro.config.ts" ]]; then
  GENERATOR="astro"
  OUTPUT_DIR_DETECTED="dist"
elif [[ -f "next.config.js" || -f "next.config.mjs" || -f "next.config.ts" ]]; then
  GENERATOR="next-export"
  OUTPUT_DIR_DETECTED="out"
elif [[ -f ".eleventy.js" || -f "eleventy.config.js" || -f ".eleventy.cjs" ]]; then
  GENERATOR="eleventy"
  OUTPUT_DIR_DETECTED="_site"
fi

OUTPUT_DIR="${OUTPUT_DIR:-$OUTPUT_DIR_DETECTED}"
OUTPUT_BASENAME="$(basename "${OUTPUT_DIR:-}" 2>/dev/null || true)"

# ============================================================
# HEADER
# ============================================================

say ""
sayc "${PURPLE}==============================================${NC}"
sayc "${PURPLE}🔒 Zimara 🔒  (v${VERSION})${NC}"
sayc "${PURPLE}==============================================${NC}"
say ""
say "Directory scanned: $(pwd)"
say "Generator detected: $GENERATOR"
[[ -n "${OUTPUT_DIR:-}" ]] && say "Output dir detected: $OUTPUT_DIR"
[[ "$NON_INTERACTIVE" -eq 1 ]] && say "Mode: Non-interactive (CI/CD)"
say ""

# ============================================================
# CHECK 1: Private Keys (HARD STOP)
# ============================================================

hr
sayc "${PURPLE}CHECK 1: Private Keys (HARD STOP)${NC}"
hr

KEYS=$(find . \( $(find_prune_args) \) -type f \
  \( -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" \) \
  -print 2>/dev/null || true)

if [[ -n "$KEYS" ]]; then
  sayc "${RED}✗ CRITICAL: Private key material found${NC}"
  printf '%s\n' "$KEYS" | sed 's/^/  /'
  say "Actions:"
  say "  • REMOVE immediately"
  say "  • Rotate/revoke keys"
  say "  • Purge git history (git filter-repo/BFG)"
  CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
else
  sayc "${GREEN}✓ No private keys found${NC}"
fi
say ""

# ============================================================
# CHECK 2: Environment / Secrets Files
# ============================================================

hr
sayc "${PURPLE}CHECK 2: Environment / Secrets Files${NC}"
hr

ENV_FILES=$(find . \( $(find_prune_args) \) -type f -name ".env*" -print 2>/dev/null || true)

if [[ -n "$ENV_FILES" ]]; then
  sayc "${RED}✗ Found environment files [CRITICAL]${NC}"
  printf '%s\n' "$ENV_FILES" | sed 's/^/  /'
  say "Actions:"
  say "  • Remove from repo"
  say "  • Add to .gitignore"
  CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
else
  sayc "${GREEN}✓ No .env files found${NC}"
fi
say ""

# ============================================================
# CHECK 3: Hardcoded Credentials
# ============================================================

hr
sayc "${PURPLE}CHECK 3: Hardcoded Credentials${NC}"
hr

CREDS=$(grep -riE "(password|api[_-]?key|secret|token)[[:space:]]*[:=][[:space:]]*['\"][^'\"]{8,}" . \
  "${GREP_EXCLUDES[@]}" 2>/dev/null || true)

if [[ -n "$CREDS" ]]; then
  sayc "${YELLOW}⚠️  Possible hardcoded credentials [HIGH]${NC}"
  printf '%s\n' "$CREDS" | head -"$SHOW_MATCHES" | sed 's/^/  /'
  say "Actions:"
  say "  • Replace with env vars / secret manager references"
  say "  • Rotate exposed values"
  HIGH_ISSUES=$((HIGH_ISSUES + 1))
else
  sayc "${GREEN}✓ No obvious hardcoded credentials${NC}"
fi
say ""

# ============================================================
# DROP-IN: Optional best-in-class secret scanning
# ============================================================

SECRET_TOOL="${SECRET_TOOL:-auto}"
SECRET_BASELINE="${SECRET_BASELINE:-.secrets.baseline}"
GITLEAKS_CONFIG="${GITLEAKS_CONFIG:-.gitleaks.toml}"

run_secret_scanner() {
  local dir="${1:-.}"
  local tool="${SECRET_TOOL,,}"

  if [[ "$tool" == "auto" ]]; then
    if _has_cmd gitleaks; then tool="gitleaks"
    elif _has_cmd detect-secrets; then tool="detect-secrets"
    elif _has_cmd git-secrets; then tool="git-secrets"
    else tool="none"
    fi
  fi

  hr
  sayc "${PURPLE}CHECK X: Enhanced Secret Scanning (optional tools)${NC}"
  hr

  case "$tool" in
    none)
      sayc "${BLUE}ℹ️  No external secret scanner found (gitleaks/detect-secrets/git-secrets).${NC}"
      say "  Using built-in checks only."
      say ""
      return 0
      ;;

    gitleaks)
      sayc "${BLUE}ℹ️  Using gitleaks${NC}"
      local report
      report="$(mktemp -t gitleaks-report.XXXXXX.json 2>/dev/null || mktemp "/tmp/gitleaks-report.XXXXXX.json")"
      local -a args
      args=( detect --source "$dir" --report-format json --report-path "$report" )

      if [[ -f "$dir/$GITLEAKS_CONFIG" ]]; then
        args+=( --config "$dir/$GITLEAKS_CONFIG" )
      elif [[ -f "$GITLEAKS_CONFIG" ]]; then
        args+=( --config "$GITLEAKS_CONFIG" )
      fi

      if gitleaks "${args[@]}" >/dev/null 2>&1; then
        sayc "${GREEN}✓ gitleaks: no secrets found${NC}"
        rm -f "$report" >/dev/null 2>&1 || true
        say ""
        return 0
      else
        if [[ -s "$report" ]]; then
          local count
          count="$(grep -c '"RuleID"' "$report" 2>/dev/null || echo 0)"
          sayc "${RED}✗ gitleaks: found ${count} potential secret(s) [CRITICAL]${NC}"
          say "  Report: $report"
          say "Actions:"
          say "  • Validate findings, then rotate/revoke anything real"
          say "  • Consider adding a .gitleaks.toml to reduce false positives"
          CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
          say ""
          return 1
        else
          sayc "${YELLOW}⚠️  gitleaks: scan failed (no report generated).${NC}"
          say "  Tip: run: gitleaks detect --source \"$dir\" -v"
          rm -f "$report" >/dev/null 2>&1 || true
          say ""
          return 3
        fi
      fi
      ;;

    detect-secrets)
      sayc "${BLUE}ℹ️  Using detect-secrets${NC}"
      if [[ -f "$dir/$SECRET_BASELINE" ]]; then
        say "  Baseline: $dir/$SECRET_BASELINE"
        if detect-secrets audit --baseline "$dir/$SECRET_BASELINE" >/dev/null 2>&1; then
          sayc "${GREEN}✓ detect-secrets: baseline audit clean${NC}"
          say ""
          return 0
        else
          sayc "${RED}✗ detect-secrets: potential secrets found vs baseline [CRITICAL]${NC}"
          say "Actions:"
          say "  • Run: detect-secrets audit --baseline \"$dir/$SECRET_BASELINE\""
          CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
          say ""
          return 1
        fi
      else
        local tmp_baseline
        tmp_baseline="$(mktemp -t secrets-baseline.XXXXXX.json 2>/dev/null || mktemp "/tmp/secrets-baseline.XXXXXX.json")"
        if (cd "$dir" && detect-secrets scan) >"$tmp_baseline" 2>/dev/null; then
          local findings
          findings="$(grep -c '"type":' "$tmp_baseline" 2>/dev/null || echo 0)"
          if [[ "${findings:-0}" -gt 0 ]]; then
            sayc "${YELLOW}⚠️  detect-secrets: findings present (baseline not adopted) [HIGH]${NC}"
            say "  Temp baseline: $tmp_baseline"
            say "Actions:"
            say "  • Review + rotate/revoke if real"
            say "  • Or adopt baseline:"
            say "      mv \"$tmp_baseline\" \"$dir/$SECRET_BASELINE\""
            say "      detect-secrets audit --baseline \"$dir/$SECRET_BASELINE\""
            HIGH_ISSUES=$((HIGH_ISSUES + 1))
            say ""
            return 1
          else
            sayc "${GREEN}✓ detect-secrets: no secrets found${NC}"
            rm -f "$tmp_baseline" >/dev/null 2>&1 || true
            say ""
            return 0
          fi
        else
          sayc "${YELLOW}⚠️  detect-secrets: scan failed.${NC}"
          say "  Tip: run: (cd \"$dir\" && detect-secrets scan)"
          rm -f "$tmp_baseline" >/dev/null 2>&1 || true
          say ""
          return 3
        fi
      fi
      ;;

    git-secrets)
      sayc "${BLUE}ℹ️  Using git-secrets${NC}"
      if [[ ! -d "$dir/.git" ]]; then
        sayc "${YELLOW}⚠️  git-secrets works best in a git repo; skipping.${NC}"
        say ""
        return 2
      fi
      if (cd "$dir" && git secrets --scan) >/dev/null 2>&1; then
        sayc "${GREEN}✓ git-secrets: no matches${NC}"
        say ""
        return 0
      else
        sayc "${RED}✗ git-secrets: potential secrets found [CRITICAL]${NC}"
        say "Actions:"
        say "  • Run: (cd \"$dir\" && git secrets --scan) for details"
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        say ""
        return 1
      fi
      ;;

    *)
      sayc "${YELLOW}⚠️  Unknown SECRET_TOOL='$SECRET_TOOL' — skipping external scanner.${NC}"
      say ""
      return 2
      ;;
  esac
}

run_secret_scanner "."

# ============================================================
# CHECK 4: Sensitive Files in Output Directory
# ============================================================

hr
sayc "${PURPLE}CHECK 4: Sensitive Files in Output Directory${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Output scanning disabled (--skip-output)${NC}"
  say ""
else
  if [[ -n "${OUTPUT_DIR:-}" && -d "${OUTPUT_DIR:-}" ]]; then
    if [[ -d "$OUTPUT_DIR/.git" ]]; then
      sayc "${RED}✗ CRITICAL: .git directory found in output dir!${NC}"
      say "  This can expose your entire git history to the web."
      say "Actions:"
      say "  • Ensure publish folder never includes .git"
      say "  • Confirm host rules prevent serving hidden directories"
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    fi

    OUTPUT_CONFIGS=$(find "$OUTPUT_DIR" -type f \( \
      -name "*.toml" -o -name "*.env" -o -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" \
    \) 2>/dev/null | wc -l | tr -d ' ')

    if [[ ${OUTPUT_CONFIGS:-0} -gt 0 ]]; then
      sayc "${RED}✗ Found $OUTPUT_CONFIGS config/key file(s) in output dir [CRITICAL]${NC}"
      find "$OUTPUT_DIR" -type f \( -name "*.toml" -o -name "*.env" -o -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" \) 2>/dev/null | sed 's/^/  /'
      say "Actions:"
      say "  • Remove sensitive files from output and rebuild"
      say "  • Ensure they live outside publish dir"
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    else
      sayc "${GREEN}✓ No critical files found in output dir${NC}"
    fi

    SOURCEMAPS=$(find "$OUTPUT_DIR" -name "*.map" 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${SOURCEMAPS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $SOURCEMAPS source map file(s) in output dir [MEDIUM]${NC}"
      say "  Source maps can expose original source code and internal paths."
      say "Actions:"
      say "  • Disable sourcemaps for production or restrict access"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  else
    sayc "${YELLOW}⚠️  No output directory found - skipping${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 5: Internal URLs/IPs in Output
# ============================================================

hr
sayc "${PURPLE}CHECK 5: Internal URLs/IPs Exposed${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Output scanning disabled (--skip-output)${NC}"
  say ""
else
  if [[ -n "${OUTPUT_DIR:-}" && -d "${OUTPUT_DIR:-}" ]]; then
    INTERNAL_URLS=$(grep -riE "(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|\.local|\.internal|docker\.sock)" "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${INTERNAL_URLS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $INTERNAL_URLS internal reference(s) [MEDIUM]${NC}"
      grep -riE "(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|\.local|\.internal|docker\.sock)" "$OUTPUT_DIR" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /' || true
      say "Actions:"
      say "  • Verify baseURL / site URL settings for production"
      say "  • Rebuild with production flags"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    else
      sayc "${GREEN}✓ No internal URLs/IPs found in output${NC}"
    fi
  else
    sayc "${YELLOW}⚠️  No output directory found - skipping${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 6: Large Files (>10MB)
# ============================================================

hr
sayc "${PURPLE}CHECK 6: Large Files (>10MB)${NC}"
hr

LARGE_FILE_LIST=$(find . \( $(find_prune_args) \) -type f -size +10M -print 2>/dev/null || true)
if [[ -n "$LARGE_FILE_LIST" ]]; then
  LARGE_FILES=$(printf '%s\n' "$LARGE_FILE_LIST" | wc -l | tr -d ' ')
  sayc "${YELLOW}⚠️  Found $LARGE_FILES file(s) larger than 10MB [MEDIUM]${NC}"
  printf '%s\n' "$LARGE_FILE_LIST" | while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    size=$(du -h "$file" 2>/dev/null | cut -f1 || echo "?")
    say "  $file ($size)"
  done
  say "Actions:"
  say "  • If accidental: remove + clean history if needed"
  say "  • If intentional: Git LFS or CDN/object storage"
  MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
else
  sayc "${GREEN}✓ No files larger than 10MB${NC}"
fi
say ""

# ============================================================
# CHECK 7: Debug/Test Files
# ============================================================

hr
sayc "${PURPLE}CHECK 7: Debug/Test Files${NC}"
hr

DEBUG_FILES=$(find . \( $(find_prune_args) \) -type f \( \
  -name "test.html" -o -name "debug.log" -o -name "*.swp" -o -name "*.swo" -o \
  -name ".DS_Store" -o -name "Thumbs.db" -o -name "phpinfo.php" -o -name "*.sql" \
\) -print 2>/dev/null || true)

if [[ -n "$DEBUG_FILES" ]]; then
  COUNT=$(printf '%s\n' "$DEBUG_FILES" | wc -l | tr -d ' ')
  sayc "${YELLOW}⚠️  Found $COUNT debug/test file(s) [HIGH]${NC}"
  printf '%s\n' "$DEBUG_FILES" | sed 's/^/  /'
  say "Actions:"
  say "  • Remove debug artifacts from repo"
  say "  • Add patterns to .gitignore"
  HIGH_ISSUES=$((HIGH_ISSUES + 1))
else
  sayc "${GREEN}✓ No debug/test files found${NC}"
fi
say ""

# ============================================================
# CHECK 8: Email/Phone in Output
# ============================================================

hr
sayc "${PURPLE}CHECK 8: Email/Phone Scraping Risk${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  EMAIL_COUNT=$(grep -roE "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}" "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)
  PHONE_COUNT=$(grep -roE "\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}" "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)

  if [[ ${EMAIL_COUNT:-0} -gt 0 || ${PHONE_COUNT:-0} -gt 0 ]]; then
    sayc "${BLUE}ℹ️  Contact info present in output:${NC}"
    [[ ${EMAIL_COUNT:-0} -gt 0 ]] && say "  • $EMAIL_COUNT email address(es)"
    [[ ${PHONE_COUNT:-0} -gt 0 ]] && say "  • $PHONE_COUNT phone number(s)"
    say "Actions:"
    say "  • If intentional: consider obfuscation or a contact form"
    say "  • If unintentional: remove and rebuild"
    LOW_ISSUES=$((LOW_ISSUES + 1))
  else
    sayc "${GREEN}✓ No email/phone numbers in output${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 9: Mixed Content
# ============================================================

hr
sayc "${PURPLE}CHECK 9: Mixed Content (HTTP/HTTPS)${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  HTTP_REFS=$(grep -roE "http://[^\"' ]+" "$OUTPUT_DIR" 2>/dev/null | grep -v "http://www.w3.org" | wc -l | tr -d ' ' || true)
  PROTO_RELATIVE=$(grep -roE "//[^\"' ]+\.(js|css|png|jpg|gif|svg|webp|woff|woff2)" "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)

  if [[ ${HTTP_REFS:-0} -gt 0 ]]; then
    sayc "${YELLOW}⚠️  Found $HTTP_REFS http:// references [MEDIUM]${NC}"
    grep -roE "http://[^\"' ]+" "$OUTPUT_DIR" 2>/dev/null | grep -v "http://www.w3.org" | head -"$SHOW_MATCHES" | sed 's/^/  /' || true
    say "Actions:"
    say "  • Switch assets to https:// URLs"
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
  fi

  if [[ ${PROTO_RELATIVE:-0} -gt 0 ]]; then
    sayc "${BLUE}ℹ️  Found $PROTO_RELATIVE protocol-relative URLs (//...) [LOW]${NC}"
    say "Actions:"
    say "  • Prefer explicit https://"
    LOW_ISSUES=$((LOW_ISSUES + 1))
  fi

  if [[ ${HTTP_REFS:-0} -eq 0 && ${PROTO_RELATIVE:-0} -eq 0 ]]; then
    sayc "${GREEN}✓ No mixed content indicators found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 10: Default/Demo Content
# ============================================================

hr
sayc "${PURPLE}CHECK 10: Default/Demo Content${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  DEMO_REFS=$(grep -rIEn \
    --include="*.html" --include="*.htm" --include="*.xml" --include="*.json" --include="*.txt" \
    "(example\.com|Your Name Here|Lorem ipsum|Demo Site|Test Site)" \
    "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)

  if [[ ${DEMO_REFS:-0} -gt 0 ]]; then
    sayc "${YELLOW}⚠️  Found $DEMO_REFS placeholder reference(s) [LOW]${NC}"
    grep -rIEn \
      --include="*.html" --include="*.htm" --include="*.xml" --include="*.json" --include="*.txt" \
      "(example\.com|Your Name Here|Lorem ipsum|Demo Site|Test Site)" \
      "$OUTPUT_DIR" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /' || true
    say "Actions:"
    say "  • Replace placeholder content"
    LOW_ISSUES=$((LOW_ISSUES + 1))
  else
    sayc "${GREEN}✓ No obvious demo content found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 11: .gitignore Coverage
# ============================================================

hr
sayc "${PURPLE}CHECK 11: .gitignore Configuration${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -f ".gitignore" ]]; then
    REQUIRED_PATTERNS=(
      "*.bak"
      "*.backup*"
      ".env"
      "*.key"
      "*.pem"
      "*.log"
      ".DS_Store"
    )

    MISSING_PATTERNS=()
    for pattern in "${REQUIRED_PATTERNS[@]}"; do
      if ! grep -qF "$pattern" ".gitignore" 2>/dev/null; then
        MISSING_PATTERNS+=("$pattern")
      fi
    done

    if [[ ${#MISSING_PATTERNS[@]} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Missing recommended .gitignore patterns [LOW]${NC}"
      printf '  %s\n' "${MISSING_PATTERNS[@]}"
      say "Actions:"
      say "  • Add missing patterns"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    else
      sayc "${GREEN}✓ .gitignore has good coverage${NC}"
    fi
  else
    sayc "${RED}✗ No .gitignore file found [MEDIUM]${NC}"
    say "Actions:"
    say "  • Create a .gitignore for secrets, build output, caches, OS files"
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
  fi
  say ""
fi

# ============================================================
# CHECK 12: Hardcoded Credentials in Common Code Dirs
# ============================================================

hr
sayc "${PURPLE}CHECK 12: Hardcoded Credentials in Code Dirs${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  HARDCODED_FOUND=0
  CODE_DIRS=("content" "layouts" "themes" "static" "src" "app" "lib" "pages")

  for d in "${CODE_DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    MATCHES=$(grep -riE "(password|api[_-]?key|secret|token)[[:space:]]*[:=][[:space:]]*['\"][^'\"]{8,}" "$d" \
      "${GREP_EXCLUDES[@]}" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${MATCHES:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $MATCHES potential credential(s) in $d/ [HIGH]${NC}"
      grep -riE "(password|api[_-]?key|secret|token)[[:space:]]*[:=][[:space:]]*['\"][^'\"]{8,}" "$d" \
        "${GREP_EXCLUDES[@]}" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /' || true
      HARDCODED_FOUND=$((HARDCODED_FOUND + MATCHES))
    fi
  done

  if [[ $HARDCODED_FOUND -gt 0 ]]; then
    say "Actions:"
    say "  • Replace hardcoded secrets with env vars"
    say "  • Rotate exposed values"
    HIGH_ISSUES=$((HIGH_ISSUES + 1))
  else
    sayc "${GREEN}✓ No obvious hardcoded secrets in common code dirs${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 13: Sensitive HTML Comments
# ============================================================

hr
sayc "${PURPLE}CHECK 13: Sensitive HTML Comments${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  DEV_COMMENTS=$(grep -rIEn --include="*.html" --include="*.htm" \
    "<!--.*\b(TODO|DEBUG|FIXME|XXX|HACK|password|token|key)\b" \
    "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)

  if [[ ${DEV_COMMENTS:-0} -gt 0 ]]; then
    sayc "${YELLOW}⚠️  Found $DEV_COMMENTS development comment(s) in output HTML [LOW]${NC}"
    grep -rIEn --include="*.html" --include="*.htm" \
      "<!--.*\b(TODO|DEBUG|FIXME|XXX|HACK|password|token|key)\b" \
      "$OUTPUT_DIR" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /' || true
    say "Actions:"
    say "  • Remove sensitive comments before publishing"
    LOW_ISSUES=$((LOW_ISSUES + 1))
  else
    sayc "${GREEN}✓ No sensitive comments in output HTML${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 14: Security Headers in netlify.toml
# ============================================================

hr
sayc "${PURPLE}CHECK 14: Security Headers in netlify.toml${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -f "netlify.toml" ]]; then
    SECURITY_HEADERS=("X-Frame-Options" "X-Content-Type-Options" "Content-Security-Policy" "Strict-Transport-Security" "Permissions-Policy" "Referrer-Policy")
    MISSING_HEADERS=()
    for header in "${SECURITY_HEADERS[@]}"; do
      if ! grep -qi "$header" "netlify.toml"; then
        MISSING_HEADERS+=("$header")
      fi
    done

    if [[ ${#MISSING_HEADERS[@]} -gt 0 ]]; then
      sayc "${BLUE}ℹ️  Missing recommended headers in netlify.toml [LOW]${NC}"
      printf '  %s\n' "${MISSING_HEADERS[@]}"
      say "Actions:"
      say "  • Add common security headers"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    else
      sayc "${GREEN}✓ netlify.toml appears to include common security headers${NC}"
    fi
  else
    sayc "${BLUE}ℹ️  No netlify.toml found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 15: Metadata/Identity Leaks
# ============================================================

hr
sayc "${PURPLE}CHECK 15: Metadata/Identity Leaks${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  IDENTITY_REFS=0

  if [[ -d ".git" ]]; then
    GIT_USER=$(git config user.name 2>/dev/null || echo "")
    GIT_EMAIL=$(git config user.email 2>/dev/null || echo "")

    if [[ -n "$GIT_USER" && "${GIT_USER,,}" != "oob" && "${GIT_USER,,}" != "oob skulden" ]]; then
      sayc "${BLUE}ℹ️  Git config name: $GIT_USER${NC}"
      say "Actions:"
      say "  • Consider per-repo identity:"
      say "      git config user.name \"Oob Skulden\""
      IDENTITY_REFS=$((IDENTITY_REFS + 1))
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi

    if [[ -n "$GIT_EMAIL" && "$GIT_EMAIL" != *"noreply"* ]]; then
      sayc "${BLUE}ℹ️  Git config email: $GIT_EMAIL${NC}"
      say "Actions:"
      say "  • Use GitHub noreply email for public repos"
      IDENTITY_REFS=$((IDENTITY_REFS + 1))
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
  fi

  if [[ -d "content" ]]; then
    DRAFT_MARKERS=$(grep -riE "\[TODO\]|\[DRAFT\]|\[PLACEHOLDER\]" "content" "${GREP_EXCLUDES[@]}" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${DRAFT_MARKERS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $DRAFT_MARKERS draft marker(s) in content [LOW]${NC}"
      say "Actions:"
      say "  • Ensure drafts/placeholders aren't published"
      LOW_ISSUES=$((LOW_ISSUES + 1))
      IDENTITY_REFS=$((IDENTITY_REFS + 1))
    fi
  fi

  if [[ $IDENTITY_REFS -eq 0 ]]; then
    sayc "${GREEN}✓ No obvious identity leaks detected${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 16: Dependency Vulnerabilities (npm audit)
# ============================================================

hr
sayc "${PURPLE}CHECK 16: Dependency Vulnerabilities (npm audit)${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -f "package.json" ]]; then
    sayc "${BLUE}ℹ️  package.json found${NC}"
    if _has_cmd npm; then
      say "  Running npm audit (may take a moment)..."
      AUDIT_OUTPUT=$((npm audit --json 2>/dev/null) || echo '{"error": true}')
      if printf '%s' "$AUDIT_OUTPUT" | grep -q '"error"'; then
        sayc "${YELLOW}⚠️  npm audit had issues (deps may not be installed) [LOW]${NC}"
        say "Actions:"
        say "  • Run: npm ci then re-run audit"
        LOW_ISSUES=$((LOW_ISSUES + 1))
      else
        VULNS=$(printf '%s' "$AUDIT_OUTPUT" | grep -o '"total":[0-9]*' | head -1 | cut -d: -f2 || echo "0")
        if [[ ${VULNS:-0} -gt 0 ]]; then
          sayc "${YELLOW}⚠️  Found $VULNS vulnerability/vulnerabilities [MEDIUM]${NC}"
          say "Actions:"
          say "  • Upgrade dependencies / lockfile hygiene"
          MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
        else
          sayc "${GREEN}✓ No vulnerabilities reported by npm audit${NC}"
        fi
      fi
    else
      sayc "${BLUE}ℹ️  npm not installed — skipping${NC}"
    fi
  else
    sayc "${GREEN}✓ No package.json found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 17: Git History Analysis (FIXED)
# ============================================================

hr
sayc "${PURPLE}CHECK 17: Git History Analysis${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -d ".git" ]] && _has_cmd git; then
    # FIX: Properly capture and count sensitive files in history
    SENSITIVE_HISTORY=0
    if git log --all --oneline --name-only 2>/dev/null | grep -qE '\.(env|key|pem|p12|pfx|backup|bak)$'; then
      SENSITIVE_HISTORY=$(git log --all --oneline --name-only 2>/dev/null \
        | grep -E '\.(env|key|pem|p12|pfx|backup|bak)$' \
        | sort -u \
        | wc -l | tr -d ' ')
    fi

    if [[ ${SENSITIVE_HISTORY:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $SENSITIVE_HISTORY sensitive-file reference(s) in git history [MEDIUM]${NC}"
      say "Actions:"
      say "  • Secrets may remain in history even if deleted"
      say "  • Use git filter-repo (preferred) or BFG"
      say "  • Rotate secrets anyway"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    else
      sayc "${GREEN}✓ No obvious sensitive extensions in git history${NC}"
    fi
  else
    sayc "${BLUE}ℹ️  Not a git repository — skipping${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 18: Module/Theme Supply Chain
# ============================================================

hr
sayc "${PURPLE}CHECK 18: Module/Theme Supply Chain${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -f "go.mod" ]]; then
    sayc "${BLUE}ℹ️  go.mod found (Hugo modules possible)${NC}"
    NON_OFFICIAL=$(
      grep -E "github\.com/[^/]+/[^/]+" "go.mod" 2>/dev/null \
        | grep -vi "gohugoio" \
        | wc -l | tr -d ' ' \
        || echo 0
    )

    if [[ "${NON_OFFICIAL:-0}" -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $NON_OFFICIAL third-party module(s) [MEDIUM]${NC}"
      grep -E "github\.com/[^/]+/[^/]+" "go.mod" 2>/dev/null \
        | grep -vi "gohugoio" \
        | head -"$SHOW_MATCHES" \
        | sed 's/^/  /'
      say "Actions:"
      say "  • Pin versions; review upstream repos"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    else
      sayc "${GREEN}✓ No obvious third-party modules in go.mod${NC}"
    fi
    say ""
  fi

  if [[ -d "themes" ]]; then
    if ! compgen -G "themes/*" >/dev/null 2>&1; then
      sayc "${GREEN}✓ No themes detected${NC}"
      say ""
    else
      THEME_COUNT=$(find "themes" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ' || echo 0)
      sayc "${BLUE}ℹ️  Found ${THEME_COUNT:-0} theme(s)${NC}"

      for theme_dir in themes/*; do
        [[ -d "$theme_dir" ]] || continue
        theme_name=$(basename "$theme_dir")

        if [[ -d "$theme_dir/.git" ]] && _has_cmd git; then
          REMOTE=$(cd "$theme_dir" && git remote get-url origin 2>/dev/null || echo "unknown")
          sayc "  ${GREEN}✓${NC} $theme_name: git-tracked ($REMOTE)"

          LICENSE_FILE=""
          [[ -f "$theme_dir/LICENSE" ]] && LICENSE_FILE="$theme_dir/LICENSE"
          [[ -f "$theme_dir/LICENSE.md" ]] && LICENSE_FILE="$theme_dir/LICENSE.md"

          if [[ -n "$LICENSE_FILE" ]]; then
            LICENSE_TYPE=$(grep -iE "(MIT|Apache|GPL|BSD)" "$LICENSE_FILE" 2>/dev/null | head -1 || echo "Unknown")
            if printf '%s' "$LICENSE_TYPE" | grep -qi "GPL"; then
              sayc "    ${YELLOW}⚠️${NC} GPL-ish license detected [LOW]"
              LOW_ISSUES=$((LOW_ISSUES + 1))
            else
              sayc "    ${GREEN}✓${NC} License hint: $LICENSE_TYPE"
            fi
          else
            sayc "    ${YELLOW}⚠️${NC} No LICENSE file found [LOW]"
            LOW_ISSUES=$((LOW_ISSUES + 1))
          fi
        else
          sayc "  ${YELLOW}⚠️${NC} $theme_name: copied theme (no version tracking) [MEDIUM]"
          say "    Actions: prefer submodule or Hugo module tracking"
          MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
        fi
      done
      say ""
    fi
  else
    sayc "${GREEN}✓ No themes directory found${NC}"
    say ""
  fi
fi

# ============================================================
# CHECK 19: Custom Shortcode Security (Hugo)
# ============================================================

hr
sayc "${PURPLE}CHECK 19: Custom Shortcode Injection Risks${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -d "layouts/shortcodes" ]]; then
    SHORTCODE_COUNT=$(find "layouts/shortcodes" -name "*.html" 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${SHORTCODE_COUNT:-0} -gt 0 ]]; then
      sayc "${BLUE}ℹ️  Found $SHORTCODE_COUNT custom shortcode(s)${NC}"
      UNSAFE=$(grep -rE "(\.Get|\.Inner|readFile|getJSON|getCSV)" "layouts/shortcodes" --include="*.html" 2>/dev/null | wc -l | tr -d ' ' || true)
      if [[ ${UNSAFE:-0} -gt 0 ]]; then
        sayc "${YELLOW}⚠️  Found $UNSAFE dynamic shortcode usage(s) [MEDIUM]${NC}"
        grep -rE "(\.Get|\.Inner|readFile|getJSON|getCSV)" "layouts/shortcodes" --include="*.html" -n 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
        say "Actions:"
        say "  • Avoid rendering untrusted input directly"
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
      else
        sayc "${GREEN}✓ Shortcodes appear safe${NC}"
      fi
    else
      sayc "${GREEN}✓ No shortcodes found${NC}"
    fi
  else
    sayc "${GREEN}✓ No custom shortcodes directory found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 20: Netlify Build Logs / Env Leaks
# ============================================================

hr
sayc "${PURPLE}CHECK 20: Netlify Build Env Exposure${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -f "netlify.toml" ]]; then
    ECHO_COMMANDS=$(grep -E "(echo|print|console\.log).*\\\$" "netlify.toml" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${ECHO_COMMANDS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Build commands may leak env vars [HIGH]${NC}"
      grep -E "(echo|print|console\.log).*\\\$" "netlify.toml" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      say "Actions:"
      say "  • Remove echo/print of env vars in build steps"
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    else
      sayc "${GREEN}✓ No obvious env-var echoing in netlify.toml${NC}"
    fi

    if ! grep -qiE 'publish[[:space:]]*=' "netlify.toml"; then
      sayc "${YELLOW}⚠️  Publish dir not explicitly set [LOW]${NC}"
      say "Actions:"
      say "  • Set publish directory explicitly"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
  else
    sayc "${GREEN}✓ No netlify.toml found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 21: RSS/Sitemap Unintended Disclosure
# ============================================================

hr
sayc "${PURPLE}CHECK 21: RSS/Sitemap Information Leaks${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  RSS_SITEMAP_ISSUES=0

  if [[ -f "$OUTPUT_DIR/index.xml" ]]; then
    DRAFT_IN_RSS=$(grep -i "draft" "$OUTPUT_DIR/index.xml" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${DRAFT_IN_RSS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  RSS feed may include draft markers [HIGH]${NC}"
      say "Actions:"
      say "  • Ensure drafts excluded in prod builds"
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
      RSS_SITEMAP_ISSUES=$((RSS_SITEMAP_ISSUES + 1))
    fi
  fi

  if [[ -f "$OUTPUT_DIR/sitemap.xml" ]]; then
    SENSITIVE_PATHS=$(grep -E "(admin|private|internal|test|staging)" "$OUTPUT_DIR/sitemap.xml" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${SENSITIVE_PATHS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Sitemap includes sensitive-looking paths [MEDIUM]${NC}"
      grep -E "(admin|private|internal|test|staging)" "$OUTPUT_DIR/sitemap.xml" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      say "Actions:"
      say "  • Remove sensitive paths from sitemap"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
      RSS_SITEMAP_ISSUES=$((RSS_SITEMAP_ISSUES + 1))
    fi
  fi

  if [[ $RSS_SITEMAP_ISSUES -eq 0 ]]; then
    sayc "${GREEN}✓ RSS and sitemap look clean${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 22: Front Matter Secrets
# ============================================================

hr
sayc "${PURPLE}CHECK 22: Front Matter Secrets${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -d "content" ]]; then
    FRONTMATTER_SECRETS=$(grep -rE "^(api_key|apikey|token|secret|password):[[:space:]]*['\"]?[A-Za-z0-9._-]{20,}" "content" --include="*.md" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${FRONTMATTER_SECRETS:-0} -gt 0 ]]; then
      sayc "${RED}✗ Found $FRONTMATTER_SECRETS potential secret(s) in front matter [CRITICAL]${NC}"
      grep -rE "^(api_key|apikey|token|secret|password):" "content" --include="*.md" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      say "Actions:"
      say "  • Remove secret values from front matter"
      say "  • Rotate tokens/keys"
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    else
      sayc "${GREEN}✓ No obvious secrets in content front matter${NC}"
    fi
  else
    sayc "${BLUE}ℹ️  No content/ directory found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 23: Git Hooks / Pre-commit Validation
# ============================================================

hr
sayc "${PURPLE}CHECK 23: Pre-commit Hooks / Validation${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  if [[ -d ".git/hooks" ]]; then
    HAS_ANY=0
    if [[ -f ".git/hooks/pre-commit" ]]; then
      HAS_ANY=1
      sayc "${GREEN}✓ .git/hooks/pre-commit exists${NC}"
      if grep -qiE "(secret|credential|key|token|trufflehog|gitleaks|detect-secrets)" ".git/hooks/pre-commit" 2>/dev/null; then
        sayc "${GREEN}✓ Pre-commit includes security keywords${NC}"
      else
        sayc "${YELLOW}⚠️  Pre-commit exists but no secret scanning detected [LOW]${NC}"
        LOW_ISSUES=$((LOW_ISSUES + 1))
      fi
    fi

    if [[ -f ".pre-commit-config.yaml" ]]; then
      HAS_ANY=1
      sayc "${GREEN}✓ .pre-commit-config.yaml found${NC}"
      if grep -qiE "(trufflehog|gitleaks|detect-secrets|secret)" ".pre-commit-config.yaml" 2>/dev/null; then
        sayc "${GREEN}✓ Pre-commit config includes security hooks${NC}"
      else
        sayc "${YELLOW}⚠️  Pre-commit config missing secrets hooks [LOW]${NC}"
        LOW_ISSUES=$((LOW_ISSUES + 1))
      fi
    fi

    if [[ $HAS_ANY -eq 0 ]]; then
      sayc "${YELLOW}⚠️  No pre-commit hooks configured [MEDIUM]${NC}"
      say "Actions:"
      say "  • Add pre-commit with at least secrets scanning + lint"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  else
    sayc "${BLUE}ℹ️  No .git/hooks directory found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 24: Output directory committed (hygiene)
# ============================================================

hr
sayc "${PURPLE}CHECK 24: Output Directory Committed (Build Artifact Hygiene)${NC}"
hr

if [[ -d ".git" && -n "${OUTPUT_DIR:-}" && -d "${OUTPUT_DIR:-}" && "$ONLY_OUTPUT" -eq 0 ]]; then
  if [[ "$INCLUDE_OUTPUT_IN_SOURCE" -eq 0 ]]; then
    if _has_cmd git; then
      OUTPUT_TRACKED_COUNT=$(git ls-files "$OUTPUT_BASENAME" 2>/dev/null | wc -l | tr -d ' ' || true)
      if [[ ${OUTPUT_TRACKED_COUNT:-0} -gt 0 ]]; then
        sayc "${YELLOW}⚠️  Output dir '$OUTPUT_BASENAME/' appears tracked by git [HIGH]${NC}"
        say "Actions:"
        say "  • Usually do NOT commit build output for Netlify builds"
        say "  • Remove tracked output:"
        say "      git rm -r --cached \"$OUTPUT_BASENAME\""
        say "      echo \"$OUTPUT_BASENAME/\" >> .gitignore"
        HIGH_ISSUES=$((HIGH_ISSUES + 1))
      else
        sayc "${GREEN}✓ Output dir '$OUTPUT_BASENAME/' is not tracked by git${NC}"
      fi
    else
      sayc "${BLUE}ℹ️  git not installed — cannot check tracked output${NC}"
    fi
  else
    sayc "${BLUE}ℹ️  Output tracking allowed (--include-output-in-source)${NC}"
  fi
else
  sayc "${BLUE}ℹ️  Not applicable (no git repo or no output dir detected)${NC}"
fi
say ""

# ============================================================
# CHECK 25: CI/CD Secret Leakage Patterns
# ============================================================

hr
sayc "${PURPLE}CHECK 25: CI/CD Secret Leakage Patterns${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  CI_CD_ISSUES=0
  
  # GitHub Actions
  if [[ -d ".github/workflows" ]]; then
    sayc "${BLUE}ℹ️  GitHub Actions detected${NC}"
    
    # Check for secrets in echo/print commands
    SECRET_ECHO=$(grep -rE "(echo|print).*\\\$\{\{.*secrets\." ".github/workflows" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${SECRET_ECHO:-0} -gt 0 ]]; then
      sayc "${RED}✗ CRITICAL: Secrets echoed in GitHub Actions [CRITICAL]${NC}"
      grep -rE "(echo|print).*\\\$\{\{.*secrets\." ".github/workflows" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      say "  GitHub Actions logs are PUBLIC for public repos!"
      CI_CD_ISSUES=$((CI_CD_ISSUES + 1))
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    fi
    
    # Check for hardcoded tokens in workflow files
    HARDCODED_TOKENS=$(grep -rE "(github_token|GITHUB_TOKEN|GH_TOKEN):[[:space:]]*['\"][a-zA-Z0-9_-]{20,}" ".github/workflows" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${HARDCODED_TOKENS:-0} -gt 0 ]]; then
      sayc "${RED}✗ Found hardcoded tokens in workflow files [CRITICAL]${NC}"
      grep -rE "(github_token|GITHUB_TOKEN|GH_TOKEN):[[:space:]]*['\"][a-zA-Z0-9_-]{20,}" ".github/workflows" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      CI_CD_ISSUES=$((CI_CD_ISSUES + 1))
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    fi
    
    # Check for AWS keys patterns
    AWS_KEYS=$(grep -rE "(AWS_ACCESS_KEY|AWS_SECRET|AKIA[0-9A-Z]{16})" ".github/workflows" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${AWS_KEYS:-0} -gt 0 ]]; then
      sayc "${RED}✗ AWS credentials pattern detected [CRITICAL]${NC}"
      grep -rE "(AWS_ACCESS_KEY|AWS_SECRET|AKIA[0-9A-Z]{16})" ".github/workflows" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      CI_CD_ISSUES=$((CI_CD_ISSUES + 1))
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    fi
    
    # Check for base64-encoded secrets (common obfuscation attempt)
    BASE64_SECRETS=$(grep -rE "echo.*base64|base64.*secrets\." ".github/workflows" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${BASE64_SECRETS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Base64 encoding used with secrets [HIGH]${NC}"
      say "  Base64 is encoding, not encryption - still visible in logs!"
      grep -rE "echo.*base64|base64.*secrets\." ".github/workflows" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      CI_CD_ISSUES=$((CI_CD_ISSUES + 1))
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    fi
  fi
  
  # GitLab CI
  if [[ -f ".gitlab-ci.yml" ]]; then
    sayc "${BLUE}ℹ️  GitLab CI detected${NC}"
    
    SECRET_ECHO=$(grep -E "(echo|print).*\\\$" ".gitlab-ci.yml" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${SECRET_ECHO:-0} -gt 0 ]]; then
      sayc "${RED}✗ Variables echoed in GitLab CI [HIGH]${NC}"
      grep -E "(echo|print).*\\\$" ".gitlab-ci.yml" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      CI_CD_ISSUES=$((CI_CD_ISSUES + 1))
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    fi
    
    # Check for hardcoded values in variables section
    HARDCODED_VARS=$(grep -A5 "^variables:" ".gitlab-ci.yml" 2>/dev/null | grep -E ":[[:space:]]*['\"][^'\"]{20,}" | wc -l | tr -d ' ' || true)
    if [[ ${HARDCODED_VARS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Hardcoded values in variables section [MEDIUM]${NC}"
      say "  Use GitLab CI/CD variables for secrets, not .gitlab-ci.yml"
      CI_CD_ISSUES=$((CI_CD_ISSUES + 1))
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  fi
  
  # CircleCI
  if [[ -f ".circleci/config.yml" ]]; then
    sayc "${BLUE}ℹ️  CircleCI detected${NC}"
    
    SECRET_ECHO=$(grep -rE "(echo|print).*\\\$" ".circleci/" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${SECRET_ECHO:-0} -gt 0 ]]; then
      sayc "${RED}✗ Variables echoed in CircleCI config [HIGH]${NC}"
      grep -rE "(echo|print).*\\\$" ".circleci/" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      CI_CD_ISSUES=$((CI_CD_ISSUES + 1))
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    fi
  fi
  
  if [[ $CI_CD_ISSUES -gt 0 ]]; then
    say ""
    say "Actions:"
    say "  • NEVER echo/print secrets in CI/CD logs"
    say "  • Use masked/protected variables in CI/CD settings"
    say "  • Review public build logs for exposed secrets"
    say "  • Rotate any exposed credentials immediately"
    say "  • Use tools like: git-secrets, talisman, or detect-secrets in pre-commit"
  else
    sayc "${GREEN}✓ No obvious CI/CD secret leakage patterns${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 26: Serverless Function Exposure
# ============================================================

hr
sayc "${PURPLE}CHECK 26: Serverless Function Exposure${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  SERVERLESS_ISSUES=0
  
  # Netlify Functions
  FUNCTION_DIRS=("netlify/functions" ".netlify/functions" "functions")
  
  for func_dir in "${FUNCTION_DIRS[@]}"; do
    if [[ -d "$func_dir" ]]; then
      sayc "${BLUE}ℹ️  Serverless functions found: $func_dir/${NC}"
      
      # Check for CORS wildcard (*)
      CORS_WILDCARD=$(grep -rE "Access-Control-Allow-Origin.*\*" "$func_dir" 2>/dev/null | wc -l | tr -d ' ' || true)
      if [[ ${CORS_WILDCARD:-0} -gt 0 ]]; then
        sayc "${YELLOW}⚠️  CORS wildcard (*) found in functions [HIGH]${NC}"
        grep -rE "Access-Control-Allow-Origin.*\*" "$func_dir" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
        say "  Allows any domain to call your function"
        SERVERLESS_ISSUES=$((SERVERLESS_ISSUES + 1))
        HIGH_ISSUES=$((HIGH_ISSUES + 1))
      fi
      
      # Check for missing rate limiting
      HAS_RATE_LIMIT=$(grep -rE "(rateLimit|rate-limit|throttle)" "$func_dir" 2>/dev/null | wc -l | tr -d ' ' || true)
      FUNCTION_COUNT=$(find "$func_dir" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.go" -o -name "*.py" \) 2>/dev/null | wc -l | tr -d ' ')
      
      if [[ ${HAS_RATE_LIMIT:-0} -eq 0 && ${FUNCTION_COUNT:-0} -gt 0 ]]; then
        sayc "${YELLOW}⚠️  No rate limiting detected in functions [MEDIUM]${NC}"
        say "  Functions are publicly accessible and can be abused"
        SERVERLESS_ISSUES=$((SERVERLESS_ISSUES + 1))
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
      fi
      
      # Check for environment variables used without validation
      ENV_USAGE=$(grep -rE "process\.env\.|os\.getenv|os\.environ" "$func_dir" 2>/dev/null | wc -l | tr -d ' ' || true)
      ENV_VALIDATION=$(grep -rE "(validate|check|assert|throw.*undefined)" "$func_dir" 2>/dev/null | wc -l | tr -d ' ' || true)
      
      if [[ ${ENV_USAGE:-0} -gt 0 && ${ENV_VALIDATION:-0} -eq 0 ]]; then
        sayc "${YELLOW}⚠️  Environment variables used without validation [MEDIUM]${NC}"
        say "  Missing env vars can cause runtime errors or unexpected behavior"
        SERVERLESS_ISSUES=$((SERVERLESS_ISSUES + 1))
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
      fi
      
      # Check for external API calls without input sanitization
      EXTERNAL_CALLS=$(grep -rE "(fetch\(|axios\.|http\.|https\.)" "$func_dir" 2>/dev/null | wc -l | tr -d ' ' || true)
      INPUT_SANITIZE=$(grep -rE "(sanitize|escape|validate|xss)" "$func_dir" 2>/dev/null | wc -l | tr -d ' ' || true)
      
      if [[ ${EXTERNAL_CALLS:-0} -gt 0 && ${INPUT_SANITIZE:-0} -eq 0 ]]; then
        sayc "${YELLOW}⚠️  External API calls without obvious input validation [MEDIUM]${NC}"
        say "  User input to external APIs = potential SSRF/injection"
        grep -rE "(fetch\(|axios\.|http\.|https\.)" "$func_dir" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
        SERVERLESS_ISSUES=$((SERVERLESS_ISSUES + 1))
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
      fi
      
      # Check for SQL queries (potential injection)
      SQL_QUERIES=$(grep -rE "(SELECT|INSERT|UPDATE|DELETE).*FROM" "$func_dir" 2>/dev/null | wc -l | tr -d ' ' || true)
      if [[ ${SQL_QUERIES:-0} -gt 0 ]]; then
        sayc "${RED}✗ SQL queries detected in functions [HIGH]${NC}"
        say "  Ensure parameterized queries are used (not string concatenation)"
        grep -rE "(SELECT|INSERT|UPDATE|DELETE).*FROM" "$func_dir" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
        SERVERLESS_ISSUES=$((SERVERLESS_ISSUES + 1))
        HIGH_ISSUES=$((HIGH_ISSUES + 1))
      fi
      
      # Check for hardcoded credentials in functions
      FUNCTION_CREDS=$(grep -rE "(password|api[_-]?key|secret|token)[[:space:]]*[:=][[:space:]]*['\"][^'\"]{8,}" "$func_dir" 2>/dev/null | wc -l | tr -d ' ' || true)
      if [[ ${FUNCTION_CREDS:-0} -gt 0 ]]; then
        sayc "${RED}✗ CRITICAL: Hardcoded credentials in serverless functions [CRITICAL]${NC}"
        grep -rE "(password|api[_-]?key|secret|token)[[:space:]]*[:=][[:space:]]*['\"][^'\"]{8,}" "$func_dir" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
        SERVERLESS_ISSUES=$((SERVERLESS_ISSUES + 1))
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
      fi
    fi
  done
  
  if [[ $SERVERLESS_ISSUES -gt 0 ]]; then
    say ""
    say "Actions:"
    say "  • Implement rate limiting (e.g., @netlify/functions + rate-limit library)"
    say "  • Use CORS allowlist instead of wildcard (*)"
    say "  • Validate all environment variables at function startup"
    say "  • Sanitize user inputs before external API calls"
    say "  • Use parameterized queries for databases"
    say "  • Store secrets in Netlify environment variables, not code"
    say "  • Consider function authentication (Netlify Identity, JWT)"
  elif compgen -G "netlify/functions/*" >/dev/null 2>&1 || compgen -G ".netlify/functions/*" >/dev/null 2>&1 || compgen -G "functions/*" >/dev/null 2>&1; then
    sayc "${GREEN}✓ Serverless functions present with no obvious issues${NC}"
  else
    sayc "${GREEN}✓ No serverless functions found${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 27: Third-Party Script Integrity (SRI)
# ============================================================

hr
sayc "${PURPLE}CHECK 27: Third-Party Script Integrity (SRI)${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  # Find all external script tags
  EXTERNAL_SCRIPTS=$(grep -roh '<script[^>]*src="https\?://[^"]*"[^>]*>' "$OUTPUT_DIR" --include="*.html" 2>/dev/null | sort -u || true)
  
  if [[ -n "$EXTERNAL_SCRIPTS" ]]; then
    TOTAL_EXTERNAL=$(printf '%s\n' "$EXTERNAL_SCRIPTS" | wc -l | tr -d ' ')
    
    # Count scripts WITHOUT integrity attribute
    NO_SRI=$(printf '%s\n' "$EXTERNAL_SCRIPTS" | grep -v "integrity=" | wc -l | tr -d ' ' || true)
    
    if [[ ${NO_SRI:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found ${NO_SRI}/${TOTAL_EXTERNAL} external scripts without SRI [MEDIUM]${NC}"
      
      # Show examples without SRI
      printf '%s\n' "$EXTERNAL_SCRIPTS" | grep -v "integrity=" | head -5 | sed 's/^/  /'
      
      say ""
      say "Third-party scripts without SRI are supply-chain risks:"
      
      # Identify common CDNs
      GOOGLE_CDN=$(printf '%s\n' "$EXTERNAL_SCRIPTS" | grep -c "googleapis.com\|gstatic.com" || true)
      CLOUDFLARE_CDN=$(printf '%s\n' "$EXTERNAL_SCRIPTS" | grep -c "cdnjs.cloudflare.com" || true)
      JSDELIVR_CDN=$(printf '%s\n' "$EXTERNAL_SCRIPTS" | grep -c "jsdelivr.net" || true)
      UNPKG_CDN=$(printf '%s\n' "$EXTERNAL_SCRIPTS" | grep -c "unpkg.com" || true)
      GA_ANALYTICS=$(printf '%s\n' "$EXTERNAL_SCRIPTS" | grep -c "google-analytics.com\|googletagmanager.com" || true)
      
      [[ ${GOOGLE_CDN:-0} -gt 0 ]] && say "  • Google CDN scripts: $GOOGLE_CDN"
      [[ ${CLOUDFLARE_CDN:-0} -gt 0 ]] && say "  • Cloudflare CDN scripts: $CLOUDFLARE_CDN"
      [[ ${JSDELIVR_CDN:-0} -gt 0 ]] && say "  • jsDelivr CDN scripts: $JSDELIVR_CDN"
      [[ ${UNPKG_CDN:-0} -gt 0 ]] && say "  • unpkg CDN scripts: $UNPKG_CDN"
      [[ ${GA_ANALYTICS:-0} -gt 0 ]] && say "  • Google Analytics/Tag Manager: $GA_ANALYTICS"
      
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    else
      sayc "${GREEN}✓ All ${TOTAL_EXTERNAL} external scripts have SRI hashes${NC}"
    fi
    
    # Check for CSP
    CSP_FOUND=$(grep -roh "Content-Security-Policy" "$OUTPUT_DIR" --include="*.html" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${CSP_FOUND:-0} -eq 0 ]] && [[ ! -f "netlify.toml" || $(grep -c "Content-Security-Policy" "netlify.toml" 2>/dev/null || echo 0) -eq 0 ]]; then
      sayc "${BLUE}ℹ️  No Content-Security-Policy detected [LOW]${NC}"
      say "  CSP provides defense-in-depth against compromised scripts"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
    
    say ""
    say "Actions:"
    say "  • Generate SRI hashes: https://www.srihash.org/"
    say "  • Add integrity + crossorigin attributes to <script> tags"
    say "  • Example:"
    say "      <script src=\"https://cdn.example.com/lib.js\""
    say "              integrity=\"sha384-oqVu...\" crossorigin=\"anonymous\"></script>"
    say "  • Consider Content-Security-Policy header to enforce SRI"
    say "  • Pin CDN versions (avoid /latest or version ranges)"
  else
    sayc "${GREEN}✓ No external scripts found in output${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 28: Form Action Endpoints
# ============================================================

hr
sayc "${PURPLE}CHECK 28: Form Action Endpoints${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  FORM_ISSUES=0
  
  # Find all forms
  FORMS=$(grep -roh '<form[^>]*>' "$OUTPUT_DIR" --include="*.html" 2>/dev/null || true)
  
  if [[ -n "$FORMS" ]]; then
    TOTAL_FORMS=$(printf '%s\n' "$FORMS" | wc -l | tr -d ' ')
    sayc "${BLUE}ℹ️  Found $TOTAL_FORMS form(s)${NC}"
    
    # Check for non-HTTPS action URLs
    HTTP_FORMS=$(printf '%s\n' "$FORMS" | grep -i 'action="http://' | wc -l | tr -d ' ' || true)
    if [[ ${HTTP_FORMS:-0} -gt 0 ]]; then
      sayc "${RED}✗ Found ${HTTP_FORMS} form(s) submitting over HTTP [HIGH]${NC}"
      printf '%s\n' "$FORMS" | grep -i 'action="http://' | head -"$SHOW_MATCHES" | sed 's/^/  /'
      FORM_ISSUES=$((FORM_ISSUES + 1))
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    fi
    
    # Check for mailto: actions (email harvesting risk)
    MAILTO_FORMS=$(printf '%s\n' "$FORMS" | grep -i 'action="mailto:' | wc -l | tr -d ' ' || true)
    if [[ ${MAILTO_FORMS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found ${MAILTO_FORMS} form(s) using mailto: action [MEDIUM]${NC}"
      say "  mailto: forms expose email addresses and provide poor UX"
      printf '%s\n' "$FORMS" | grep -i 'action="mailto:' | head -"$SHOW_MATCHES" | sed 's/^/  /'
      FORM_ISSUES=$((FORM_ISSUES + 1))
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
    
    # Check for third-party form processors
    THIRD_PARTY_FORMS=$(printf '%s\n' "$FORMS" | grep -iE 'action="https?://(formspree\.io|getform\.io|forms\.google\.com|docs\.google\.com|formcarry\.com|formspark\.io|basin\.com|usebasin\.com|kwes\.io|formsubmit\.co|staticforms\.xyz)' | wc -l | tr -d ' ' || true)
    if [[ ${THIRD_PARTY_FORMS:-0} -gt 0 ]]; then
      sayc "${BLUE}ℹ️  Found ${THIRD_PARTY_FORMS} third-party form processor(s) [LOW]${NC}"
      say "  Data flows to external service - verify GDPR/privacy compliance"
      printf '%s\n' "$FORMS" | grep -iE 'action="https?://(formspree|getform|forms\.google|formcarry|formspark|basin|usebasin|kwes|formsubmit|staticforms)' | head -"$SHOW_MATCHES" | sed 's/^/  /'
      FORM_ISSUES=$((FORM_ISSUES + 1))
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
    
    # Check for CSRF protection (very basic check)
    FORMS_WITH_TOKEN=$(grep -roh '<input[^>]*name="[^"]*\(csrf\|token\|_token\)[^"]*"' "$OUTPUT_DIR" --include="*.html" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${FORMS_WITH_TOKEN:-0} -eq 0 ]] && [[ $TOTAL_FORMS -gt 0 ]]; then
      sayc "${BLUE}ℹ️  No obvious CSRF tokens detected [LOW]${NC}"
      say "  Consider CSRF protection for state-changing forms"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
    
    # Check for honeypot fields (bot protection)
    HONEYPOT=$(grep -roh '<input[^>]*\(style="display:\s*none"\|class="[^"]*hidden\)' "$OUTPUT_DIR" --include="*.html" 2>/dev/null | grep -i 'name=' | wc -l | tr -d ' ' || true)
    if [[ ${HONEYPOT:-0} -eq 0 ]] && [[ $TOTAL_FORMS -gt 0 ]]; then
      sayc "${BLUE}ℹ️  No honeypot fields detected [LOW]${NC}"
      say "  Honeypot fields help prevent spam bot submissions"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
    
    if [[ $FORM_ISSUES -gt 0 ]]; then
      say ""
      say "Actions:"
      say "  • Use HTTPS for all form actions"
      say "  • Replace mailto: with proper form backend (Netlify Forms, serverless)"
      say "  • Add CSRF tokens for state-changing operations"
      say "  • Implement honeypot fields for bot protection"
      say "  • Review third-party processors for GDPR compliance"
      say "  • Consider Netlify Forms (built-in spam protection + HTTPS)"
    else
      sayc "${GREEN}✓ Forms appear secure${NC}"
    fi
  else
    sayc "${GREEN}✓ No forms found in output${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 29: Analytics & Tag Manager Data Leakage
# ============================================================

hr
sayc "${PURPLE}CHECK 29: Analytics & Tag Manager Data Leakage${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  ANALYTICS_ISSUES=0
  
  # Check for Google Tag Manager
  GTM=$(grep -roh "googletagmanager\.com/gtm\.js\?id=GTM-[A-Z0-9]*" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | sort -u || true)
  if [[ -n "$GTM" ]]; then
    GTM_COUNT=$(printf '%s\n' "$GTM" | wc -l | tr -d ' ')
    sayc "${BLUE}ℹ️  Google Tag Manager detected ($GTM_COUNT container(s))${NC}"
    
    # Check for dataLayer.push with PII patterns
    DATALAYER_PII=$(grep -rE "dataLayer\.push.*\{[^}]*(email|phone|ssn|password|credit|card)" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${DATALAYER_PII:-0} -gt 0 ]]; then
      sayc "${RED}✗ Potential PII in dataLayer.push() [HIGH]${NC}"
      grep -rE "dataLayer\.push.*\{[^}]*(email|phone|ssn|password|credit|card)" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      say "  PII in analytics = GDPR violation + data breach risk"
      ANALYTICS_ISSUES=$((ANALYTICS_ISSUES + 1))
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    fi
  fi
  
  # Check for Google Analytics
  GA=$(grep -roh "google-analytics\.com/analytics\.js\|googletagmanager\.com/gtag/js" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | wc -l | tr -d ' ' || true)
  if [[ ${GA:-0} -gt 0 ]]; then
    sayc "${BLUE}ℹ️  Google Analytics detected${NC}"
    
    # Check for user ID tracking
    USER_ID=$(grep -rE "ga\(.*'set'.*'userId'" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${USER_ID:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  User ID tracking detected [MEDIUM]${NC}"
      say "  Ensure user IDs are anonymized/hashed (not email or real ID)"
      grep -rE "ga\(.*'set'.*'userId'" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      ANALYTICS_ISSUES=$((ANALYTICS_ISSUES + 1))
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  fi
  
  # Check for Segment
  SEGMENT=$(grep -roh "cdn\.segment\.com/analytics\.js" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | wc -l | tr -d ' ' || true)
  if [[ ${SEGMENT:-0} -gt 0 ]]; then
    sayc "${BLUE}ℹ️  Segment detected${NC}"
    
    # Check for identify() calls with PII
    SEGMENT_PII=$(grep -rE "analytics\.identify.*\{[^}]*(email|phone|address)" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${SEGMENT_PII:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  PII in Segment identify() [MEDIUM]${NC}"
      grep -rE "analytics\.identify.*\{[^}]*(email|phone|address)" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      ANALYTICS_ISSUES=$((ANALYTICS_ISSUES + 1))
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  fi
  
  # Check for Mixpanel
  MIXPANEL=$(grep -roh "mixpanel\.com/libs/mixpanel" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | wc -l | tr -d ' ' || true)
  if [[ ${MIXPANEL:-0} -gt 0 ]]; then
    sayc "${BLUE}ℹ️  Mixpanel detected${NC}"
  fi
  
  # Check for email addresses in URL parameters (common mistake)
  EMAIL_IN_URL=$(grep -roE "https?://[^\"' ]*[?&](email|user|utm_email)=[^&\"' ]*@[^&\"' ]*" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | wc -l | tr -d ' ' || true)
  if [[ ${EMAIL_IN_URL:-0} -gt 0 ]]; then
    sayc "${YELLOW}⚠️  Email addresses in URL parameters [MEDIUM]${NC}"
    say "  URLs with emails = logged in analytics, referrer headers, browser history"
    grep -roE "https?://[^\"' ]*[?&](email|user|utm_email)=[^&\"' ]*@[^&\"' ]*" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
    ANALYTICS_ISSUES=$((ANALYTICS_ISSUES + 1))
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
  fi
  
  # Check for internal user IDs as analytics properties
  INTERNAL_IDS=$(grep -rE "(userId|user_id|customerId|customer_id)['\"]?\s*:\s*[0-9]{5,}" "$OUTPUT_DIR" --include="*.html" --include="*.js" 2>/dev/null | wc -l | tr -d ' ' || true)
  if [[ ${INTERNAL_IDS:-0} -gt 0 ]]; then
    sayc "${BLUE}ℹ️  Internal IDs sent to analytics [LOW]${NC}"
    say "  Consider hashing user IDs before sending to third-party analytics"
    LOW_ISSUES=$((LOW_ISSUES + 1))
  fi
  
  if [[ $ANALYTICS_ISSUES -gt 0 ]]; then
    say ""
    say "Actions:"
    say "  • Remove PII (email, phone, SSN) from analytics events"
    say "  • Hash user IDs before sending to third parties"
    say "  • Never include email in URL parameters"
    say "  • Anonymize IP addresses (GA: anonymizeIp)"
    say "  • Review GDPR compliance for data collection"
    say "  • Use consent management platform (CMP) for opt-in/opt-out"
    say "  • Consider server-side tracking for sensitive data"
  elif [[ ${GA:-0} -gt 0 || ${GTM:-0} -gt 0 || ${SEGMENT:-0} -gt 0 || ${MIXPANEL:-0} -gt 0 ]]; then
    sayc "${GREEN}✓ Analytics configured with no obvious PII leakage${NC}"
  else
    sayc "${GREEN}✓ No third-party analytics detected${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 30: DNS/Subdomain Takeover Risk
# ============================================================

hr
sayc "${PURPLE}CHECK 30: DNS/Subdomain Takeover Risk${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  DNS_ISSUES=0
  
  # Check netlify.toml for custom domains
  if [[ -f "netlify.toml" ]]; then
    CUSTOM_DOMAINS=$(grep -E "^\s*domain\s*=" "netlify.toml" 2>/dev/null || true)
    if [[ -n "$CUSTOM_DOMAINS" ]]; then
      sayc "${BLUE}ℹ️  Custom domain(s) configured in netlify.toml${NC}"
      printf '%s\n' "$CUSTOM_DOMAINS" | sed 's/^/  /'
      say ""
      say "  Manual verification required:"
      say "  • Ensure DNS CNAME points to active Netlify site"
      say "  • Verify domain is claimed in Netlify dashboard"
      say "  • Check for orphaned DNS records to deleted sites"
      LOW_ISSUES=$((LOW_ISSUES + 1))
      DNS_ISSUES=$((DNS_ISSUES + 1))
    fi
  fi
  
  # Check for _redirects file with external domains
  if [[ -f "_redirects" || -f "public/_redirects" || -f "$OUTPUT_DIR/_redirects" ]]; then
    REDIRECT_FILE=""
    [[ -f "_redirects" ]] && REDIRECT_FILE="_redirects"
    [[ -f "public/_redirects" ]] && REDIRECT_FILE="public/_redirects"
    [[ -f "$OUTPUT_DIR/_redirects" ]] && REDIRECT_FILE="$OUTPUT_DIR/_redirects"
    
    if [[ -n "$REDIRECT_FILE" ]]; then
      # Look for redirects to external domains
      EXTERNAL_REDIRECTS=$(grep -E "https?://" "$REDIRECT_FILE" 2>/dev/null | grep -v "^#" || true)
      if [[ -n "$EXTERNAL_REDIRECTS" ]]; then
        sayc "${BLUE}ℹ️  External redirects found in _redirects${NC}"
        printf '%s\n' "$EXTERNAL_REDIRECTS" | head -5 | sed 's/^/  /'
        say ""
        say "  Verify target domains are:"
        say "  • Still active and under your control"
        say "  • Not vulnerable to takeover"
        LOW_ISSUES=$((LOW_ISSUES + 1))
        DNS_ISSUES=$((DNS_ISSUES + 1))
      fi
    fi
  fi
  
  # Check for common vulnerable CNAME patterns in docs
  VULNERABLE_PATTERNS=$(grep -rE "(\.s3\.amazonaws\.com|\.herokuapp\.com|\.azurewebsites\.net|\.github\.io|\.gitlab\.io|\.bitbucket\.io|\.surge\.sh|\.ghost\.io)" . \
    --include="*.md" --include="*.txt" --include="README*" --include="*.toml" --include="*.yml" --include="*.yaml" \
    "${GREP_EXCLUDES[@]}" 2>/dev/null | wc -l | tr -d ' ' || true)
  
  if [[ ${VULNERABLE_PATTERNS:-0} -gt 0 ]]; then
    sayc "${YELLOW}⚠️  References to takeover-vulnerable services found [MEDIUM]${NC}"
    say "  Common takeover targets: S3, Heroku, Azure, GitHub Pages, GitLab Pages"
    grep -rE "(\.s3\.amazonaws\.com|\.herokuapp\.com|\.azurewebsites\.net|\.github\.io|\.gitlab\.io)" . \
      --include="*.md" --include="*.txt" --include="README*" --include="*.toml" --include="*.yml" --include="*.yaml" \
      "${GREP_EXCLUDES[@]}" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /' || true
    DNS_ISSUES=$((DNS_ISSUES + 1))
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
  fi
  
  # Check for old Netlify site references
  OLD_NETLIFY=$(grep -rE "[a-z0-9-]+\.netlify\.(com|app)" . \
    --include="*.md" --include="*.txt" --include="README*" \
    "${GREP_EXCLUDES[@]}" 2>/dev/null | grep -v "$(basename "$PWD")" | wc -l | tr -d ' ' || true)
  
  if [[ ${OLD_NETLIFY:-0} -gt 0 ]]; then
    sayc "${BLUE}ℹ️  References to Netlify subdomains found [LOW]${NC}"
    say "  Verify these sites are still active and under your control"
    LOW_ISSUES=$((LOW_ISSUES + 1))
    DNS_ISSUES=$((DNS_ISSUES + 1))
  fi
  
  if [[ $DNS_ISSUES -gt 0 ]]; then
    say ""
    say "Actions:"
    say "  • Audit DNS records for orphaned CNAME entries"
    say "  • Remove DNS records pointing to deleted services"
    say "  • Use Netlify DNS for automatic cleanup"
    say "  • Monitor with: https://github.com/EdOverflow/can-i-take-over-xyz"
    say "  • Set up subdomain monitoring (e.g., SecurityTrails, DNSDumpster)"
    say "  • Delete unused subdomains from DNS provider"
  else
    sayc "${GREEN}✓ No obvious subdomain takeover risks${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 31: Stale OAuth Tokens in Static Content
# ============================================================

hr
sayc "${PURPLE}CHECK 31: Stale OAuth Tokens in Static Content${NC}"
hr

if [[ "$SKIP_OUTPUT" -eq 1 || -z "${OUTPUT_DIR:-}" || ! -d "${OUTPUT_DIR:-}" ]]; then
  sayc "${BLUE}ℹ️  Skipping (no output dir or output scan disabled)${NC}"
  say ""
else
  OAUTH_ISSUES=0
  
  # Check for OAuth redirect URIs in JavaScript
  REDIRECT_URIS=$(grep -roE "redirect_uri['\"]?\s*[:=]\s*['\"]https?://[^'\"]*['\"]" "$OUTPUT_DIR" --include="*.js" --include="*.html" 2>/dev/null || true)
  if [[ -n "$REDIRECT_URIS" ]]; then
    REDIRECT_COUNT=$(printf '%s\n' "$REDIRECT_URIS" | wc -l | tr -d ' ')
    sayc "${BLUE}ℹ️  Found $REDIRECT_COUNT OAuth redirect_uri reference(s)${NC}"
    
    # Check for localhost/development URIs
    DEV_REDIRECTS=$(printf '%s\n' "$REDIRECT_URIS" | grep -E "(localhost|127\.0\.0\.1|\.local|\.dev)" | wc -l | tr -d ' ' || true)
    if [[ ${DEV_REDIRECTS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Development redirect URIs in production code [MEDIUM]${NC}"
      printf '%s\n' "$REDIRECT_URIS" | grep -E "(localhost|127\.0\.0\.1|\.local|\.dev)" | head -"$SHOW_MATCHES" | sed 's/^/  /'
      OAUTH_ISSUES=$((OAUTH_ISSUES + 1))
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  fi
  
  # Check for Client IDs (even without secrets, still sensitive)
  CLIENT_IDS=$(grep -roE "(client_id|clientId|client-id)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9._-]{20,}['\"]" "$OUTPUT_DIR" --include="*.js" --include="*.html" 2>/dev/null | wc -l | tr -d ' ' || true)
  if [[ ${CLIENT_IDS:-0} -gt 0 ]]; then
    sayc "${BLUE}ℹ️  Found $CLIENT_IDS OAuth client_id reference(s) [LOW]${NC}"
    say "  Client IDs in frontend code are normal, but verify:"
    say "  • They're for public OAuth flows (implicit/PKCE)"
    say "  • Redirect URIs are properly configured"
    say "  • No client_secret is present (would be CRITICAL)"
    LOW_ISSUES=$((LOW_ISSUES + 1))
    
    # Check for client_secret (CRITICAL if found)
    CLIENT_SECRETS=$(grep -roE "(client_secret|clientSecret|client-secret)['\"]?\s*[:=]\s*['\"][^'\"]{10,}['\"]" "$OUTPUT_DIR" --include="*.js" --include="*.html" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${CLIENT_SECRETS:-0} -gt 0 ]]; then
      sayc "${RED}✗ CRITICAL: OAuth client_secret found in frontend code [CRITICAL]${NC}"
      grep -roE "(client_secret|clientSecret|client-secret)['\"]?\s*[:=]\s*['\"][^'\"]{10,}['\"]" "$OUTPUT_DIR" --include="*.js" --include="*.html" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      OAUTH_ISSUES=$((OAUTH_ISSUES + 1))
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    fi
  fi
  
  # Check for deprecated implicit grant flow
  IMPLICIT_FLOW=$(grep -rE "response_type['\"]?\s*[:=]\s*['\"]token" "$OUTPUT_DIR" --include="*.js" --include="*.html" 2>/dev/null | wc -l | tr -d ' ' || true)
  if [[ ${IMPLICIT_FLOW:-0} -gt 0 ]]; then
    sayc "${YELLOW}⚠️  Deprecated OAuth implicit flow detected [MEDIUM]${NC}"
    say "  Implicit flow is deprecated - use Authorization Code + PKCE instead"
    grep -rE "response_type['\"]?\s*[:=]\s*['\"]token" "$OUTPUT_DIR" --include="*.js" --include="*.html" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
    OAUTH_ISSUES=$((OAUTH_ISSUES + 1))
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
  fi
  
  # Check for access tokens in localStorage (common mistake)
  LOCALSTORAGE_TOKENS=$(grep -rE "localStorage\.(setItem|getItem).*['\"].*(token|access|refresh)" "$OUTPUT_DIR" --include="*.js" --include="*.html" 2>/dev/null | wc -l | tr -d ' ' || true)
  if [[ ${LOCALSTORAGE_TOKENS:-0} -gt 0 ]]; then
    sayc "${YELLOW}⚠️  Tokens stored in localStorage [MEDIUM]${NC}"
    say "  localStorage is vulnerable to XSS - consider httpOnly cookies"
    grep -rE "localStorage\.(setItem|getItem).*['\"].*(token|access|refresh)" "$OUTPUT_DIR" --include="*.js" --include="*.html" 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
    OAUTH_ISSUES=$((OAUTH_ISSUES + 1))
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
  fi
  
  if [[ $OAUTH_ISSUES -gt 0 ]]; then
    say ""
    say "Actions:"
    say "  • NEVER expose client_secret in frontend code"
    say "  • Use Authorization Code + PKCE flow (not implicit)"
    say "  • Store tokens in httpOnly cookies (not localStorage)"
    say "  • Implement token rotation and short expiry"
    say "  • Remove development redirect URIs from production"
    say "  • Verify OAuth provider's redirect URI allowlist"
    say "  • Consider backend-for-frontend (BFF) pattern"
  else
    sayc "${GREEN}✓ No obvious OAuth token issues${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 32: Build-Time Data Exfiltration
# ============================================================

hr
sayc "${PURPLE}CHECK 32: Build-Time Data Exfiltration${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  BUILD_ISSUES=0
  
  # Check package.json scripts
  if [[ -f "package.json" ]]; then
    sayc "${BLUE}ℹ️  Analyzing package.json scripts${NC}"
    
    # Check for curl/wget to non-official domains
    SUSPICIOUS_DOWNLOADS=$(grep -E "(curl|wget|fetch|download).*https?://" "package.json" 2>/dev/null | \
      grep -vE "(npmjs\.org|github\.com|githubusercontent\.com|cloudflare\.com|unpkg\.com|jsdelivr\.net|yarnpkg\.com)" || true)
    
    if [[ -n "$SUSPICIOUS_DOWNLOADS" ]]; then
      sayc "${YELLOW}⚠️  Network calls to non-standard domains in scripts [HIGH]${NC}"
      printf '%s\n' "$SUSPICIOUS_DOWNLOADS" | head -"$SHOW_MATCHES" | sed 's/^/  /'
      say "  Build scripts downloading from unknown sources = supply chain risk"
      BUILD_ISSUES=$((BUILD_ISSUES + 1))
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    fi
    
    # Check for postinstall hooks
    POSTINSTALL=$(grep -E "\"postinstall\":" "package.json" 2>/dev/null || true)
    if [[ -n "$POSTINSTALL" ]]; then
      sayc "${YELLOW}⚠️  postinstall hook detected [MEDIUM]${NC}"
      printf '%s\n' "$POSTINSTALL" | sed 's/^/  /'
      say "  postinstall runs automatically after npm install - verify it's safe"
      BUILD_ISSUES=$((BUILD_ISSUES + 1))
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
    
    # Check for preinstall hooks
    PREINSTALL=$(grep -E "\"preinstall\":" "package.json" 2>/dev/null || true)
    if [[ -n "$PREINSTALL" ]]; then
      sayc "${YELLOW}⚠️  preinstall hook detected [MEDIUM]${NC}"
      printf '%s\n' "$PREINSTALL" | sed 's/^/  /'
      BUILD_ISSUES=$((BUILD_ISSUES + 1))
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  fi
  
  # Check netlify.toml build commands
  if [[ -f "netlify.toml" ]]; then
    sayc "${BLUE}ℹ️  Analyzing netlify.toml build commands${NC}"
    
    # Check for network calls in build
    BUILD_DOWNLOADS=$(grep -E "^\s*command.*=.*(curl|wget|fetch)" "netlify.toml" 2>/dev/null | \
      grep -vE "(npmjs\.org|github\.com|githubusercontent\.com)" || true)
    
    if [[ -n "$BUILD_DOWNLOADS" ]]; then
      sayc "${YELLOW}⚠️  Network downloads in build commands [HIGH]${NC}"
      printf '%s\n' "$BUILD_DOWNLOADS" | head -"$SHOW_MATCHES" | sed 's/^/  /'
      BUILD_ISSUES=$((BUILD_ISSUES + 1))
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    fi
    
    # Check for executable downloads
    EXECUTABLE_DOWNLOADS=$(grep -E "^\s*command.*(\.sh|\.py|\.rb|\.pl|binary|executable)" "netlify.toml" 2>/dev/null || true)
    if [[ -n "$EXECUTABLE_DOWNLOADS" ]]; then
      sayc "${YELLOW}⚠️  Executable downloads in build [HIGH]${NC}"
      printf '%s\n' "$EXECUTABLE_DOWNLOADS" | head -"$SHOW_MATCHES" | sed 's/^/  /'
      say "  Downloading and running scripts = supply chain attack vector"
      BUILD_ISSUES=$((BUILD_ISSUES + 1))
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    fi
  fi
  
  # Check for suspicious npm packages (common typosquatting targets)
  if [[ -f "package.json" ]]; then
    SUSPICIOUS_PACKAGES=$(grep -oE "\"[^\"]*\":" "package.json" | grep -E "(crossenv|cross-env\.js|nodemailer\.js|bootstrap\.js)" || true)
    if [[ -n "$SUSPICIOUS_PACKAGES" ]]; then
      sayc "${RED}✗ Potential typosquatting packages detected [CRITICAL]${NC}"
      printf '%s\n' "$SUSPICIOUS_PACKAGES" | sed 's/^/  /'
      say "  These may be malicious lookalikes of legitimate packages"
      BUILD_ISSUES=$((BUILD_ISSUES + 1))
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    fi
  fi
  
  # Check for .npmrc with non-official registries
  if [[ -f ".npmrc" ]]; then
    CUSTOM_REGISTRY=$(grep -E "^registry\s*=" ".npmrc" 2>/dev/null | grep -v "registry.npmjs.org" || true)
    if [[ -n "$CUSTOM_REGISTRY" ]]; then
      sayc "${YELLOW}⚠️  Custom npm registry configured [MEDIUM]${NC}"
      printf '%s\n' "$CUSTOM_REGISTRY" | sed 's/^/  /'
      say "  Verify this is an official private registry"
      BUILD_ISSUES=$((BUILD_ISSUES + 1))
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  fi
  
  if [[ $BUILD_ISSUES -gt 0 ]]; then
    say ""
    say "Actions:"
    say "  • Audit all build-time network calls"
    say "  • Verify package sources (npm audit, Socket.dev)"
    say "  • Pin dependency versions with lockfiles"
    say "  • Review postinstall/preinstall hooks"
    say "  • Use npm audit / yarn audit regularly"
    say "  • Consider: Dependabot, Snyk, or Socket Security"
    say "  • Never download + execute unverified scripts in builds"
  else
    sayc "${GREEN}✓ No obvious build-time supply chain risks${NC}"
  fi
  say ""
fi

# ============================================================
# CHECK 33: API Key Rotation Age
# ============================================================

hr
sayc "${PURPLE}CHECK 33: API Key Rotation Age${NC}"
hr

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output)${NC}"
  say ""
else
  ROTATION_ISSUES=0
  
  if [[ -f ".env.example" || -f ".env.sample" || -f ".env.template" ]]; then
    ENV_EXAMPLE=""
    [[ -f ".env.example" ]] && ENV_EXAMPLE=".env.example"
    [[ -f ".env.sample" ]] && ENV_EXAMPLE=".env.sample"
    [[ -f ".env.template" ]] && ENV_EXAMPLE=".env.template"
    
    sayc "${BLUE}ℹ️  Found environment template: $ENV_EXAMPLE${NC}"
    
    # Check git history for when this file was last changed
    if [[ -d ".git" ]] && _has_cmd git; then
      LAST_MODIFIED=$(git log -1 --format="%cr" -- "$ENV_EXAMPLE" 2>/dev/null || echo "unknown")
      sayc "  Last modified: $LAST_MODIFIED"
      
      # Check if older than 90 days
      if [[ "$LAST_MODIFIED" != "unknown" ]]; then
        DAYS_AGO=$(git log -1 --format="%ct" -- "$ENV_EXAMPLE" 2>/dev/null || echo "0")
        NOW=$(date +%s)
        AGE_DAYS=$(( (NOW - DAYS_AGO) / 86400 ))
        
        if [[ $AGE_DAYS -gt 90 ]]; then
          sayc "${YELLOW}⚠️  Environment template unchanged for ${AGE_DAYS} days [MEDIUM]${NC}"
          say "  Consider reviewing and rotating API keys quarterly"
          ROTATION_ISSUES=$((ROTATION_ISSUES + 1))
          MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
        else
          sayc "${GREEN}✓ Environment template recently updated ($AGE_DAYS days ago)${NC}"
        fi
      fi
      
      # Check for same keys across branches
      if git branch -a | grep -qE "main|master|develop|staging|production"; then
        sayc "${BLUE}ℹ️  Checking for key reuse across branches${NC}"
        
        # This is a simplified check - in reality, would need to compare actual key values
        BRANCHES=$(git branch -a | grep -E "remotes/origin/(main|master|develop|staging|production)" | sed 's/.*\///' | sort -u)
        if [[ $(printf '%s\n' "$BRANCHES" | wc -l) -gt 1 ]]; then
          sayc "${BLUE}ℹ️  Multiple environment branches detected [LOW]${NC}"
          say "  Verify each environment uses unique API keys"
          LOW_ISSUES=$((LOW_ISSUES + 1))
        fi
      fi
    else
      sayc "${BLUE}ℹ️  Not a git repo - cannot check rotation age${NC}"
    fi
    
    # Parse .env.example for key categories
    API_KEYS=$(grep -iE "^[A-Z_]*API[A-Z_]*KEY" "$ENV_EXAMPLE" 2>/dev/null | wc -l | tr -d ' ' || true)
    SECRETS=$(grep -iE "^[A-Z_]*SECRET" "$ENV_EXAMPLE" 2>/dev/null | wc -l | tr -d ' ' || true)
    TOKENS=$(grep -iE "^[A-Z_]*TOKEN" "$ENV_EXAMPLE" 2>/dev/null | wc -l | tr -d ' ' || true)
    
    if [[ ${API_KEYS:-0} -gt 0 || ${SECRETS:-0} -gt 0 || ${TOKENS:-0} -gt 0 ]]; then
      sayc "${BLUE}ℹ️  Secret types in environment template:${NC}"
      [[ ${API_KEYS:-0} -gt 0 ]] && say "  • API keys: $API_KEYS"
      [[ ${SECRETS:-0} -gt 0 ]] && say "  • Secrets: $SECRETS"
      [[ ${TOKENS:-0} -gt 0 ]] && say "  • Tokens: $TOKENS"
    fi
    
  else
    sayc "${BLUE}ℹ️  No .env.example/.env.sample found${NC}"
    say "  Consider creating one to document required environment variables"
    LOW_ISSUES=$((LOW_ISSUES + 1))
  fi
  
  # Check for test vs prod key confusion
  if [[ -f ".env.example" ]]; then
    TEST_PROD_MIX=$(grep -E "(test|dev|development|staging).*prod|prod.*(test|dev|development|staging)" ".env.example" -i 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${TEST_PROD_MIX:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Possible test/prod key mixing in template [MEDIUM]${NC}"
      grep -E "(test|dev|development|staging).*prod|prod.*(test|dev|development|staging)" ".env.example" -i 2>/dev/null | head -"$SHOW_MATCHES" | sed 's/^/  /'
      ROTATION_ISSUES=$((ROTATION_ISSUES + 1))
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  fi
  
  say ""
  say "Actions:"
  say "  • Rotate API keys quarterly (every 90 days minimum)"
  say "  • Use separate keys per environment (dev/staging/prod)"
  say "  • Document key rotation schedule in team runbook"
  say "  • Set up calendar reminders for key rotation"
  say "  • Use secret management tools (Vault, AWS Secrets Manager)"
  say "  • Track key creation dates in password manager"
  say "  • Implement automated rotation where possible"
  say ""
fi

# ============================================================

# ============================================================
# FINAL SUMMARY + INTERACTIVE DECISION LOGIC
# ============================================================

say "=============================================="
say "🔒 FINAL SECURITY SUMMARY 🔒"
say "=============================================="
say ""
say "Generator detected: $GENERATOR"
[[ -n "${OUTPUT_DIR:-}" ]] && say "Output dir detected: $OUTPUT_DIR"
say ""

TOTAL_ISSUES=$((CRITICAL_ISSUES + HIGH_ISSUES + MEDIUM_ISSUES + LOW_ISSUES))

# Display issue summary
if [[ $CRITICAL_ISSUES -gt 0 ]]; then
  sayc "${RED}🚨 CRITICAL: $CRITICAL_ISSUES issue(s) - DEPLOYMENT BLOCKED${NC}"
fi
if [[ $HIGH_ISSUES -gt 0 ]]; then
  sayc "${RED}⚠️  HIGH:     $HIGH_ISSUES issue(s) - DEPLOYMENT BLOCKED${NC}"
fi
if [[ $MEDIUM_ISSUES -gt 0 ]]; then
  sayc "${YELLOW}⚠️  MEDIUM:   $MEDIUM_ISSUES issue(s) - Review required${NC}"
fi
if [[ $LOW_ISSUES -gt 0 ]]; then
  sayc "${BLUE}ℹ️  LOW:      $LOW_ISSUES issue(s) - Nice to fix${NC}"
fi

say ""


# EXIT DECISION LOGIC
# ============================================================

# CRITICAL or HIGH: ALWAYS BLOCK
if [[ $CRITICAL_ISSUES -gt 0 || $HIGH_ISSUES -gt 0 ]]; then
  hr
  sayc "${RED}❌ DEPLOYMENT BLOCKED ❌${NC}"
  hr
  say ""
  say "CRITICAL and HIGH severity issues must be fixed before deployment."
  say ""
  say "Priority actions:"
  [[ $CRITICAL_ISSUES -gt 0 ]] && say "  1. 🚨 Fix $CRITICAL_ISSUES CRITICAL issue(s) immediately"
  [[ $HIGH_ISSUES -gt 0 ]] && say "  2. ⚠️  Fix $HIGH_ISSUES HIGH issue(s) before deploying"
  say ""
  say "Re-run this script after fixing issues."
  say ""
  say "=============================================="
  sayc "${PURPLE}Generated by: 🦛 Published by Oob Skulden™ 🦛${NC}"
  sayc "${PURPLE}\"The threats you don't see coming\"${NC}"
  say "=============================================="
  say ""
  
  if [[ $CRITICAL_ISSUES -gt 0 ]]; then
    exit 3
  else
    exit 2
  fi
fi

# MEDIUM: PROMPT USER (unless non-interactive)
if [[ $MEDIUM_ISSUES -gt 0 ]]; then
  if ! prompt_user "MEDIUM" "$MEDIUM_ISSUES"; then
    say ""
    say "=============================================="
    sayc "${PURPLE}Generated by: 🦛 Published by Oob Skulden™ 🦛${NC}"
    sayc "${PURPLE}\"The threats you don't see coming\"${NC}"
    say "=============================================="
    say ""
    exit 1
  fi
fi

# LOW: PROMPT USER (unless non-interactive)
if [[ $LOW_ISSUES -gt 0 ]]; then
  if ! prompt_user "LOW" "$LOW_ISSUES"; then
    say ""
    say "=============================================="
    sayc "${PURPLE}Generated by: 🦛 Published by Oob Skulden™ 🦛${NC}"
    sayc "${PURPLE}\"The threats you don't see coming\"${NC}"
    say "=============================================="
    say ""
    exit 1
  fi
fi

# NO ISSUES or USER ACCEPTED RISKS
if [[ $TOTAL_ISSUES -eq 0 ]]; then
  sayc "${GREEN}✅ EXCELLENT! No security issues found!${NC}"
  sayc "${GREEN}✅ Safe to deploy${NC}"
else
  sayc "${YELLOW}⚠️  Proceeding with acknowledged risks${NC}"
  say ""
  say "Issues accepted:"
  [[ $MEDIUM_ISSUES -gt 0 ]] && say "  • $MEDIUM_ISSUES MEDIUM issue(s)"
  [[ $LOW_ISSUES -gt 0 ]] && say "  • $LOW_ISSUES LOW issue(s)"
fi

say ""
say "=============================================="
sayc "${PURPLE}Generated by: 🦛 Published by Oob Skulden™ 🦛${NC}"
sayc "${PURPLE}\"The threats you don't see coming\"${NC}"
say "=============================================="
say ""

exit 0
