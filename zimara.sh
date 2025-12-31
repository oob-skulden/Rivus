#!/usr/bin/env bash
# ============================================
# Zimara — Security Audit Script
# ============================================
# Local pre-push/pre-commit guardrail for static sites and web projects.
#
# Supported generators: Hugo, Jekyll, Astro, Next.js export, Eleventy, generic.
#
# Published by Oob Skulden™
#
# Notes:
# - This is a *local* hygiene scanner. It does not replace CI SAST/DAST/SCA.
# - Designed to be fast, dependency-light, and low-noise.
# ============================================

set -euo pipefail

# -----------------------------
# Execution safety hardening
# -----------------------------
umask 077

_ORIG_PATH="${PATH:-}"
# Prefer a safe, minimal PATH to reduce command hijack risk (repo-local ./git, etc.)
PATH="/usr/sbin:/usr/bin:/sbin:/bin:/opt/homebrew/bin:/usr/local/sbin:/usr/local/bin"
export PATH
if [[ ":${_ORIG_PATH}:" == *":.:"* ]]; then
  echo "  Detected '.' in original PATH; ignoring it for this run (command hijack mitigation)."
fi

VERSION="0.48.0"

# -----------------------------
# Colors
# -----------------------------
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
PURPLE="\033[0;35m"
CYAN="\033[0;36m"
NC="\033[0m"

# -----------------------------
# Defaults / flags
# -----------------------------
TARGET_DIR="."
NON_INTERACTIVE=0
ONLY_OUTPUT=0
VERBOSE=0
TRACE_CHECKS=0

# Snippet configuration
SNIPPET_CONTEXT_LINES=3
SNIPPET_MAX_LINE_LENGTH=120
SNIPPET_SHOW_PATTERN=1

# Findings counters
CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0

# Hit tracking (avoid associative arrays for macOS bash 3.2 compatibility)
HIT_CHECK_IDS=()
HIT_LINES=()

# Generator detection
GENERATOR="generic"
OUTPUT_DIR=""

# Temp file tracking
TMP_FILES=()

cleanup() {
  local f
  for f in "${TMP_FILES[@]:-}"; do
    [[ -n "${f}" && -f "${f}" ]] && rm -f -- "${f}" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

tmpfile() {
  # Usage: tmpfile <prefix> <suffix>
  # Creates a secure temp file and tracks it for cleanup.
  local prefix="${1:-zimara}"
  local suffix="${2:-}"
  local f=""

  # mktemp is already race-safe; we still enforce ownership + no symlink.
  f="$(mktemp -t "${prefix}.XXXXXX${suffix}" 2>/dev/null || mktemp "/tmp/${prefix}.XXXXXX${suffix}")" || {
    sayc "${RED} FATAL: Cannot create secure temp file${NC}" >&2
    exit 99
  }

  # Defense-in-depth: ensure it's a regular file we own and not a symlink.
  if [[ ! -f "$f" || -L "$f" || ! -O "$f" ]]; then
    rm -f -- "$f" 2>/dev/null || true
    sayc "${RED} FATAL: Temp file safety/ownership violation${NC}" >&2
    exit 99
  fi

  TMP_FILES+=("$f")
  echo "$f"
}

hr() { printf "%s\n" "------------------------------------------------------------"; }
say() { printf "%b\n" "$1"; }
sayc() { printf "%b\n" "$1"; }

_has_cmd() { command -v "$1" >/dev/null 2>&1; }

# Resolve high-value tools to absolute paths (best-effort, with light trust checks)
_is_trusted_bin() {
  local p="$1"
  [[ -n "$p" && -x "$p" && -f "$p" ]] || return 1
  [[ ! -L "$p" ]] || return 1
  # Reject world-writable binaries (common hijack vector)
  if command -v stat >/dev/null 2>&1; then
    # Linux: stat -c %a ; macOS: stat -f %Lp
    local mode=""
    mode="$(stat -c %a "$p" 2>/dev/null || stat -f %Lp "$p" 2>/dev/null || echo "")"
    [[ -z "$mode" ]] && return 0
    # If "others write" bit set => reject
    local last="${mode: -1}"
    [[ "$last" =~ [2367] ]] && return 1
  fi
  return 0
}

_resolve_tool() {
  # Usage: _resolve_tool <name> <preferred_path1> <preferred_path2> ...
  local name="$1"; shift
  local cand
  for cand in "$@"; do
    if [[ -n "$cand" && -x "$cand" ]]; then
      echo "$cand"; return 0
    fi
  done
  cand="$(command -v "$name" 2>/dev/null || true)"
  if [[ -n "$cand" ]] && _is_trusted_bin "$cand"; then
    echo "$cand"; return 0
  fi
  echo ""
  return 0
}

GIT_BIN="$(_resolve_tool git /usr/bin/git /bin/git)"
GITLEAKS_BIN="$(_resolve_tool gitleaks /usr/local/bin/gitleaks /opt/homebrew/bin/gitleaks)"
DETECT_SECRETS_BIN="$(_resolve_tool detect-secrets)"
NPM_BIN="$(_resolve_tool npm /usr/bin/npm /opt/homebrew/bin/npm /usr/local/bin/npm)"
STAT_BIN="$(_resolve_tool stat /usr/bin/stat /bin/stat)"
FIND_BIN="$(_resolve_tool find /usr/bin/find /bin/find)"
GREP_BIN="$(_resolve_tool grep /usr/bin/grep /bin/grep)"
XARGS_BIN="$(_resolve_tool xargs /usr/bin/xargs /bin/xargs)"

git_cmd() { [[ -n "${GIT_BIN}" && -x "${GIT_BIN}" ]] && "${GIT_BIN}" "$@" || command git "$@"; }
gitleaks_cmd() { [[ -n "${GITLEAKS_BIN}" && -x "${GITLEAKS_BIN}" ]] && "${GITLEAKS_BIN}" "$@" || command gitleaks "$@"; }
detect_secrets_cmd() { [[ -n "${DETECT_SECRETS_BIN}" && -x "${DETECT_SECRETS_BIN}" ]] && "${DETECT_SECRETS_BIN}" "$@" || command detect-secrets "$@"; }
npm_cmd() { [[ -n "${NPM_BIN}" && -x "${NPM_BIN}" ]] && "${NPM_BIN}" "$@" || command npm "$@"; }
stat_cmd() { [[ -n "${STAT_BIN}" && -x "${STAT_BIN}" ]] && "${STAT_BIN}" "$@" || command stat "$@"; }
find_cmd() { [[ -n "${FIND_BIN}" && -x "${FIND_BIN}" ]] && "${FIND_BIN}" "$@" || command find "$@"; }
grep_cmd() { [[ -n "${GREP_BIN}" && -x "${GREP_BIN}" ]] && "${GREP_BIN}" "$@" || command grep "$@"; }
xargs_cmd() { [[ -n "${XARGS_BIN}" && -x "${XARGS_BIN}" ]] && "${XARGS_BIN}" "$@" || command xargs "$@"; }

# Safe grep: never propagate "no matches" as a fatal error under set -e
safe_grep() {
  # shellcheck disable=SC2068
  grep_cmd "$@" 2>/dev/null || true
}

# ============================================
# .zimaraignore Security & Validation
# ============================================

# Configuration
MAX_IGNORE_PATTERNS=100
MAX_PATTERN_LENGTH=200
SAFE_PATTERN_REGEX='^[a-zA-Z0-9._/*-]+$'

# Global arrays to hold validated patterns and constructed exclusions
IGNORE_PATTERNS=()
GREP_EXCLUDES=()
FIND_EXCLUDES=()

validate_ignore_pattern() {
  local pattern="$1"
  
  # Length check
  if [[ "${#pattern}" -gt "$MAX_PATTERN_LENGTH" ]]; then
    sayc "${RED} WARNING: .zimaraignore pattern exceeds ${MAX_PATTERN_LENGTH} chars (truncated): ${pattern:0:50}...${NC}" >&2
    return 1
  fi
  
  # Character whitelist (strict): alphanumeric, dot, slash, dash, underscore, asterisk ONLY
  if [[ ! "$pattern" =~ $SAFE_PATTERN_REGEX ]]; then
    sayc "${RED} WARNING: .zimaraignore invalid pattern (only a-z A-Z 0-9 . / - _ * allowed): ${pattern}${NC}" >&2
    return 1
  fi
  
  # Reject argument injection vectors
  if [[ "$pattern" =~ ^- ]]; then
    sayc "${RED} WARNING: .zimaraignore pattern cannot start with '-' (argument injection): ${pattern}${NC}" >&2
    return 1
  fi
  
  # Reject path traversal
  if [[ "$pattern" =~ \.\. ]]; then
    sayc "${RED} WARNING: .zimaraignore path traversal not allowed (..): ${pattern}${NC}" >&2
    return 1
  fi
  
  # Reject absolute paths
  if [[ "$pattern" =~ ^/ ]]; then
    sayc "${RED} WARNING: .zimaraignore absolute paths not allowed: ${pattern}${NC}" >&2
    return 1
  fi
  
  # Warn on overly broad patterns (but allow them)
  case "$pattern" in
    "*"|"*/*"|"*.*"|".")
      sayc "${YELLOW} WARNING: Very broad pattern may disable important checks: ${pattern}${NC}" >&2
      ;;
  esac
  
  return 0
}

load_zimaraignore() {
  IGNORE_PATTERNS=()
  
  if [[ ! -f ".zimaraignore" ]]; then
    return 0
  fi
  
  sayc "${BLUE} Loading .zimaraignore${NC}"
  
  local line pattern count=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    # Strip leading/trailing whitespace
    pattern="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    
    # Skip empty lines and comments
    [[ -z "$pattern" || "$pattern" =~ ^# ]] && continue
    
    # Enforce maximum pattern count
    if [[ "$count" -ge "$MAX_IGNORE_PATTERNS" ]]; then
      sayc "${YELLOW} WARNING: Maximum ${MAX_IGNORE_PATTERNS} patterns reached, ignoring remaining lines${NC}" >&2
      break
    fi
    
    # Validate and add
    if validate_ignore_pattern "$pattern"; then
      IGNORE_PATTERNS+=("$pattern")
      count=$((count + 1))
      [[ "$VERBOSE" -eq 1 ]] && say "   [${count}] ${pattern}"
    fi
  done < ".zimaraignore"
  
  if [[ "${#IGNORE_PATTERNS[@]}" -gt 0 ]]; then
    sayc "${GREEN} Loaded ${#IGNORE_PATTERNS[@]} valid pattern(s) from .zimaraignore${NC}"
  fi
  say ""
}

build_grep_excludes() {
  GREP_EXCLUDES=()
  for pattern in "${IGNORE_PATTERNS[@]}"; do
    GREP_EXCLUDES+=("--exclude=${pattern}")
  done
}

build_find_prunes() {
  FIND_EXCLUDES=()
  for pattern in "${IGNORE_PATTERNS[@]}"; do
    # Convert glob patterns to find-compatible expressions
    case "$pattern" in
      */*)
        # Path-based pattern: use -path
        FIND_EXCLUDES+=("-path" "./${pattern}" "-prune" "-o")
        ;;
      *.*)
        # Extension-based pattern: use -name
        FIND_EXCLUDES+=("-name" "${pattern}" "-prune" "-o")
        ;;
      *)
        # Generic pattern: use -name
        FIND_EXCLUDES+=("-name" "${pattern}" "-prune" "-o")
        ;;
    esac
  done
}

# ============================================
# Snippet Extraction Functions
# ============================================

# Extract and display file snippet around a specific line
# Usage: extract_snippet <file> <line_num> [context_lines]
extract_snippet() {
  local file="$1"
  local target_line="$2"
  local context="${3:-${SNIPPET_CONTEXT_LINES}}"
  
  # Check if file is readable
  [[ ! -f "$file" || ! -r "$file" ]] && return 1
  
  # Check if file appears to be binary
  if file "$file" 2>/dev/null | grep_cmd -qE 'executable|binary'; then
    say "  ${CYAN}[BINARY FILE - cannot display snippet]${NC}"
    return 0
  fi
  
  local start_line=$((target_line - context))
  local end_line=$((target_line + context))
  
  # Bounds checking
  [[ $start_line -lt 1 ]] && start_line=1
  
  # Extract snippet with line numbers
  local line_num=$start_line
  local display_line
  
  sed -n "${start_line},${end_line}p" "$file" 2>/dev/null | while IFS= read -r line || [[ -n "$line" ]]; do
    # Truncate very long lines
    if [[ "${#line}" -gt "$SNIPPET_MAX_LINE_LENGTH" ]]; then
      display_line="${line:0:$SNIPPET_MAX_LINE_LENGTH}..."
    else
      display_line="$line"
    fi
    
    # Highlight the violation line
    if [[ $line_num -eq $target_line ]]; then
      printf "${CYAN}>> %4d |${NC} %s\n" "$line_num" "$display_line"
    else
      printf "   %4d | %s\n" "$line_num" "$display_line"
    fi
    ((line_num++))
  done
  
  return 0
}

# Get line number where pattern matches (first occurrence)
# Usage: get_violation_line <file> <pattern>
# Returns: line number or empty string
get_violation_line() {
  local file="$1"
  local pattern="$2"
  
  [[ ! -f "$file" || ! -r "$file" ]] && return 1
  
  # Use grep -n to get line number, return first match only
  grep_cmd -n -E "$pattern" "$file" 2>/dev/null | head -1 | cut -d: -f1 || echo ""
}

# Report a finding with optional snippet
# Usage: report_snippet_finding <severity> <title> <file> <pattern> [description]
report_snippet_finding() {
  local severity="$1"
  local title="$2"
  local file="$3"
  local pattern="$4"
  local description="${5:-}"
  
  # Get line number
  local line_num
  line_num="$(get_violation_line "$file" "$pattern")"
  
  if [[ -z "$line_num" ]]; then
    # Fallback: couldn't determine line (pattern may not match exactly)
    sayc "  ${YELLOW}${title}${NC}"
    say "  File: $file"
    [[ -n "$description" ]] && say "  $description"
    return 0
  fi
  
  # Print header with file:line format
  sayc "  ${YELLOW}${title}${NC}"
  say "  File: ${file}:${line_num}"
  say "  ────────────────────────────────────────"
  
  # Print snippet
  extract_snippet "$file" "$line_num" "$SNIPPET_CONTEXT_LINES"
  
  say "  ────────────────────────────────────────"
  
  # Show pattern if enabled
  if [[ "$SNIPPET_SHOW_PATTERN" -eq 1 ]]; then
    say "  Pattern: ${pattern}"
  fi
  
  # Show description if provided
  [[ -n "$description" ]] && say "  ${description}"
  
  say ""
}

# ============================================
# Finding recording & check execution
# ============================================

# Record finding with check id + severity, and keep a compact log line
record_finding() {
  local sev="$1" check_id="$2" msg="$3"
  case "$sev" in
    CRITICAL) CRITICAL=$((CRITICAL+1)) ;;
    HIGH)     HIGH=$((HIGH+1)) ;;
    MEDIUM)   MEDIUM=$((MEDIUM+1)) ;;
    LOW)      LOW=$((LOW+1)) ;;
    *)        LOW=$((LOW+1)) ;;
  esac

  # Add check id once
  local seen=0
  local id
  for id in "${HIT_CHECK_IDS[@]:-}"; do
    [[ "$id" == "$check_id" ]] && seen=1 && break
  done
  [[ "$seen" -eq 0 ]] && HIT_CHECK_IDS+=("$check_id")

  HIT_LINES+=("${sev} ${check_id}: ${msg}")
}

# Run a check body with execution safety (never abort the whole script on a non-zero subcommand)
run_check() {
  local check_id="$1"
  local title="$2"
  shift 2

  hr
  sayc "${PURPLE}${check_id}: ${title}${NC}"
  hr

  if [[ "$TRACE_CHECKS" -eq 1 ]]; then
    sayc "${BLUE}>> ENTER ${check_id}${NC}"
  fi

  # IMPORTANT: turn off -e inside checks so "expected non-zero" doesn't kill the run
  set +e
  "$@"
  local rc=$?
  set -e

  if [[ "$TRACE_CHECKS" -eq 1 ]]; then
    sayc "${BLUE}<< EXIT  ${check_id} (rc=${rc})${NC}"
  fi

  say ""
  return 0
}

usage() {
cat <<EOF
Zimara — Security Audit Script (v$VERSION)

Usage:
  ./zimara.sh [path] [options]

Options:
  -n, --non-interactive   Non-interactive mode (CI-safe). No prompts.
  -o, --only-output       Scan only build output (skip source scanning)
  -v, --verbose           More output detail
  --trace-checks          Print ENTER/EXIT markers for each check (debug)
  --snippet-context N     Lines of context around findings (default: 3)
  --no-snippet-pattern    Don't show regex patterns in output
  --version               Print version and exit
  -h, --help              Show help

Exit Codes:
  0  Success (or user accepted Medium/Low risk)
  1  Medium/Low findings present and user declined (or non-interactive medium/low)
  2  High findings present (blocked)
  3  Critical findings present (blocked)
  99 Usage/input error
EOF
}

# -----------------------------
# Arg parsing
# -----------------------------
if [[ "${1:-}" == "--version" ]]; then
  echo "$VERSION"
  exit 0
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--non-interactive) NON_INTERACTIVE=1; shift ;;
    -o|--only-output) ONLY_OUTPUT=1; shift ;;
    -v|--verbose) VERBOSE=1; shift ;;
    --trace-checks) TRACE_CHECKS=1; shift ;;
    --snippet-context)
      shift
      if [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]]; then
        SNIPPET_CONTEXT_LINES="$1"
        shift
      else
        sayc "${RED} --snippet-context requires a number${NC}"
        exit 99
      fi
      ;;
    --no-snippet-pattern) SNIPPET_SHOW_PATTERN=0; shift ;;
    -h|--help) usage; exit 0 ;;
    -*)
      sayc "${RED} Unknown option: $1${NC}"
      usage
      exit 99 ;;
    *)
      TARGET_DIR="$1"; shift ;;
  esac
done

START_DIR="$(pwd -P 2>/dev/null || pwd)"

if [[ ! -d "$TARGET_DIR" ]]; then
  sayc "${RED} Target directory not found: $TARGET_DIR${NC}"
  exit 99
fi

# Canonicalize the target (resolves symlinks) and validate we landed where intended.
TARGET_DIR_CANON="$(cd "$TARGET_DIR" 2>/dev/null && pwd -P)" || {
  sayc "${RED} Cannot access directory: $TARGET_DIR${NC}"
  exit 99
}

# Guardrails: avoid scanning sensitive system locations by accident or via symlink tricks.
# Allowed: current working tree, user home, /tmp, and common dev roots.
case "$TARGET_DIR_CANON" in
  "$START_DIR"/*|"$START_DIR"|"${HOME:-/nonexistent}"/*|/home/*|/Users/*|/tmp/*)
    ;;
  *)
    sayc "${RED} Refusing to scan outside allowed paths: $TARGET_DIR_CANON${NC}"
    sayc "${YELLOW}   Tip: run Zimara from inside the repo, or pass a path under your home directory.${NC}"
    exit 99
    ;;
esac

[[ "$TARGET_DIR_CANON" != "/" ]] || { sayc "${RED} Refusing to scan filesystem root '/'${NC}"; exit 99; }

cd "$TARGET_DIR_CANON" || { sayc "${RED} Cannot access directory: $TARGET_DIR_CANON${NC}"; exit 99; }

sayc "${BLUE}  Resolved scan path: ${TARGET_DIR_CANON}${NC}"
say ""

detect_generator() {
  if [[ -f "hugo.toml" || -f "config.toml" || -f "config.yaml" || -f "config.yml" ]]; then
    GENERATOR="hugo"; OUTPUT_DIR="public"
  elif [[ -f "_config.yml" || -f "_config.yaml" ]]; then
    GENERATOR="jekyll"; OUTPUT_DIR="_site"
  elif [[ -f "astro.config.mjs" || -f "astro.config.ts" ]]; then
    GENERATOR="astro"; OUTPUT_DIR="dist"
  elif [[ -f "eleventy.config.js" || -f ".eleventy.js" ]]; then
    GENERATOR="eleventy"; OUTPUT_DIR="_site"
  elif [[ -f "next.config.js" || -f "next.config.mjs" || -f "next.config.ts" ]]; then
    GENERATOR="next"; OUTPUT_DIR="out"
  else
    GENERATOR="generic"
    if [[ -d "public" ]]; then OUTPUT_DIR="public"
    elif [[ -d "dist" ]]; then OUTPUT_DIR="dist"
    elif [[ -d "_site" ]]; then OUTPUT_DIR="_site"
    elif [[ -d "out" ]]; then OUTPUT_DIR="out"
    else OUTPUT_DIR="" ; fi
  fi
}

detect_generator

# Load .zimaraignore patterns immediately after generator detection
load_zimaraignore
build_grep_excludes
build_find_prunes

OUTPUT_SCAN_DIR=""
[[ -n "${OUTPUT_DIR}" && -d "${OUTPUT_DIR}" ]] && OUTPUT_SCAN_DIR="${OUTPUT_DIR}"

hr
sayc "${PURPLE}Zimara (v${VERSION}) — Published by Oob Skulden™ — generator: ${GENERATOR}${NC}"
hr
say "Directory scanned: $(pwd)"
say "Output dir detected: ${OUTPUT_SCAN_DIR:-"(none)"}"
say "Snippet context: ${SNIPPET_CONTEXT_LINES} lines"
say ""

prompt_continue() {
  local msg="$1"
  [[ "$NON_INTERACTIVE" -eq 1 ]] && return 1
  read -r -p "$msg (y/N): " ans
  [[ "${ans:-N}" =~ ^[Yy]$ ]]
}

# ---------------------------------
# Checks (01–45)
# ---------------------------------

check_01_repo() {
  if [[ -d ".git" ]]; then
    sayc "${GREEN} Git repo detected${NC}"
  else
    sayc "${YELLOW}  No .git directory found (still scanning files) [LOW]${NC}"
    record_finding "LOW" "CHECK 01" "No .git directory found"
  fi
}

check_02_gitignore() {
  if [[ -f ".gitignore" ]]; then
    sayc "${GREEN} .gitignore present${NC}"
  else
    sayc "${YELLOW}  Missing .gitignore [LOW]${NC}"
    record_finding "LOW" "CHECK 02" "Missing .gitignore"
    say "Actions:"
    say "  • Add a .gitignore to prevent committing secrets/build artifacts"
  fi
}

check_03_private_keys() {
  if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
    sayc "${BLUE}  Source scanning disabled (--only-output)${NC}"
    return 0
  fi

  local pattern='BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY'
  local tmpf
  tmpf="$(tmpfile private-keys-hits)"
  
  # Find files containing private key blocks
  find_cmd . \
    \( -path "./.git" -o -path "./node_modules" -o -path "./vendor" \) -prune -o \
    "${FIND_EXCLUDES[@]}" \
    -type f -maxdepth 6 -print0 2>/dev/null \
    | xargs_cmd -0 grep_cmd -l -E "$pattern" 2>/dev/null > "$tmpf" || true

  if [[ -s "$tmpf" ]]; then
    sayc "${RED} CRITICAL: Private key material detected${NC}"
    record_finding "CRITICAL" "CHECK 03" "Private key block(s) detected"
    say ""
    
    # Show snippets for first 5 files
    local count=0
    while IFS= read -r file && [[ $count -lt 5 ]]; do
      report_snippet_finding "CRITICAL" "Private Key in: $file" "$file" "$pattern" \
        "Action: Remove immediately and rotate credentials"
      count=$((count + 1))
    done < "$tmpf"
    
    # If more than 5, show count
    local total
    total="$(wc -l < "$tmpf" | tr -d ' ')"
    if [[ $total -gt 5 ]]; then
      say "  ... and $((total - 5)) more file(s) with private keys"
      say ""
    fi
  else
    sayc "${GREEN} No private key blocks found${NC}"
  fi
}

check_04_secret_patterns() {
  if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
    sayc "${BLUE}  Source scanning disabled (--only-output)${NC}"
    return 0
  fi

  local pattern='(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,}|ghp_[0-9A-Za-z]{30,}|github_pat_[0-9A-Za-z_]{20,}|AIza[0-9A-Za-z\-_]{35}|-----BEGIN PRIVATE KEY-----|SECRET_KEY=|AWS_SECRET_ACCESS_KEY|BEGIN OPENSSH PRIVATE KEY)'
  
  local tmpf
  tmpf="$(tmpfile secret-patterns)"
  
  safe_grep -RIn \
    --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" \
    --exclude="*.min.js" --exclude="*.map" \
    "${GREP_EXCLUDES[@]}" \
    -E "$pattern" . > "$tmpf" || true

  if [[ -s "$tmpf" ]]; then
    sayc "${YELLOW}  Possible secrets detected [HIGH]${NC}"
    record_finding "HIGH" "CHECK 04" "Possible secret patterns detected"
    say ""
    
    # Group by file and show snippets
    local shown=0
    local current_file=""
    
    while IFS=: read -r file line_num matched_text && [[ $shown -lt 10 ]]; do
      if [[ "$file" != "$current_file" ]]; then
        current_file="$file"
        report_snippet_finding "HIGH" "Possible Secret" "$file" "$pattern" \
          "Action: Remove secret, rotate credentials, use env vars/secret manager"
        shown=$((shown + 1))
      fi
    done < "$tmpf"
    
    say "Actions:"
    say "  • Remove secrets from source"
    say "  • Rotate exposed credentials"
    say "  • Use env vars / secret manager"
  else
    sayc "${GREEN} No obvious secret patterns found${NC}"
  fi
}

check_05_backup_artifacts() {
  if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
    sayc "${BLUE}  Source scanning disabled (--only-output)${NC}"
    return 0
  fi

  local hits
  hits="$(find_cmd . \
    \( -path "./.git" -o -path "./node_modules" -o -path "./vendor" \) -prune -o \
    "${FIND_EXCLUDES[@]}" \
    -type f \( -name "*.bak" -o -name "*.old" -o -name "*.backup" -o -name "*.tmp" -o -name "*~" \) \
    -print 2>/dev/null | head -n 10 || true)"

  if [[ -n "${hits}" ]]; then
    sayc "${YELLOW}  Backup/temp artifacts present [MEDIUM]${NC}"
    record_finding "MEDIUM" "CHECK 05" "Backup/temp artifacts present"
    echo "${hits}"
    say "Actions:"
    say "  • Delete or add to .gitignore"
  else
    sayc "${GREEN} No backup/temp artifacts found${NC}"
  fi
}

check_06_dotenv_files() {
  local hits
  hits="$(find_cmd . \
    \( -path "./.git" -o -path "./node_modules" -o -path "./vendor" \) -prune -o \
    "${FIND_EXCLUDES[@]}" \
    -type f \( -name ".env" -o -name ".env.*" -o -name "*.env" \) -print 2>/dev/null | head -n 10 || true)"

  if [[ -n "${hits}" ]]; then
    sayc "${YELLOW}  .env-style files detected [MEDIUM]${NC}"
    record_finding "MEDIUM" "CHECK 06" ".env-style files detected"
    echo "${hits}"
    say "Actions:"
    say "  • Ensure .env files are not committed and are gitignored"
  else
    sayc "${GREEN} No .env files detected${NC}"
  fi
}

check_07_output_exposure() {
  if [[ -z "${OUTPUT_SCAN_DIR}" ]]; then
    sayc "${BLUE}  No build output directory detected${NC}"
    return 0
  fi

  if [[ -d "${OUTPUT_SCAN_DIR}/.git" ]]; then
    sayc "${RED} CRITICAL: Output contains .git directory${NC}"
    record_finding "CRITICAL" "CHECK 07" "Output contains .git directory"
    say "Actions:"
    say "  • Ensure build output does not include .git"
    say "  • Clean output directory and rebuild"
  else
    sayc "${GREEN} No .git directory inside output${NC}"
  fi

  local pattern='BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY'
  local tmpf
  tmpf="$(tmpfile output-keys)"
  
  find_cmd "${OUTPUT_SCAN_DIR}" -type f -maxdepth 6 -print0 2>/dev/null \
    | xargs_cmd -0 grep_cmd -l -E "$pattern" 2>/dev/null > "$tmpf" || true

  if [[ -s "$tmpf" ]]; then
    sayc "${RED} CRITICAL: Output contains private key material${NC}"
    record_finding "CRITICAL" "CHECK 07" "Output contains private key material"
    say ""
    
    while IFS= read -r file; do
      report_snippet_finding "CRITICAL" "Private Key in Output" "$file" "$pattern"
    done < <(head -5 "$tmpf")
  fi
}

check_08_mixed_content_output() {
  if [[ -z "${OUTPUT_SCAN_DIR}" ]]; then
    sayc "${BLUE}  No build output directory detected${NC}"
    return 0
  fi

  local pattern='(href="http://|src="http://|url\("http://)'
  local tmpf
  tmpf="$(tmpfile mixed-content)"
  
  safe_grep -RIn --exclude="*.map" -E "$pattern" "${OUTPUT_SCAN_DIR}" > "$tmpf" || true
  
  if [[ -s "$tmpf" ]]; then
    sayc "${YELLOW}  Mixed content references found [MEDIUM]${NC}"
    record_finding "MEDIUM" "CHECK 08" "Mixed content references in output"
    say ""
    
    # Show first occurrence in each file
    local shown=0
    local current_file=""
    while IFS=: read -r file line_num matched && [[ $shown -lt 5 ]]; do
      if [[ "$file" != "$current_file" ]]; then
        current_file="$file"
        report_snippet_finding "MEDIUM" "Mixed Content" "$file" "$pattern" \
          "Action: Use https:// resources to avoid downgrade and blocking"
        shown=$((shown + 1))
      fi
    done < "$tmpf"
  else
    sayc "${GREEN} No mixed content references found${NC}"
  fi
}

check_09_netlify_config_present() {
  if [[ -f "netlify.toml" ]]; then
    sayc "${GREEN} netlify.toml detected${NC}"
  else
    sayc "${BLUE}  netlify.toml not found (ok if not using Netlify)${NC}"
  fi
}

check_10_netlify_headers_basic() {
  if [[ ! -f "netlify.toml" ]]; then
    sayc "${BLUE}  netlify.toml not found${NC}"
    return 0
  fi

  local hsts xcto
  hsts="$(safe_grep -nE 'Strict-Transport-Security' netlify.toml | head -n 1)"
  xcto="$(safe_grep -nE 'X-Content-Type-Options' netlify.toml | head -n 1)"

  if [[ -z "${hsts}" ]]; then
    sayc "${YELLOW}  Missing HSTS header in netlify.toml [LOW]${NC}"
    record_finding "LOW" "CHECK 10" "Missing HSTS header"
  else
    sayc "${GREEN} HSTS present${NC}"
  fi

  if [[ -z "${xcto}" ]]; then
    sayc "${YELLOW}  Missing X-Content-Type-Options header in netlify.toml [LOW]${NC}"
    record_finding "LOW" "CHECK 10" "Missing X-Content-Type-Options header"
  else
    sayc "${GREEN} X-Content-Type-Options present${NC}"
  fi
}

check_11_github_dir() {
  if [[ -d ".github" ]]; then
    sayc "${GREEN} .github directory present${NC}"
  else
    sayc "${BLUE}  .github directory not found${NC}"
  fi
}

check_12_gitleaks_optional() {
  if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
    sayc "${BLUE}  Source scanning disabled (--only-output)${NC}"
    return 0
  fi

  if ! _has_cmd gitleaks; then
    sayc "${BLUE}  gitleaks not installed (skipping)${NC}"
    return 0
  fi

  # If not a git repo, skip to avoid confusing failures
  if [[ ! -d ".git" ]]; then
    sayc "${BLUE}  Skipping gitleaks (not a git repository)${NC}"
    return 0
  fi

  local report rc
  report="$(tmpfile gitleaks-report .json)"

  # gitleaks returns non-zero for findings; treat that as HIGH with actionable guidance.
  gitleaks_cmd detect --source . --report-format json --report-path "${report}" >/dev/null 2>&1
  rc=$?

  if [[ "$rc" -ne 0 ]]; then
    # If report file exists and is non-empty, it likely found findings.
    if [[ -s "${report}" ]]; then
      sayc "${YELLOW}  gitleaks reported potential secrets [HIGH]${NC}"
      record_finding "HIGH" "CHECK 12" "gitleaks findings (see report)"
      say "Actions:"
      say "  • Review report: ${report}"
      say "  • Remove secrets and rotate credentials"
    else
      sayc "${BLUE}  gitleaks ran but produced no report (debug needed)${NC}"
      record_finding "LOW" "CHECK 12" "gitleaks execution issue (no report)"
      say "Actions:"
      say "  • Debug: gitleaks detect --source . -v"
    fi
  else
    sayc "${GREEN} gitleaks found no issues${NC}"
  fi
}

check_13_detect_secrets_optional() {
  if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
    sayc "${BLUE}  Source scanning disabled (--only-output)${NC}"
    return 0
  fi
  if ! _has_cmd detect-secrets; then
    sayc "${BLUE}  detect-secrets not installed (skipping)${NC}"
    return 0
  fi

  local baseline rc
  baseline="$(tmpfile secrets-baseline .json)"
  detect_secrets_cmd scan --all-files > "${baseline}" 2>/dev/null
  rc=$?

  if [[ "$rc" -ne 0 ]]; then
    sayc "${BLUE}  detect-secrets returned non-zero (tooling issue) [LOW]${NC}"
    record_finding "LOW" "CHECK 13" "detect-secrets returned non-zero"
    say "Actions:"
    say "  • Run: detect-secrets scan --all-files -v"
  else
    sayc "${GREEN} detect-secrets baseline generated${NC}"
    [[ "$VERBOSE" -eq 1 ]] && say "Baseline: ${baseline}"
  fi
}

check_14_npm_audit_optional() {
  if [[ ! -f "package.json" ]]; then
    sayc "${BLUE}  No package.json detected${NC}"
    return 0
  fi
  if ! _has_cmd npm; then
    sayc "${BLUE}  npm not installed (skipping)${NC}"
    return 0
  fi

  npm_cmd audit --audit-level=high >/dev/null 2>&1
  local rc=$?
  if [[ "$rc" -ne 0 ]]; then
    sayc "${YELLOW}  npm audit reports issues (>= high) [MEDIUM]${NC}"
    record_finding "MEDIUM" "CHECK 14" "npm audit issues (>= high)"
    say "Actions:"
    say "  • Run: npm audit"
    say "  • Update dependencies / apply fixes"
  else
    sayc "${GREEN} npm audit clean at high threshold${NC}"
  fi
}

check_15_worktree_clean() {
  if [[ ! -d ".git" ]] || ! _has_cmd git; then
    sayc "${BLUE}  Not a git repo or git not available${NC}"
    return 0
  fi
  local st
  st="$(git_cmd status --porcelain 2>/dev/null || true)"
  if [[ -n "${st}" ]]; then
    sayc "${BLUE}  Uncommitted changes detected (ok)${NC}"
  else
    sayc "${GREEN} Working tree clean${NC}"
  fi
}

check_16_risky_debug_output() {
  if [[ -z "${OUTPUT_SCAN_DIR}" ]]; then
    sayc "${BLUE}  No build output directory detected${NC}"
    return 0
  fi
  local hits
  hits="$(find_cmd "${OUTPUT_SCAN_DIR}" -type f \( -name "debug.log" -o -name "phpinfo.php" -o -name "*.sql" \) -print 2>/dev/null | head -n 10 || true)"
  if [[ -n "${hits}" ]]; then
    sayc "${YELLOW}  Risky debug artifacts found in output [HIGH]${NC}"
    record_finding "HIGH" "CHECK 16" "Risky debug artifacts in output"
    echo "${hits}"
    say "Actions:"
    say "  • Remove debug artifacts"
    say "  • Ensure build pipeline excludes them"
  else
    sayc "${GREEN} No risky debug artifacts in output${NC}"
  fi
}

check_17_git_history_sensitive_ext() {
  if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
    sayc "${BLUE}  Source scanning disabled (--only-output)${NC}"
    return 0
  fi
  if [[ ! -d ".git" ]] || ! _has_cmd git; then
    sayc "${BLUE}  Not a git repo or git not available (skipping)${NC}"
    return 0
  fi

  local count tmpf
  tmpf="$(tmpfile git-history-check)"
  
  # Write matching filenames to temp file
  git_cmd log --all --oneline --name-only 2>/dev/null \
    | grep_cmd -E '\.(env|key|pem|p12|pfx|backup|bak)$' 2>/dev/null \
    > "${tmpf}" || true
  
  # Count lines in the temp file
  count="$(wc -l < "${tmpf}" 2>/dev/null | tr -d ' ')"

  if [[ "${count:-0}" -gt 0 ]]; then
    sayc "${YELLOW}  Found ${count} sensitive-file reference(s) in git history [MEDIUM]${NC}"
    record_finding "MEDIUM" "CHECK 17" "Sensitive file extensions referenced in git history"
    say "Actions:"
    say "  • Secrets may remain in history even if deleted"
    say "  • Use git filter-repo/BFG to purge, then rotate secrets"
  else
    sayc "${GREEN}  No sensitive file extensions found in git history${NC}"
  fi
}

check_18_git_remote_http() {
  if [[ ! -d ".git" ]] || ! _has_cmd git; then
    sayc "${BLUE}  Not a git repo or git not available${NC}"
    return 0
  fi
  local rem
  rem="$(git_cmd remote -v 2>/dev/null || true)"
  if echo "$rem" | grep_cmd -qiE 'http://'; then
    sayc "${YELLOW}  Git remotes use http:// (insecure) [MEDIUM]${NC}"
    record_finding "MEDIUM" "CHECK 18" "Insecure git remote (http://)"
    echo "$rem" | grep_cmd -iE 'http://' 2>/dev/null || true
    say "Actions:"
    say "  • Switch to https:// or ssh (git@...) remotes"
  else
    sayc "${GREEN} No http:// git remotes detected${NC}"
  fi
}

check_19_sensitive_filenames() {
  if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
    sayc "${BLUE}  Source scanning disabled (--only-output)${NC}"
    return 0
  fi

  local hits
  hits="$(find_cmd . \
    \( -path "./.git" -o -path "./node_modules" -o -path "./vendor" \) -prune -o \
    "${FIND_EXCLUDES[@]}" \
    -type f \( -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" \) \
    -print 2>/dev/null | head -n 10 || true)"

  if [[ -n "${hits}" ]]; then
    sayc "${YELLOW}  Sensitive key/cert filenames detected [HIGH]${NC}"
    record_finding "HIGH" "CHECK 19" "Sensitive key/cert filenames present"
    echo "${hits}"
    say "Actions:"
    say "  • Remove and rotate credentials if exposed"
    say "  • Add to .gitignore"
  else
    sayc "${GREEN} No obvious key/cert filenames found${NC}"
  fi
}

check_20_output_js_key_exposure() {
  if [[ -z "${OUTPUT_SCAN_DIR}" ]]; then
    sayc "${BLUE}  No build output directory detected${NC}"
    return 0
  fi
  
  local pattern='(AIza[0-9A-Za-z\-_]{35}|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,}|ghp_[0-9A-Za-z]{30,})'
  local tmpf
  tmpf="$(tmpfile output-keys-check)"
  
  safe_grep -RIn --exclude="*.map" -E "$pattern" "${OUTPUT_SCAN_DIR}" > "$tmpf" || true
  
  if [[ -s "$tmpf" ]]; then
    sayc "${YELLOW}  Possible API keys found in output JS/HTML [HIGH]${NC}"
    record_finding "HIGH" "CHECK 20" "Possible keys in output bundles"
    say ""
    
    local shown=0
    local current_file=""
    while IFS=: read -r file line_num matched && [[ $shown -lt 5 ]]; do
      if [[ "$file" != "$current_file" ]]; then
        current_file="$file"
        report_snippet_finding "HIGH" "Possible API Key in Bundle" "$file" "$pattern" \
          "Action: Remove keys from client-side bundles, use server-side injection"
        shown=$((shown + 1))
      fi
    done < "$tmpf"
  else
    sayc "${GREEN} No obvious keys in output bundles${NC}"
  fi
}

# 21–33 are mostly posture and hygiene; keep them low-noise
check_21_netlify_redirects_hint() {
  if [[ -f "netlify.toml" ]]; then
    if safe_grep -qE 'status\s*=\s*30[12]' netlify.toml; then
      sayc "${GREEN} Redirect rules detected${NC}"
    else
      sayc "${BLUE}  No redirect rules detected${NC}"
    fi
  else
    sayc "${BLUE}  netlify.toml not found${NC}"
  fi
}

check_22_cname() {
  if [[ -f "CNAME" ]]; then
    sayc "${GREEN} CNAME file found${NC}"
  else
    sayc "${BLUE}  No CNAME file found${NC}"
  fi
}

check_23_htaccess() {
  local hits
  hits="$(find_cmd . -maxdepth 4 -type f -name ".htaccess" -print 2>/dev/null | head -n 5 || true)"
  if [[ -n "${hits}" ]]; then
    sayc "${BLUE}  .htaccess found (verify rules are safe) [LOW]${NC}"
    record_finding "LOW" "CHECK 23" ".htaccess present"
    echo "${hits}"
  else
    sayc "${GREEN} No .htaccess files found${NC}"
  fi
}

check_24_exposed_configs_output() {
  if [[ -z "${OUTPUT_SCAN_DIR}" ]]; then
    sayc "${BLUE}  No build output directory detected${NC}"
    return 0
  fi
  local hits
  hits="$(find_cmd "${OUTPUT_SCAN_DIR}" -type f \
    \( -name ".env" -o -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" -o -name "*.bak" -o -name "*.old" \) \
    -print 2>/dev/null | head -n 10 || true)"
  if [[ -n "${hits}" ]]; then
    sayc "${RED} CRITICAL: Sensitive config/key artifacts in output${NC}"
    record_finding "CRITICAL" "CHECK 24" "Sensitive artifacts in output"
    echo "${hits}"
    say "Actions:"
    say "  • Remove from output and fix build exclusions"
  else
    sayc "${GREEN} No exposed config/key artifacts in output${NC}"
  fi
}

check_25_netlify_env_leak() {
  if [[ ! -f "netlify.toml" ]]; then
    sayc "${BLUE}  netlify.toml not found${NC}"
    return 0
  fi
  
  local pattern='(API_KEY|SECRET|TOKEN|PASSWORD)\s*='
  local tmpf
  tmpf="$(tmpfile netlify-secrets)"
  
  safe_grep -n -E "$pattern" netlify.toml > "$tmpf" || true
  
  if [[ -s "$tmpf" ]]; then
    sayc "${YELLOW}  Possible secrets in netlify.toml [HIGH]${NC}"
    record_finding "HIGH" "CHECK 25" "Possible secrets in netlify.toml"
    say ""
    
    report_snippet_finding "HIGH" "Possible Secret in Config" "netlify.toml" "$pattern" \
      "Action: Move secrets to Netlify environment variables / secret store"
  else
    sayc "${GREEN} No obvious secrets in netlify.toml${NC}"
  fi
}

check_26_hugo_modules() {
  if [[ "$GENERATOR" != "hugo" ]]; then
    sayc "${BLUE}  Not Hugo (skipping)${NC}"
    return 0
  fi
  if [[ -f "go.mod" ]]; then
    sayc "${GREEN} go.mod present (modules in use)${NC}"
  else
    sayc "${BLUE}  go.mod not found (modules may not be used)${NC}"
  fi
}

check_27_jekyll_plugins() {
  if [[ "$GENERATOR" != "jekyll" ]]; then
    sayc "${BLUE}  Not Jekyll (skipping)${NC}"
    return 0
  fi
  if [[ -f "_config.yml" ]] && safe_grep -qE '^plugins:' _config.yml; then
    sayc "${BLUE}  Jekyll plugins configured (verify trusted) [LOW]${NC}"
    record_finding "LOW" "CHECK 27" "Jekyll plugins configured"
    safe_grep -nE '^plugins:' -A 20 _config.yml | head -n 25
  else
    sayc "${GREEN} No plugins section detected in Jekyll config${NC}"
  fi
}

check_28_astro_integrations() {
  if [[ "$GENERATOR" != "astro" ]]; then
    sayc "${BLUE}  Not Astro (skipping)${NC}"
    return 0
  fi
  local hits
  hits="$(safe_grep -RIn -E 'integrations\s*:\s*\[' astro.config.* | head -n 10)"
  if [[ -n "${hits}" ]]; then
    sayc "${BLUE}  Astro integrations detected (verify trusted) [LOW]${NC}"
    record_finding "LOW" "CHECK 28" "Astro integrations detected"
    echo "${hits}"
  else
    sayc "${GREEN} No obvious integrations array found${NC}"
  fi
}

check_29_eleventy_eval() {
  if [[ "$GENERATOR" != "eleventy" ]]; then
    sayc "${BLUE}  Not Eleventy (skipping)${NC}"
    return 0
  fi
  local hits
  hits="$(safe_grep -RIn --exclude-dir=".git" --exclude-dir="node_modules" -E 'eval\(|Function\(' . | head -n 10)"
  if [[ -n "${hits}" ]]; then
    sayc "${YELLOW}  Potential eval/Function usage found [MEDIUM]${NC}"
    record_finding "MEDIUM" "CHECK 29" "eval/Function usage detected"
    echo "${hits}"
    say "Actions:"
    say "  • Avoid eval/Function in build tooling where possible"
  else
    sayc "${GREEN} No eval/Function usage detected (heuristic)${NC}"
  fi
}

check_30_next_export() {
  if [[ "$GENERATOR" != "next" ]]; then
    sayc "${BLUE}  Not Next.js (skipping)${NC}"
    return 0
  fi
  if [[ -d "out" ]]; then
    sayc "${GREEN} out/ directory present (export output)${NC}"
  else
    sayc "${BLUE}  out/ not found (may not be exported build)${NC}"
  fi
}

check_31_large_files() {
  local hits
  hits="$(find_cmd . \
    \( -path "./.git" -o -path "./node_modules" -o -path "./vendor" \) -prune -o \
    "${FIND_EXCLUDES[@]}" \
    -type f -size +20M -print 2>/dev/null | head -n 10 || true)"
  if [[ -n "${hits}" ]]; then
    sayc "${YELLOW}  Large files detected (>20MB) [LOW]${NC}"
    record_finding "LOW" "CHECK 31" "Large files >20MB present"
    echo "${hits}"
    say "Actions:"
    say "  • Consider Git LFS or exclude from repo"
  else
    sayc "${GREEN} No large files detected${NC}"
  fi
}

check_32_precommit_hook() {
  if [[ -f ".git/hooks/pre-commit" ]]; then
    sayc "${GREEN} .git/hooks/pre-commit present${NC}"
  else
    sayc "${BLUE}  No pre-commit hook found${NC}"
  fi
}

check_33_readme() {
  if [[ -f "README.md" || -f "readme.md" ]]; then
    sayc "${GREEN} README present${NC}"
  else
    sayc "${BLUE}  No README found${NC}"
  fi
}

# Added checks (34–45)
check_34_actions_footguns() {
  if [[ ! -d ".github/workflows" ]]; then
    sayc "${BLUE}  No .github/workflows directory${NC}"
    return 0
  fi
  
  local pattern='(pull_request_target|curl[^|]*\|\s*(bash|sh)|wget[^|]*\|\s*(bash|sh)|\bset\s+-x\b|\benv\s*\||\bprintenv\b|secrets\.)'
  local tmpf
  tmpf="$(tmpfile workflow-footguns)"
  
  safe_grep -RIn -E "$pattern" .github/workflows > "$tmpf" || true
  
  if [[ -s "$tmpf" ]]; then
    sayc "${YELLOW}  Potential workflow foot-guns detected [MEDIUM]${NC}"
    record_finding "MEDIUM" "CHECK 34" "Workflow foot-guns detected (heuristic)"
    say ""
    
    # Show first few unique files
    local shown=0
    local current_file=""
    while IFS=: read -r file line_num matched && [[ $shown -lt 3 ]]; do
      if [[ "$file" != "$current_file" ]]; then
        current_file="$file"
        report_snippet_finding "MEDIUM" "Workflow Foot-gun" "$file" "$pattern"
        shown=$((shown + 1))
      fi
    done < "$tmpf"
    
    say "Actions:"
    say "  • Avoid pull_request_target unless you fully understand trust boundaries"
    say "  • Avoid curl|bash / wget|bash patterns"
    say "  • Avoid echoing env/secrets into logs"
  else
    sayc "${GREEN} No common workflow foot-guns detected (heuristic)${NC}"
  fi
}

check_35_actions_pinning_permissions() {
  if [[ ! -d ".github/workflows" ]]; then
    sayc "${BLUE}  No .github/workflows directory${NC}"
    return 0
  fi

  local unpinned writeall hasperms
  unpinned="$(safe_grep -RIn -E '^\s*uses:\s*[^#]+@([A-Za-z0-9_.-]+)\s*$' .github/workflows \
    | grep_cmd -v -E '@[0-9a-f]{40}\b' 2>/dev/null \
    | grep_cmd -v -E 'uses:\s*\./' 2>/dev/null \
    | head -n 50 || true)"

  writeall="$(safe_grep -RIn -E '^\s*permissions:\s*write-all\b' .github/workflows | head -n 20)"
  hasperms="$(safe_grep -RIn -E '^\s*permissions:\s*$' .github/workflows | head -n 5)"

  if [[ -n "${unpinned}" ]]; then
    sayc "${YELLOW}  Actions not pinned to commit SHA [MEDIUM]${NC}"
    record_finding "MEDIUM" "CHECK 35" "Unpinned GitHub Actions detected"
    echo "${unpinned}"
    say "Actions:"
    say "  • Pin actions to full commit SHAs (supply chain hardening)"
  else
    sayc "${GREEN} Actions appear pinned (heuristic)${NC}"
  fi

  if [[ -n "${writeall}" ]]; then
    sayc "${YELLOW}  permissions: write-all detected [MEDIUM]${NC}"
    record_finding "MEDIUM" "CHECK 35" "permissions: write-all detected"
    echo "${writeall}"
    say "Actions:"
    say "  • Use least-privilege permissions (e.g., contents: read)"
  fi

  if [[ -z "${hasperms}" ]]; then
    sayc "${YELLOW}  No explicit permissions block found (defaults may be broader than intended) [LOW]${NC}"
    record_finding "LOW" "CHECK 35" "No explicit permissions block in workflows"
    say "Actions:"
    say "  • Add a top-level permissions: block to workflows"
  else
    sayc "${GREEN} permissions: block detected in workflows${NC}"
  fi
}

check_36_lockfile() {
  if [[ ! -f "package.json" ]]; then
    sayc "${BLUE}  No package.json detected${NC}"
    return 0
  fi
  if [[ -f "package-lock.json" || -f "pnpm-lock.yaml" || -f "yarn.lock" ]]; then
    sayc "${GREEN} Lockfile present${NC}"
  else
    sayc "${YELLOW}  package.json present but no lockfile found [MEDIUM]${NC}"
    record_finding "MEDIUM" "CHECK 36" "No lockfile found"
    say "Actions:"
    say "  • Commit a lockfile (package-lock.json / pnpm-lock.yaml / yarn.lock)"
    say "  • This reduces supply-chain drift and improves reproducibility"
  fi
}

check_37_security_txt() {
  local found=0
  [[ -f ".well-known/security.txt" || -f "security.txt" ]] && found=1
  if [[ -n "${OUTPUT_SCAN_DIR}" ]]; then
    [[ -f "${OUTPUT_SCAN_DIR}/.well-known/security.txt" || -f "${OUTPUT_SCAN_DIR}/security.txt" ]] && found=1
  fi
  if [[ "${found}" -eq 1 ]]; then
    sayc "${GREEN} security.txt detected${NC}"
  else
    sayc "${YELLOW}  security.txt not found [LOW]${NC}"
    record_finding "LOW" "CHECK 37" "security.txt missing"
    say "Actions:"
    say "  • Add /.well-known/security.txt with a contact for vulnerability reports"
  fi
}

check_38_csp_quality() {
  if [[ ! -f "netlify.toml" ]]; then
    sayc "${BLUE}  netlify.toml not found${NC}"
    return 0
  fi
  local csp
  csp="$(safe_grep -n -E 'Content-Security-Policy' netlify.toml | head -n 3)"
  if [[ -z "${csp}" ]]; then
    sayc "${YELLOW}  No Content-Security-Policy header found [LOW]${NC}"
    record_finding "LOW" "CHECK 38" "CSP missing"
    say "Actions:"
    say "  • Add a CSP header (even a basic one) to reduce XSS impact"
  else
    sayc "${GREEN} CSP header found${NC}"
    if echo "${csp}" | grep_cmd -qi -E 'unsafe-inline|unsafe-eval' 2>/dev/null; then
      sayc "${YELLOW}  CSP includes unsafe-inline/unsafe-eval (review) [LOW]${NC}"
      record_finding "LOW" "CHECK 38" "CSP includes unsafe-*"
      echo "${csp}"
      say "Actions:"
      say "  • Remove unsafe-* where possible; use nonces/hashes"
    fi
  fi
}

check_39_browser_headers() {
  if [[ ! -f "netlify.toml" ]]; then
    sayc "${BLUE}  netlify.toml not found${NC}"
    return 0
  fi

  local rp pp coop coep
  rp="$(safe_grep -n -E 'Referrer-Policy' netlify.toml | head -n 1)"
  pp="$(safe_grep -n -E 'Permissions-Policy' netlify.toml | head -n 1)"
  coop="$(safe_grep -n -E 'Cross-Origin-Opener-Policy' netlify.toml | head -n 1)"
  coep="$(safe_grep -n -E 'Cross-Origin-Embedder-Policy' netlify.toml | head -n 1)"

  [[ -z "${rp}" ]] && sayc "${YELLOW}  Missing Referrer-Policy [LOW]${NC}" && record_finding "LOW" "CHECK 39" "Referrer-Policy missing" || sayc "${GREEN} Referrer-Policy present${NC}"
  [[ -z "${pp}" ]] && sayc "${YELLOW}  Missing Permissions-Policy [LOW]${NC}" && record_finding "LOW" "CHECK 39" "Permissions-Policy missing" || sayc "${GREEN} Permissions-Policy present${NC}"
  [[ -z "${coop}" ]] && sayc "${YELLOW}  Missing Cross-Origin-Opener-Policy [LOW]${NC}" && record_finding "LOW" "CHECK 39" "COOP missing" || sayc "${GREEN} COOP present${NC}"
  [[ -z "${coep}" ]] && sayc "${YELLOW}  Missing Cross-Origin-Embedder-Policy [LOW]${NC}" && record_finding "LOW" "CHECK 39" "COEP missing" || sayc "${GREEN} COEP present${NC}"

  say "Actions:"
  say "  • Consider adding missing headers to strengthen browser isolation"
}

check_40_robots_sitemap() {
  if [[ -z "${OUTPUT_SCAN_DIR}" ]]; then
    sayc "${BLUE}  No build output directory detected${NC}"
    return 0
  fi
  if [[ -f "${OUTPUT_SCAN_DIR}/robots.txt" ]]; then
    sayc "${GREEN} robots.txt found in output${NC}"
  else
    sayc "${YELLOW}  robots.txt not found in output [LOW]${NC}"
    record_finding "LOW" "CHECK 40" "robots.txt missing in output"
    say "Actions:"
    say "  • Add robots.txt to control indexing (especially for staging/drafts)"
  fi

  if [[ -f "${OUTPUT_SCAN_DIR}/sitemap.xml" ]]; then
    local pattern='(draft|internal|admin|/\.env|/\.git)'
    local bad
    bad="$(safe_grep -n -E "$pattern" "${OUTPUT_SCAN_DIR}/sitemap.xml" | head -n 20)"
    if [[ -n "${bad}" ]]; then
      sayc "${YELLOW}  sitemap.xml includes potentially sensitive paths [MEDIUM]${NC}"
      record_finding "MEDIUM" "CHECK 40" "Sensitive paths in sitemap.xml"
      say ""
      report_snippet_finding "MEDIUM" "Sensitive Path in Sitemap" "${OUTPUT_SCAN_DIR}/sitemap.xml" "$pattern" \
        "Action: Exclude drafts/admin/internal paths from sitemap generation"
    else
      sayc "${GREEN} sitemap.xml looks sane (heuristic)${NC}"
    fi
  else
    sayc "${BLUE}  sitemap.xml not found in output${NC}"
  fi
}

check_41_storage_endpoints() {
  if [[ -z "${OUTPUT_SCAN_DIR}" ]]; then
    sayc "${BLUE}  No build output directory detected${NC}"
    return 0
  fi
  local hits
  hits="$(safe_grep -RIn --exclude="*.map" \
    -E '(s3\.amazonaws\.com|\.s3\.amazonaws\.com|storage\.googleapis\.com|\.blob\.core\.windows\.net)' \
    "${OUTPUT_SCAN_DIR}" | head -n 20)"
  if [[ -n "${hits}" ]]; then
    sayc "${YELLOW}  Cloud storage endpoints referenced in output [LOW]${NC}"
    record_finding "LOW" "CHECK 41" "Cloud storage endpoints referenced in output"
    echo "${hits}"
    say "Actions:"
    say "  • Confirm buckets/containers are intentional and properly scoped"
  else
    sayc "${GREEN} No common cloud storage endpoints found${NC}"
  fi
}

check_42_recon_breadcrumbs() {
  if [[ -z "${OUTPUT_SCAN_DIR}" ]]; then
    sayc "${BLUE}  No build output directory detected${NC}"
    return 0
  fi
  local hits
  hits="$(safe_grep -RIn --exclude="*.map" \
    -E '(/wp-admin|/phpmyadmin|/admin\b|/graphql\b|/\.env\b|/\.git\b)' \
    "${OUTPUT_SCAN_DIR}" | head -n 20)"
  if [[ -n "${hits}" ]]; then
    sayc "${YELLOW}  Potential recon breadcrumbs found in output [LOW]${NC}"
    record_finding "LOW" "CHECK 42" "Recon breadcrumbs in output"
    echo "${hits}"
    say "Actions:"
    say "  • Remove unnecessary endpoint references from public pages"
  else
    sayc "${GREEN} No common recon breadcrumbs found${NC}"
  fi
}

check_43_exfil_indicators() {
  local pattern='(webhook\.site|requestbin|ngrok\.io|hookdeck\.com|pipedream\.net|pastebin\.com|discord(app)?\.com/api/webhooks)'
  local tmpf
  tmpf="$(tmpfile exfil-indicators)"
  
  safe_grep -RIn --exclude-dir=".git" --exclude-dir="node_modules" \
    -E "$pattern" . > "$tmpf" || true
    
  if [[ -s "$tmpf" ]]; then
    sayc "${YELLOW}  Potential exfiltration endpoints referenced [MEDIUM]${NC}"
    record_finding "MEDIUM" "CHECK 43" "Possible exfil endpoints referenced"
    say ""
    
    local shown=0
    local current_file=""
    while IFS=: read -r file line_num matched && [[ $shown -lt 5 ]]; do
      if [[ "$file" != "$current_file" ]]; then
        current_file="$file"
        report_snippet_finding "MEDIUM" "Potential Exfil Endpoint" "$file" "$pattern" \
          "Action: Confirm endpoints are intentional, treat unexpected webhooks as compromise indicator"
        shown=$((shown + 1))
      fi
    done < "$tmpf"
  else
    sayc "${GREEN} No common exfil endpoints detected${NC}"
  fi
}

check_44_hook_permissions() {
  if [[ ! -f ".git/hooks/pre-commit" ]]; then
    sayc "${BLUE}  No pre-commit hook found${NC}"
    return 0
  fi

  if [[ ! -x ".git/hooks/pre-commit" ]]; then
    sayc "${YELLOW}  pre-commit hook exists but is not executable [LOW]${NC}"
    record_finding "LOW" "CHECK 44" "pre-commit hook not executable"
    say "Actions:"
    say "  • chmod +x .git/hooks/pre-commit"
  else
    sayc "${GREEN} pre-commit hook is executable${NC}"
  fi

  local mode=""
  mode="$(stat_cmd -c %a .git/hooks/pre-commit 2>/dev/null || stat_cmd -f %OLp .git/hooks/pre-commit 2>/dev/null || true)"
  if [[ -n "${mode}" ]]; then
    local last="${mode: -1}"
    if [[ "${last}" =~ ^[2367]$ ]]; then
      sayc "${YELLOW}  pre-commit hook appears writable by others (mode ${mode}) [MEDIUM]${NC}"
      record_finding "MEDIUM" "CHECK 44" "pre-commit hook world/group writable"
      say "Actions:"
      say "  • chmod 700 .git/hooks/pre-commit"
    fi
  fi
}

check_45_dependabot() {
  local has_deps=0
  [[ -f "package.json" || -f "go.mod" || -f "requirements.txt" || -f "Gemfile" ]] && has_deps=1
  if [[ "${has_deps}" -eq 0 ]]; then
    sayc "${BLUE}  No obvious dependency manifests detected${NC}"
    return 0
  fi
  if [[ -f ".github/dependabot.yml" || -f ".github/dependabot.yaml" ]]; then
    sayc "${GREEN} Dependabot config detected${NC}"
  else
    sayc "${YELLOW}  Dependabot config not found [LOW]${NC}"
    record_finding "LOW" "CHECK 45" "Dependabot config missing"
    say "Actions:"
    say "  • Add .github/dependabot.yml to keep deps fresh"
  fi
}

# ---------------------------------
# Execute checks (in order)
# ---------------------------------
run_check "CHECK 01" "Repo Structure" check_01_repo
run_check "CHECK 02" ".gitignore Hygiene" check_02_gitignore
run_check "CHECK 03" "Private Keys (Hard Stop)" check_03_private_keys
run_check "CHECK 04" "Secrets Pattern Scan" check_04_secret_patterns
run_check "CHECK 05" "Backup/Temp Artifacts" check_05_backup_artifacts
run_check "CHECK 06" "Dotenv Files" check_06_dotenv_files
run_check "CHECK 07" "Build Output Exposure" check_07_output_exposure
run_check "CHECK 08" "Mixed Content (Output)" check_08_mixed_content_output
run_check "CHECK 09" "Netlify Config Presence" check_09_netlify_config_present
run_check "CHECK 10" "Security Headers (Netlify) — Basic" check_10_netlify_headers_basic
run_check "CHECK 11" "GitHub Directory" check_11_github_dir
run_check "CHECK 12" "Gitleaks Scan (Optional)" check_12_gitleaks_optional
run_check "CHECK 13" "detect-secrets (Optional)" check_13_detect_secrets_optional
run_check "CHECK 14" "npm audit (Optional)" check_14_npm_audit_optional
run_check "CHECK 15" "Working Tree Cleanliness" check_15_worktree_clean
run_check "CHECK 16" "Risky Debug Artifacts (Output)" check_16_risky_debug_output
run_check "CHECK 17" "Git History — Sensitive Extensions" check_17_git_history_sensitive_ext
run_check "CHECK 18" "Git Remote URL Hygiene" check_18_git_remote_http
run_check "CHECK 19" "Known Sensitive Filenames" check_19_sensitive_filenames
run_check "CHECK 20" "Output JS Key Exposure (Heuristic)" check_20_output_js_key_exposure
run_check "CHECK 21" "Netlify Redirects (Hint)" check_21_netlify_redirects_hint
run_check "CHECK 22" "CNAME / GitHub Pages File" check_22_cname
run_check "CHECK 23" "Server Config Artifacts (.htaccess)" check_23_htaccess
run_check "CHECK 24" "Exposed Config Files (Output)" check_24_exposed_configs_output
run_check "CHECK 25" "Netlify Env Leak Heuristic" check_25_netlify_env_leak
run_check "CHECK 26" "Hugo Modules / Themes" check_26_hugo_modules
run_check "CHECK 27" "Jekyll Plugins (Hint)" check_27_jekyll_plugins
run_check "CHECK 28" "Astro Integrations (Hint)" check_28_astro_integrations
run_check "CHECK 29" "Eleventy eval/Function (Hint)" check_29_eleventy_eval
run_check "CHECK 30" "Next.js Export Output" check_30_next_export
run_check "CHECK 31" "Large Files" check_31_large_files
run_check "CHECK 32" "Git Hooks (pre-commit)" check_32_precommit_hook
run_check "CHECK 33" "README Presence" check_33_readme
run_check "CHECK 34" "GitHub Actions Foot-guns" check_34_actions_footguns
run_check "CHECK 35" "Actions Pinning & Permissions" check_35_actions_pinning_permissions
run_check "CHECK 36" "Lockfile Hygiene" check_36_lockfile
run_check "CHECK 37" "security.txt Presence" check_37_security_txt
run_check "CHECK 38" "CSP Quality (Netlify)" check_38_csp_quality
run_check "CHECK 39" "Browser Hardening Headers (Netlify)" check_39_browser_headers
run_check "CHECK 40" "robots.txt & sitemap.xml Sanity (Output)" check_40_robots_sitemap
run_check "CHECK 41" "Public Storage Endpoints (Output)" check_41_storage_endpoints
run_check "CHECK 42" "Recon Breadcrumbs (Output)" check_42_recon_breadcrumbs
run_check "CHECK 43" "Exfiltration Indicators" check_43_exfil_indicators
run_check "CHECK 44" "Git Hook Permissions" check_44_hook_permissions
run_check "CHECK 45" "Dependabot Config" check_45_dependabot

# ---------------------------------
# Final summary + exit logic
# ---------------------------------
hr
sayc "${PURPLE}FINAL SUMMARY${NC}"
hr
say "Generator: ${GENERATOR}"
say "Output dir: ${OUTPUT_SCAN_DIR:-"(none detected)"}"
say ""
say "Findings:"
say "  CRITICAL: ${CRITICAL}"
say "  HIGH:     ${HIGH}"
say "  MEDIUM:   ${MEDIUM}"
say "  LOW:      ${LOW}"
say ""

if [[ "${#HIT_CHECK_IDS[@]}" -gt 0 ]]; then
  say "Triggered checks: ${HIT_CHECK_IDS[*]}"
  if [[ "$VERBOSE" -eq 1 ]]; then
    say ""
    say "Findings detail:"
    printf "  - %s\n" "${HIT_LINES[@]}"
  fi
  say ""
fi

EXIT_CODE=0

if [[ "${CRITICAL}" -gt 0 ]]; then
  sayc "${RED} CRITICAL: One or more CRITICAL findings. Blocking.${NC}"
  EXIT_CODE=3
elif [[ "${HIGH}" -gt 0 ]]; then
  sayc "${YELLOW}  One or more HIGH findings.${NC}"
  sayc "${RED} Blocking on HIGH.${NC}"
  EXIT_CODE=2
elif [[ "${MEDIUM}" -gt 0 || "${LOW}" -gt 0 ]]; then
  if [[ "${NON_INTERACTIVE}" -eq 1 ]]; then
    sayc "${YELLOW}  Medium/Low findings present (non-interactive). Exiting non-zero.${NC}"
    EXIT_CODE=1
  else
    sayc "${YELLOW}  Medium/Low findings present.${NC}"
    if prompt_continue "Proceed anyway with Medium/Low risk?"; then
      sayc "${GREEN} Proceeding (user accepted risk).${NC}"
      EXIT_CODE=0
    else
      sayc "${YELLOW} User declined. Blocking.${NC}"
      EXIT_CODE=1
    fi
  fi
else
  sayc "${GREEN} No findings. You're clean.${NC}"
  EXIT_CODE=0
fi

say ""
say "Exit code legend:"
say "  0  Success (or user accepted Medium/Low risk)"
say "  1  Medium/Low present and blocked/declined"
say "  2  High present (blocked)"
say "  3  Critical present (blocked)"
say "  99 Usage/input error"
say ""

exit "${EXIT_CODE}"
