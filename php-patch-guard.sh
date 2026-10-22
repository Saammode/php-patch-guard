#!/usr/bin/env bash
#
# php-patch-guard.sh
# -----------------------------------------------------------------------------
# Detect whether the PHP on this server is vulnerable to the "php2shell" RCE
# pair CVE-2026-109618 / CVE-2026-109619, show exactly what would change, ask
# for confirmation, then apply the official vendor update and verify it.
#
# Safe by default: with no flags it ONLY reports. It never changes anything
# until you confirm an interactive prompt (or pass --yes).
#
# Supports: Debian/Ubuntu (apt), RHEL family / Alma / Rocky / Fedora (dnf/yum).
# Project:  https://github.com/Saammode/php-patch-guard
# License:  MIT
# -----------------------------------------------------------------------------

set -Eeuo pipefail

PPG_VERSION="1.0.1"

# --- The vulnerability this tool checks for -----------------------------------
CVE_A="CVE-2026-109618"
CVE_B="CVE-2026-109619"
NICKNAME="php2shell"

# Upstream (php.net) FIXED versions, per branch. Used only as a fallback for
# PHP that did NOT come from the OS package manager (e.g. compiled from source),
# because distro packages backport the fix WITHOUT bumping this number.
#   branch -> first fixed upstream patch version
declare -A UPSTREAM_FIXED=(
  [8.5]=8.5.12
  [8.4]=8.4.27
  [8.3]=8.3.36
  [8.2]=8.2.35
)
# Branches with no official upstream fix (end of life).
EOL_BRANCHES_REGEX='^(5\.|7\.|8\.0|8\.1)'

# --- Exit codes ---------------------------------------------------------------
EX_OK=0          # all detected PHP is patched
EX_USAGE=1       # bad invocation
EX_UNSUPPORTED=2 # OS / package manager not supported
EX_NEEDS=10      # check-only: at least one install needs updating
EX_UPDATED=20    # an update was applied successfully
EX_FAILED=30     # an update or verification failed

# --- Defaults (overridden by flags) ------------------------------------------
MODE="check"            # check | apply
ASSUME_YES=0
DO_RESTART=1
JSON=0
MITIGATE=0
REVERT_MITIGATION=0
COLOR=1
LOG_FILE=""
MITIGATION_DIR_TAG="99-php-patch-guard"
INSTALL_PATH="/usr/local/sbin/php-patch-guard"

# --- Output helpers -----------------------------------------------------------
if [[ ! -t 1 ]]; then COLOR=0; fi
c() { # c <color> <text...>
  local code="$1"; shift
  if [[ "$COLOR" == "1" ]]; then printf '\033[%sm%s\033[0m' "$code" "$*"; else printf '%s' "$*"; fi
}
red()   { c '0;31' "$@"; }
grn()   { c '0;32' "$@"; }
ylw()   { c '0;33' "$@"; }
blu()   { c '0;36' "$@"; }
bold()  { c '1'    "$@"; }

log() { # append to log file if configured; always echo to stderr trace off
  if [[ -n "$LOG_FILE" ]]; then
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$LOG_FILE" 2>/dev/null || true
  fi
}
say()  { printf '%s\n' "$*"; log "$*"; }
info() { printf '%s %s\n' "$(blu '•')" "$*"; log "INFO $*"; }
warn() { printf '%s %s\n' "$(ylw '!')" "$*"; log "WARN $*"; }
err()  { printf '%s %s\n' "$(red '✗')" "$*" >&2; log "ERR  $*"; }
ok()   { printf '%s %s\n' "$(grn '✓')" "$*"; log "OK   $*"; }

die() { err "$*"; exit "$EX_USAGE"; }

on_err() {
  local ec=$?
  err "Unexpected failure (line $1, exit $ec). Nothing further will run."
  err "Re-run with --log /tmp/ppg.log and share that file if you need help."
  exit "$EX_FAILED"
}
trap 'on_err $LINENO' ERR

# --- Usage --------------------------------------------------------------------
usage() {
  cat <<EOF
php-patch-guard v$PPG_VERSION
Detect & fix PHP exposure to $NICKNAME ($CVE_A / $CVE_B).

USAGE
  sudo ./php-patch-guard.sh [options]

By default it only REPORTS. It changes nothing until you confirm.

OPTIONS
  --check            Report status and exit. Never prompts, never changes. (default)
  --update, --fix    Detect, show the plan, ASK for confirmation, then upgrade.
  -y, --yes          Skip the confirmation prompt (for automation). Implies --update.
  --mitigate         Apply the temporary stopgap (disable session.upload_progress)
                     instead of upgrading. Use only if you cannot patch yet.
  --revert-mitigation Remove a stopgap previously applied by this tool.
  --install          Copy this script to $INSTALL_PATH so you can
                     then just run 'sudo php-patch-guard' from anywhere.
  --uninstall        Remove the installed copy.
  --no-restart       Upgrade/mitigate but do NOT restart web services (you restart later).
  --json             Machine-readable output (status report). Implies no prompts.
  --no-color         Disable colored output.
  --log FILE         Append a timestamped log to FILE.
  -h, --help         This help.
  --version          Print version and exit.

EXIT CODES
  0  all PHP installs are patched
  10 at least one install needs updating (check mode)
  20 an update was applied successfully
  30 an update or verification failed
  2  unsupported OS / package manager
  1  usage error

EXAMPLES
  sudo ./php-patch-guard.sh                 # just tell me if I'm exposed
  sudo ./php-patch-guard.sh --update        # show plan, ask, then fix
  sudo ./php-patch-guard.sh --yes           # fix without prompting (cron/fleet)
  sudo ./php-patch-guard.sh --json          # for monitoring / Ansible
  sudo ./php-patch-guard.sh --mitigate      # stopgap if no patch available yet
EOF
}

# --- Argument parsing ---------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --check)             MODE="check" ;;
      --update|--fix)      MODE="apply" ;;
      -y|--yes)            MODE="apply"; ASSUME_YES=1 ;;
      --mitigate)          MODE="apply"; MITIGATE=1 ;;
      --revert-mitigation) MODE="apply"; REVERT_MITIGATION=1 ;;
      --install)           MODE="install" ;;
      --uninstall)         MODE="uninstall" ;;
      --no-restart)        DO_RESTART=0 ;;
      --json)              JSON=1; COLOR=0 ;;
      --no-color)          COLOR=0 ;;
      --log)               shift; [[ $# -gt 0 ]] || die "--log needs a file path"; LOG_FILE="$1" ;;
      -h|--help)           usage; exit 0 ;;
      --version)           echo "$PPG_VERSION"; exit 0 ;;
      *) die "Unknown option: $1 (try --help)" ;;
    esac
    shift
  done
}

# -----------------------------------------------------------------------------
# Environment detection
# -----------------------------------------------------------------------------
OS_ID=""; OS_LIKE=""; PKG=""
detect_os() {
  # Read os-release in SUBSHELLS so its VERSION/NAME/etc. can never overwrite
  # this script's own variables (e.g. PPG_VERSION, or array names).
  if [[ -r /etc/os-release ]]; then
    OS_ID="$(. /etc/os-release 2>/dev/null; printf '%s' "${ID:-}")"
    OS_LIKE="$(. /etc/os-release 2>/dev/null; printf '%s' "${ID_LIKE:-}")"
  fi
  if command -v apt-get >/dev/null 2>&1 && [[ "$OS_ID $OS_LIKE" == *debian* || "$OS_ID" == ubuntu || "$OS_ID" == debian ]]; then
    PKG="apt"
  elif command -v dnf >/dev/null 2>&1; then
    PKG="dnf"
  elif command -v yum >/dev/null 2>&1; then
    PKG="yum"
  else
    PKG=""
  fi
}

need_root_for_changes() {
  if [[ "$MODE" == "apply" && "$(id -u)" -ne 0 ]]; then
    die "Applying changes needs root. Re-run with: sudo $0 $*"
  fi
}

# -----------------------------------------------------------------------------
# Version helpers
# -----------------------------------------------------------------------------
# Return "major.minor" branch from a full version like 8.3.6 -> 8.3
branch_of() { awk -F. '{print $1"."$2}' <<<"$1"; }

# dpkg-style version compare: echo 1 if $1 >= $2, else 0  (Debian only)
dpkg_ge() { dpkg --compare-versions "$1" ge "$2" && echo 1 || echo 0; }

# Plain upstream semver compare: 1 if $1 >= $2 else 0
ver_ge() {
  [[ "$1" == "$2" ]] && { echo 1; return; }
  local lower
  lower="$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)"
  [[ "$lower" == "$2" ]] && echo 1 || echo 0
}

is_eol_branch() { [[ "$1" =~ $EOL_BRANCHES_REGEX ]]; }

# -----------------------------------------------------------------------------
# Detection results are accumulated into these parallel arrays.
#   DET_NAME   human label (e.g. "PHP 8.3 (apt: php8.3-fpm)")
#   DET_BRANCH 8.3
#   DET_VER    full version string
#   DET_STATE  patched | vulnerable | eol | unknown
#   DET_DETAIL short explanation
#   DET_PKGS   space-separated package names to upgrade (apt/dnf)
#   DET_SVC    space-separated service hints
# -----------------------------------------------------------------------------
DET_NAME=(); DET_BRANCH=(); DET_VER=(); DET_STATE=(); DET_DETAIL=(); DET_PKGS=(); DET_SVC=()

add_det() {
  DET_NAME+=("$1"); DET_BRANCH+=("$2"); DET_VER+=("$3")
  DET_STATE+=("$4"); DET_DETAIL+=("$5"); DET_PKGS+=("$6"); DET_SVC+=("$7")
}

# Does an installed Debian package's shipped changelog mention the CVE?
apt_changelog_has_cve() { # $1 = package name
  local pkg="$1" f
  for f in "/usr/share/doc/$pkg/changelog.Debian.gz" "/usr/share/doc/$pkg/changelog.gz"; do
    if [[ -r "$f" ]] && zgrep -qE "$CVE_A|$CVE_B" "$f" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

# Is a fixed candidate available in apt for this package?
apt_candidate_version() { # $1 = package
  # No early `exit` in awk: closing the pipe early can SIGPIPE apt-cache and,
  # under pipefail, abort a standalone assignment. There's only one Candidate
  # line, so reading the whole stream is cheap and safe.
  apt-cache policy "$1" 2>/dev/null | awk '/Candidate:/{print $2}'
}
apt_installed_version() { # $1 = package
  dpkg-query -W -f='${Version}' "$1" 2>/dev/null || true
}

# -----------------------------------------------------------------------------
# DETECTION — Debian / Ubuntu
# -----------------------------------------------------------------------------
detect_apt() {
  local commons=() c br instver
  # All INSTALLED phpX.Y-common packages = one per installed PHP branch.
  # Filter on the install status ('ii') so dpkg's known-but-not-installed
  # entries (version "(none)") never leak in and invent phantom branches.
  mapfile -t commons < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'php*-common' 2>/dev/null \
                          | awk '$1=="ii"{print $2}' \
                          | grep -E '^php[0-9]+\.[0-9]+-common$' || true)

  if [[ ${#commons[@]} -eq 0 ]]; then
    return 0
  fi

  for c in "${commons[@]}"; do
    br="$(sed -E 's/^php([0-9]+\.[0-9]+)-common$/\1/' <<<"$c")"
    instver="$(apt_installed_version "$c")"

    # Which related packages exist (so we upgrade + restart the right things).
    local related=() svcarr=()
    related+=("$c")
    for cand in "php$br-cli" "php$br-fpm" "libapache2-mod-php$br"; do
      if [[ "$(dpkg-query -W -f='${Status}' "$cand" 2>/dev/null)" == *"install ok installed"* ]]; then
        related+=("$cand")
        [[ "$cand" == "php$br-fpm" ]] && svcarr+=("php$br-fpm")
        [[ "$cand" == "libapache2-mod-php$br" ]] && svcarr+=("apache2")
      fi
    done

    local state detail pkgs
    pkgs="${related[*]}"
    if apt_changelog_has_cve "$c"; then
      state="patched"; detail="installed package $instver includes the $CVE_A fix"
    else
      local cand; cand="$(apt_candidate_version "$c")"
      if [[ -n "$cand" && "$cand" != "$instver" && "$(dpkg_ge "$cand" "$instver")" == "1" ]]; then
        state="vulnerable"; detail="fix available: upgrade $instver → $cand"
      else
        # No newer candidate and changelog has no CVE: either not yet published,
        # or a 3rd-party build. Flag as unknown so we don't give false comfort.
        if is_eol_branch "$br"; then
          state="eol"; detail="PHP $br is end-of-life; no official package fix"
        else
          state="unknown"; detail="no patched package offered yet by apt (run apt update; or EOL/3rd-party build)"
        fi
      fi
    fi
    add_det "PHP $br (apt)" "$br" "$instver" "$state" "$detail" "$pkgs" "${svcarr[*]:-}"
  done
}

# -----------------------------------------------------------------------------
# DETECTION — RHEL family (dnf/yum)
# -----------------------------------------------------------------------------
rpm_changelog_has_cve() { # $1 = package
  # No `grep -q`: it closes the pipe on first match and SIGPIPEs rpm, which
  # under pipefail would flip the result to failure on a cumulative changelog.
  # Writing to /dev/null makes grep drain the whole stream.
  rpm -q --changelog "$1" 2>/dev/null | grep -E "$CVE_A|$CVE_B" >/dev/null
}
detect_rpm() {
  local pm="$PKG" pkgs_common br instver
  # Find installed php core packages. Modules (php-fpm, php-cli) and php-common.
  mapfile -t pkgs_common < <(rpm -qa 'php*-common' 'php-common' 2>/dev/null | sort -u || true)
  if [[ ${#pkgs_common[@]} -eq 0 ]]; then
    # SCL / remi style: php74-php-common, etc.
    mapfile -t pkgs_common < <(rpm -qa '*php*-common' 2>/dev/null | sort -u || true)
  fi
  [[ ${#pkgs_common[@]} -eq 0 ]] && return 0

  local seen_br=""
  for p in "${pkgs_common[@]}"; do
    instver="$(rpm -q --qf '%{VERSION}' "$p" 2>/dev/null || true)"
    br="$(branch_of "$instver")"
    [[ -z "$instver" ]] && continue
    case " $seen_br " in *" $br "*) continue;; esac
    seen_br+=" $br"

    local svcarr=() related=("$p")
    rpm -q php-fpm >/dev/null 2>&1 && { related+=("php-fpm"); svcarr+=("php-fpm"); }
    systemctl cat -- httpd >/dev/null 2>&1 && svcarr+=("httpd")

    # dnf/yum check-update exit codes: 0 = no update, 100 = update available,
    # 1 = error. Use `|| rc=$?` so the non-zero result is EXEMPT from both
    # set -e AND the ERR trap (set +e does NOT disarm the trap). Without this,
    # exit 100 — the "update available" (vulnerable) case — would fire on_err
    # and abort with EX_FAILED exactly when a host needs patching.
    local rc=0; "$pm" -q check-update "$p" >/dev/null 2>&1 || rc=$?

    local state detail
    if rpm_changelog_has_cve "$p"; then
      state="patched"; detail="installed rpm $instver includes the $CVE_A fix"
    elif [[ "$rc" -eq 100 ]]; then
      state="vulnerable"; detail="fix available: '$pm upgrade $p'"
    elif is_eol_branch "$br"; then
      state="eol"; detail="PHP $br is end-of-life; no official package fix"
    else
      state="unknown"; detail="no update offered by $pm; run '$pm makecache' then re-check, or verify EOL/3rd-party repo"
    fi
    add_det "PHP $br ($pm)" "$br" "$instver" "$state" "$detail" "php*" "${svcarr[*]:-}"
  done
}

# -----------------------------------------------------------------------------
# DETECTION — CLI fallback (source builds / unmanaged)
# -----------------------------------------------------------------------------
detect_cli_fallback() {
  command -v php >/dev/null 2>&1 || return 0
  # Only add a CLI entry if we have NOT already covered this branch via packages.
  local v br; v="$(php -r 'echo PHP_VERSION;' 2>/dev/null || true)"
  [[ -z "$v" ]] && return 0
  br="$(branch_of "$v")"
  local i
  if [[ "${#DET_BRANCH[@]}" -gt 0 ]]; then
    for i in "${!DET_BRANCH[@]}"; do
      [[ "${DET_BRANCH[$i]}" == "$br" ]] && return 0
    done
  fi
  local state detail
  if is_eol_branch "$br"; then
    state="eol"; detail="PHP $br is end-of-life; upgrade to a supported branch"
  else
    local fixed="${UPSTREAM_FIXED[$br]:-}"
    if [[ -n "$fixed" && "$(ver_ge "$v" "$fixed")" == "1" ]]; then
      state="patched"; detail="$v >= upstream fixed $fixed"
    elif [[ -n "$fixed" ]]; then
      state="vulnerable"; detail="upstream fix is $fixed; this is a non-package build so update it at its source"
    else
      state="unknown"; detail="unrecognized branch $br"
    fi
  fi
  add_det "PHP $br (cli/source)" "$br" "$v" "$state" "$detail" "" ""
}

run_detection() {
  case "$PKG" in
    apt)      detect_apt ;;
    dnf|yum)  detect_rpm ;;
  esac
  detect_cli_fallback
}

# -----------------------------------------------------------------------------
# Reporting
# -----------------------------------------------------------------------------
overall_state() {
  local any_vuln=0 any_unknown=0 any_eol=0 n=${#DET_STATE[@]}
  [[ "$n" -eq 0 ]] && { echo "none"; return; }
  local s
  for s in "${DET_STATE[@]}"; do
    case "$s" in
      vulnerable) any_vuln=1 ;;
      unknown)    any_unknown=1 ;;
      eol)        any_eol=1 ;;
    esac
  done
  if [[ "$any_vuln" == 1 ]]; then echo "vulnerable"
  elif [[ "$any_eol" == 1 ]]; then echo "eol"
  elif [[ "$any_unknown" == 1 ]]; then echo "unknown"
  else echo "patched"; fi
}

print_report() {
  local n=${#DET_STATE[@]} i
  say ""
  say "$(bold "php-patch-guard") — $NICKNAME ($CVE_A / $CVE_B)"
  say "Host: $(hostname 2>/dev/null || echo '?')   OS: ${OS_ID:-?}   Pkg: ${PKG:-none}"
  say "-------------------------------------------------------------------"
  if [[ "$n" -eq 0 ]]; then
    warn "No PHP installation detected on this host."
    return
  fi
  for i in $(seq 0 $((n-1))); do
    local tag
    case "${DET_STATE[$i]}" in
      patched)    tag="$(grn PATCHED)   " ;;
      vulnerable) tag="$(red VULNERABLE)" ;;
      eol)        tag="$(red EOL)       " ;;
      *)          tag="$(ylw UNKNOWN)   " ;;
    esac
    say "  [$tag] ${DET_NAME[$i]}  v${DET_VER[$i]}"
    say "            ${DET_DETAIL[$i]}"
  done
  say "-------------------------------------------------------------------"
}

print_json() {
  local n=${#DET_STATE[@]} i first=1
  printf '{'
  printf '"tool":"php-patch-guard","version":"%s",' "$PPG_VERSION"
  printf '"cves":["%s","%s"],' "$CVE_A" "$CVE_B"
  printf '"host":"%s","os":"%s","pkg":"%s",' "$(hostname 2>/dev/null)" "${OS_ID:-}" "${PKG:-}"
  printf '"overall":"%s","installs":[' "$(overall_state)"
  for i in $(seq 0 $((n-1))); do
    [[ "$n" -eq 0 ]] && break
    [[ "$first" == 1 ]] || printf ','
    first=0
    printf '{"name":"%s","branch":"%s","version":"%s","state":"%s","detail":"%s"}' \
      "${DET_NAME[$i]}" "${DET_BRANCH[$i]}" "${DET_VER[$i]}" "${DET_STATE[$i]}" "${DET_DETAIL[$i]//\"/\'}"
  done
  printf ']}'
  printf '\n'
}

# -----------------------------------------------------------------------------
# Confirmation prompt
# -----------------------------------------------------------------------------
confirm() { # $1 = question
  [[ "$ASSUME_YES" == 1 ]] && { say "$1 [auto-yes]"; return 0; }
  if [[ ! -t 0 ]]; then
    err "Not an interactive terminal and --yes not given; refusing to change anything."
    return 1
  fi
  local ans
  printf '%s %s ' "$(bold '?')" "$1 [y/N]"
  read -r ans
  [[ "$ans" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# -----------------------------------------------------------------------------
# Service restart / config test
# -----------------------------------------------------------------------------
has_systemd() { [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; }

service_active() { # $1 service
  has_systemd && systemctl is-active --quiet "$1" 2>/dev/null
}

config_test() {
  # Best-effort config validation before restart. Never fatal by itself.
  local svc="$1" rc=0
  case "$svc" in
    apache2|httpd)
      if command -v apachectl >/dev/null 2>&1; then apachectl configtest >/dev/null 2>&1 || rc=$?
      elif command -v apache2ctl >/dev/null 2>&1; then apache2ctl configtest >/dev/null 2>&1 || rc=$?; fi
      ;;
    php*-fpm)
      local bin; bin="$(command -v "$svc" 2>/dev/null || true)"
      [[ -z "$bin" ]] && bin="$(command -v php-fpm 2>/dev/null || true)"
      [[ -n "$bin" ]] && { "$bin" -t >/dev/null 2>&1 || rc=$?; }
      ;;
  esac
  return "$rc"
}

restart_service() { # $1 service
  local svc="$1"
  if ! has_systemd; then
    warn "No systemd here; restart '$svc' yourself after this run."
    return 0
  fi
  # Unit-presence test via `systemctl cat` — avoids a `… | grep -q` pipeline,
  # whose early pipe-close can SIGPIPE systemctl and, under pipefail, make an
  # EXISTING unit look absent (so its restart would be silently skipped),
  # leaving old vulnerable workers running. Also avoids an unanchored regex.
  if ! systemctl cat -- "$svc" >/dev/null 2>&1; then
    return 0   # unit not present on this host
  fi
  if config_test "$svc"; then
    if systemctl restart "$svc" 2>/dev/null; then
      ok "restarted $svc"
    else
      err "failed to restart $svc — check 'systemctl status $svc'"
      return 1
    fi
  else
    err "config test FAILED for $svc; NOT restarting. Fix config, then: systemctl restart $svc"
    return 1
  fi
}

restart_all() {
  local svcs="$1" s rc=0
  [[ "$DO_RESTART" == 0 ]] && { warn "--no-restart set; skipping restarts. Remember to restart PHP/web services."; return 0; }
  # unique
  for s in $(tr ' ' '\n' <<<"$svcs" | sort -u); do
    [[ -z "$s" ]] && continue
    restart_service "$s" || rc=1
  done
  return "$rc"
}

# -----------------------------------------------------------------------------
# Upgrade
# -----------------------------------------------------------------------------
apt_refresh_done=0
apt_refresh() {
  [[ "$apt_refresh_done" == 1 ]] && return 0
  info "Refreshing apt package lists (apt-get update)…"
  if apt-get update >/dev/null 2>&1; then apt_refresh_done=1; ok "apt lists updated"
  else warn "apt-get update reported problems; continuing with cached lists"; apt_refresh_done=1; fi
}

do_upgrade() {
  local n=${#DET_STATE[@]} i svcs="" pkgs_all=""

  # Build the set of packages to upgrade from vulnerable/unknown entries.
  for i in $(seq 0 $((n-1))); do
    case "${DET_STATE[$i]}" in
      vulnerable|unknown)
        pkgs_all+=" ${DET_PKGS[$i]}"
        svcs+=" ${DET_SVC[$i]}"
        ;;
    esac
  done

  # do_upgrade is only reached when the overall state is vulnerable/unknown/eol,
  # so there IS something exposed. If apt collected no packages, the exposed PHP
  # is a non-package (source / 3rd-party) build we cannot upgrade for them — do
  # NOT exit 0, or automation keying on the exit code would read "all patched".
  if [[ -z "${pkgs_all// }" && "$PKG" != "dnf" && "$PKG" != "yum" ]]; then
    warn "The exposed PHP here was not installed via apt (compiled from source or"
    warn "a 3rd-party build), so this tool cannot upgrade it automatically."
    warn "Update it to the fixed version at its source, then re-run --check."
    return "$EX_NEEDS"
  fi

  say ""
  say "$(bold 'PLAN')"
  case "$PKG" in
    apt)
      apt_refresh
      say "  Will run:  apt-get install --only-upgrade -y$pkgs_all"
      ;;
    dnf|yum)
      say "  Will run:  $PKG upgrade -y 'php*'"
      ;;
  esac
  [[ -n "${svcs// }" ]] && say "  Then restart: $(tr ' ' '\n' <<<"$svcs" | sort -u | tr '\n' ' ')"
  say "  Then re-verify every PHP install against $CVE_A / $CVE_B."
  say ""

  if ! confirm "Apply this update now?"; then
    warn "Cancelled by user. No changes made."
    return "$EX_NEEDS"
  fi

  info "Applying update…"
  local up_rc=0
  case "$PKG" in
    apt)
      # shellcheck disable=SC2086
      if DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y $pkgs_all 2>&1 | tee -a "${LOG_FILE:-/dev/null}"; then
        ok "apt upgrade finished"
      else
        err "apt upgrade failed"; up_rc=1
      fi
      ;;
    dnf|yum)
      if "$PKG" upgrade -y 'php*' 2>&1 | tee -a "${LOG_FILE:-/dev/null}"; then
        ok "$PKG upgrade finished"
      else
        err "$PKG upgrade failed"; up_rc=1
      fi
      ;;
  esac

  if [[ "$up_rc" -ne 0 ]]; then
    err "Package upgrade failed; NOT restarting services. Investigate, then re-run."
    return "$EX_FAILED"
  fi

  restart_all "$svcs" || up_rc=1

  # Re-detect and report.
  info "Re-checking after upgrade…"
  DET_NAME=(); DET_BRANCH=(); DET_VER=(); DET_STATE=(); DET_DETAIL=(); DET_PKGS=(); DET_SVC=()
  run_detection
  print_report
  local after; after="$(overall_state)"
  if [[ "$after" == "patched" ]]; then
    ok "All PHP installs now report PATCHED against $CVE_A / $CVE_B."
    return "$EX_UPDATED"
  elif [[ "$after" == "eol" ]]; then
    warn "Upgrade applied, but an END-OF-LIFE PHP branch remains (no official fix)."
    warn "Plan to move those sites to a supported branch, or use an ELS/backport vendor."
    return "$EX_UPDATED"
  else
    err "After upgrade, status is '$after'. Some installs are not confirmed patched."
    err "If apt offered no new build yet, re-run later. See README 'Troubleshooting'."
    return "$EX_FAILED"
  fi
}

# -----------------------------------------------------------------------------
# Mitigation (temporary stopgap) — disable session.upload_progress
# -----------------------------------------------------------------------------
mitigation_body() {
  cat <<'INI'
; Added by php-patch-guard as a TEMPORARY stopgap for php2shell
; (CVE-2026-109618 / CVE-2026-109619). Remove after upgrading PHP.
session.upload_progress.enabled = 0
INI
}

apply_mitigation() {
  local wrote=0 svcs=""
  say ""
  say "$(bold 'PLAN (mitigation, not a full fix)')"
  say "  Create '$MITIGATION_DIR_TAG.ini' (session.upload_progress off) in each PHP conf.d"
  say "  Then restart PHP-FPM / Apache."
  say "  This blocks the confirmed upload-progress path only. UPGRADE is still required."
  say ""
  confirm "Apply the temporary mitigation now?" || { warn "Cancelled."; return "$EX_NEEDS"; }

  local d
  for d in /etc/php/*/fpm/conf.d /etc/php/*/apache2/conf.d /etc/php/*/cli/conf.d \
           /etc/php.d /etc/opt/remi/php*/php.d; do
    [[ -d "$d" ]] || continue
    if mitigation_body > "$d/$MITIGATION_DIR_TAG.ini" 2>/dev/null; then
      ok "wrote $d/$MITIGATION_DIR_TAG.ini"; wrote=1
    fi
  done
  # Collect fpm service names from the php dir structure.
  for d in /etc/php/*/fpm; do [[ -d "$d" ]] && svcs+=" php$(basename "$(dirname "$d")")-fpm"; done
  [[ -d /etc/php.d ]] && svcs+=" php-fpm httpd"
  svcs+=" apache2"

  if [[ "$wrote" == 0 ]]; then
    err "Could not find a PHP conf.d directory to write to. Is PHP installed here?"
    return "$EX_FAILED"
  fi
  restart_all "$svcs"
  warn "Mitigation applied. This is a STOPGAP — run '--update' as soon as a patch is available."
  return "$EX_UPDATED"
}

revert_mitigation() {
  local removed=0 f svcs="" files=()
  mapfile -t files < <(find /etc/php /etc/php.d /etc/opt/remi -name "$MITIGATION_DIR_TAG.ini" 2>/dev/null || true)
  if [[ ${#files[@]} -eq 0 ]]; then
    warn "No php-patch-guard mitigation files found."; return "$EX_OK"
  fi
  say ""
  say "$(bold 'PLAN (revert mitigation)')"
  say "  Will remove:"
  printf '    %s\n' "${files[@]}"
  say "  Then restart PHP-FPM / Apache."
  say ""
  # Same safety gate as every other change: confirm (or --yes). Removing the
  # stopgap AND bouncing web services must never happen unprompted.
  confirm "Remove the mitigation and restart web services now?" || { warn "Cancelled. Nothing removed."; return "$EX_NEEDS"; }
  for f in "${files[@]}"; do
    rm -f "$f" && { ok "removed $f"; removed=1; }
  done
  [[ "$removed" == 0 ]] && { err "Could not remove mitigation files (permissions?)."; return "$EX_FAILED"; }
  local d
  for d in /etc/php/*/fpm; do [[ -d "$d" ]] && svcs+=" php$(basename "$(dirname "$d")")-fpm"; done
  svcs+=" apache2 php-fpm httpd"
  restart_all "$svcs"
  return "$EX_UPDATED"
}

# -----------------------------------------------------------------------------
# Self-install: make the tool a global command so later runs are one word.
# -----------------------------------------------------------------------------
install_self() {
  [[ "$(id -u)" -eq 0 ]] || die "Installing needs root: sudo $0 --install"
  local self="${BASH_SOURCE[0]:-}"
  local src; src="$(readlink -f "$self" 2>/dev/null || echo "$self")"
  if [[ -z "$src" || ! -f "$src" ]]; then
    err "Can't locate the script file to install (did you run it via a pipe?)."
    err "Clone the repo and run: sudo ./php-patch-guard.sh --install"
    return "$EX_FAILED"
  fi
  if install -m 0755 "$src" "$INSTALL_PATH" 2>/dev/null; then
    ok "Installed to $INSTALL_PATH"
    say "Now run it from anywhere:"
    say "  sudo php-patch-guard            # check only"
    say "  sudo php-patch-guard --update   # show plan, ask, then fix"
    return "$EX_OK"
  fi
  err "Could not write $INSTALL_PATH (need root, and the dir must exist)."
  return "$EX_FAILED"
}

uninstall_self() {
  [[ "$(id -u)" -eq 0 ]] || die "Uninstalling needs root: sudo $0 --uninstall"
  if [[ -e "$INSTALL_PATH" ]]; then
    rm -f "$INSTALL_PATH" && ok "Removed $INSTALL_PATH" || { err "could not remove $INSTALL_PATH"; return "$EX_FAILED"; }
  else
    warn "Nothing installed at $INSTALL_PATH"
  fi
  return "$EX_OK"
}

# -----------------------------------------------------------------------------
# main
# -----------------------------------------------------------------------------
main() {
  parse_args "$@"
  [[ -n "$LOG_FILE" ]] && { : >>"$LOG_FILE" || die "cannot write log $LOG_FILE"; log "=== php-patch-guard $PPG_VERSION start ==="; }

  # install/uninstall are standalone and don't need OS/PHP detection.
  local rc0=0
  if [[ "$MODE" == "install" ]]; then install_self || rc0=$?; exit "$rc0"; fi
  if [[ "$MODE" == "uninstall" ]]; then uninstall_self || rc0=$?; exit "$rc0"; fi

  detect_os
  if [[ -z "$PKG" && "$MODE" == "apply" ]]; then
    err "No supported package manager (apt/dnf/yum) found; cannot change anything here."
    exit "$EX_UNSUPPORTED"
  fi
  need_root_for_changes "$@"

  local rc=0
  if [[ "$REVERT_MITIGATION" == 1 ]]; then revert_mitigation || rc=$?; exit "$rc"; fi

  run_detection

  if [[ "$JSON" == 1 ]]; then
    print_json
    [[ "$(overall_state)" == "patched" || "$(overall_state)" == "none" ]] && exit "$EX_OK" || exit "$EX_NEEDS"
  fi

  print_report

  local ov; ov="$(overall_state)"

  if [[ "$MODE" == "check" ]]; then
    case "$ov" in
      patched|none) ok "Nothing to do — not exposed to $NICKNAME."; exit "$EX_OK" ;;
      *) warn "Exposure found. Re-run with --update to fix (it will ask before changing anything)."; exit "$EX_NEEDS" ;;
    esac
  fi

  # apply mode
  if [[ "$MITIGATE" == 1 ]]; then apply_mitigation || rc=$?; exit "$rc"; fi

  case "$ov" in
    patched|none) ok "Already patched — nothing to upgrade."; exit "$EX_OK" ;;
    eol)
      warn "Only END-OF-LIFE PHP found. apt/dnf will not have an official fix."
      warn "See README: move to a supported branch, or use an ELS/backport vendor."
      do_upgrade || rc=$?; exit "$rc" ;;
    *) do_upgrade || rc=$?; exit "$rc" ;;
  esac
}

# Run main when executed directly OR piped to bash (curl | bash), but NOT when
# sourced (so tests can load the functions). When piped via stdin, BASH_SOURCE
# is unset — ${BASH_SOURCE[0]:-$0} defaults it to $0 so the guard is true and,
# crucially, doesn't trip `set -u` with an unbound-variable error.
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
