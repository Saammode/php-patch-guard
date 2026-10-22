#!/usr/bin/env bash
# Unit tests for php-patch-guard's pure logic functions.
# Run: bash tests/test_logic.sh
#
# DET_STATE is assigned here and read by the sourced overall_state(); shellcheck
# can't see that cross-function use, so silence its "unused" warning file-wide.
# shellcheck disable=SC2034
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Source the script without executing main (BASH_SOURCE guard handles this).
# shellcheck disable=SC1091
source "$HERE/../php-patch-guard.sh"

pass=0; fail=0
check() { # check <description> <expected> <actual>
  if [[ "$2" == "$3" ]]; then
    printf '  ok   %s\n' "$1"; pass=$((pass+1))
  else
    printf '  FAIL %s (expected "%s", got "%s")\n' "$1" "$2" "$3"; fail=$((fail+1))
  fi
}

echo "branch_of:"
check "8.3.6 -> 8.3"        "8.3" "$(branch_of 8.3.6)"
check "8.4.27 -> 8.4"       "8.4" "$(branch_of 8.4.27)"
check "7.4.33 -> 7.4"       "7.4" "$(branch_of 7.4.33)"

echo "ver_ge (upstream semver):"
check "8.3.36 >= 8.3.36"    "1" "$(ver_ge 8.3.36 8.3.36)"
check "8.3.37 >= 8.3.36"    "1" "$(ver_ge 8.3.37 8.3.36)"
check "8.3.6  >= 8.3.36"    "0" "$(ver_ge 8.3.6 8.3.36)"
check "8.4.27 >= 8.4.27"    "1" "$(ver_ge 8.4.27 8.4.27)"
check "8.4.2  >= 8.4.27"    "0" "$(ver_ge 8.4.2 8.4.27)"
check "8.5.12 >= 8.5.12"    "1" "$(ver_ge 8.5.12 8.5.12)"

echo "is_eol_branch:"
check "8.1 is EOL"          "yes" "$(is_eol_branch 8.1 && echo yes || echo no)"
check "8.0 is EOL"          "yes" "$(is_eol_branch 8.0 && echo yes || echo no)"
check "7.4 is EOL"          "yes" "$(is_eol_branch 7.4 && echo yes || echo no)"
check "5.6 is EOL"          "yes" "$(is_eol_branch 5.6 && echo yes || echo no)"
check "8.2 is NOT EOL"      "no"  "$(is_eol_branch 8.2 && echo yes || echo no)"
check "8.3 is NOT EOL"      "no"  "$(is_eol_branch 8.3 && echo yes || echo no)"

echo "overall_state:"
DET_STATE=(); check "empty -> none"              "none"       "$(overall_state)"
DET_STATE=(patched patched); check "all patched" "patched"    "$(overall_state)"
DET_STATE=(patched vulnerable); check "any vuln" "vulnerable" "$(overall_state)"
DET_STATE=(patched unknown); check "any unknown" "unknown"    "$(overall_state)"
DET_STATE=(patched eol); check "eol over unknown" "eol"       "$(overall_state)"
DET_STATE=(vulnerable eol); check "vuln wins over eol" "vulnerable" "$(overall_state)"
DET_STATE=(patched eol-os); check "eol-os reported" "eol-os"  "$(overall_state)"
DET_STATE=(eol-os eol); check "eol-os over eol"   "eol-os"    "$(overall_state)"
DET_STATE=(vulnerable eol-os); check "vuln wins over eol-os" "vulnerable" "$(overall_state)"

echo "os_eol_reason:"
_tmp_eol="$(mktemp)"; printf 'deb http://old-releases.ubuntu.com/ubuntu oracular main\n' > "$_tmp_eol"
check "ubuntu old-releases -> reason" "yes" "$([ -n "$(PPG_TEST_SOURCES=$_tmp_eol os_eol_reason)" ] && echo yes || echo no)"
_tmp_deb="$(mktemp)"; printf 'deb http://archive.debian.org/debian buster main\n' > "$_tmp_deb"
check "debian archive -> reason"      "yes" "$([ -n "$(PPG_TEST_SOURCES=$_tmp_deb os_eol_reason)" ] && echo yes || echo no)"
_tmp_ok="$(mktemp)"; printf 'deb http://archive.ubuntu.com/ubuntu noble main\n' > "$_tmp_ok"
check "supported repo -> no reason"   "no"  "$([ -n "$(PPG_TEST_SOURCES=$_tmp_ok os_eol_reason)" ] && echo yes || echo no)"
rm -f "$_tmp_eol" "$_tmp_deb" "$_tmp_ok"

echo "UPSTREAM_FIXED table:"
check "8.5 -> 8.5.12"       "8.5.12" "${UPSTREAM_FIXED[8.5]}"
check "8.4 -> 8.4.27"       "8.4.27" "${UPSTREAM_FIXED[8.4]}"
check "8.3 -> 8.3.36"       "8.3.36" "${UPSTREAM_FIXED[8.3]}"
check "8.2 -> 8.2.35"       "8.2.35" "${UPSTREAM_FIXED[8.2]}"

echo "---"
printf 'Passed: %d   Failed: %d\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
