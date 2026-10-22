# php-patch-guard

A single, safe command-line runner that tells you whether the PHP on a server is
exposed to the **php2shell** remote-code-execution pair
(**CVE-2026-109618** / **CVE-2026-109619**, both CVSS v4.0 9.2), shows you exactly
what it would change, **asks before touching anything**, then applies the official
vendor update and verifies it worked.

> **php2shell** was disclosed on 20 Oct 2026 and patched upstream on 21 Oct 2026.
> It affects every PHP install that serves web requests (PHP-FPM, Apache mod_php,
> php-cgi, FrankenPHP, LiteSpeed). Patched versions: **8.5.12, 8.4.27, 8.3.36, 8.2.35**.

---

## Why a tool and not just `apt upgrade`?

Because **"am I patched?" is not the same as comparing version numbers.** Debian,
Ubuntu and RHEL **backport** the security fix into their existing package *without
changing the upstream version*. For example, Ubuntu 24.04 ships the fix as:

```
8.3.6-0ubuntu0.24.04.12   ← vulnerable
8.3.6-0ubuntu0.24.04.13   ← patched   (same "8.3.6"!)
```

So a script that just reads `php -v` and compares against "8.3.36" would wrongly
tell you a fully patched server is vulnerable. `php-patch-guard` instead checks the
**installed package's changelog for the CVE IDs** (and the package revision), which
is the correct signal on managed distros. For PHP built from source it falls back to
comparing against the upstream fixed versions.

---

## Safety model

- **Read-only by default.** Running it with no flags only *reports*.
- **It never changes anything without an explicit `y` at the prompt** (or `--yes`).
- It **config-tests** PHP-FPM / Apache *before* restarting them, and will not
  restart a service whose config fails the test.
- If a package upgrade fails, it **stops and does not restart** anything.
- Everything can be logged with `--log`.

---

## Requirements

- Linux with **apt** (Debian/Ubuntu) or **dnf/yum** (RHEL/Alma/Rocky/Fedora).
- `bash` 4+, and `sudo`/root to apply changes (checking status needs no root).

---

## Run it in one command

### One-liner (`curl | bash` — the bash equivalent of PowerShell's `irm url | iex`)

**Requires the script to be publicly reachable** (make the repo public, or host the
raw file somewhere public). Then, to download *just the script* and run a read-only
check — safe to pipe, because check mode changes nothing:

```bash
curl -fsSL https://raw.githubusercontent.com/Saammode/php-patch-guard/main/php-patch-guard.sh | sudo bash -s -- --check
```

To apply the fix, don't pipe it — piping leaves no terminal for the confirmation
prompt. Either download then run (so you can read it first and answer the prompt):

```bash
curl -fsSLO https://raw.githubusercontent.com/Saammode/php-patch-guard/main/php-patch-guard.sh
sudo bash php-patch-guard.sh --update
```

…or, for unattended runs, pipe with `--yes` (no prompt — make sure you trust it):

```bash
curl -fsSL https://raw.githubusercontent.com/Saammode/php-patch-guard/main/php-patch-guard.sh | sudo bash -s -- --yes
```

> While the repo is **private**, use the `git clone` one-liner below instead — `git`
> authenticates with the server's existing GitHub login, which `curl` to the raw URL
> does not.

### Private repo (as it is now): clone + run

`git` uses the server's existing GitHub login, so one line clones and checks:

```bash
git clone https://github.com/Saammode/php-patch-guard.git && sudo php-patch-guard/php-patch-guard.sh
```

Add `--update` to fix instead of just check:

```bash
git clone https://github.com/Saammode/php-patch-guard.git && sudo php-patch-guard/php-patch-guard.sh --update
```

**Install once, then it's a single word everywhere:**

```bash
git clone https://github.com/Saammode/php-patch-guard.git && sudo php-patch-guard/php-patch-guard.sh --install
# from now on, on that server:
sudo php-patch-guard            # check
sudo php-patch-guard --update   # fix (asks first)
```

**If you make the repo public**, you get a true `curl` one-liner (read-only check —
safe to pipe because it changes nothing):

```bash
curl -fsSL https://raw.githubusercontent.com/Saammode/php-patch-guard/main/php-patch-guard.sh | sudo bash -s -- --check
```

> Piping to `bash` can't show the interactive confirm prompt, so for applying a fix
> use the installed command (`sudo php-patch-guard --update`) or add `--yes` to the
> pipe. Either way, **inspect the script once before trusting it as root** — it's
> short and commented.

### Manual (inspect first, recommended for the apply step)

```bash
git clone https://github.com/Saammode/php-patch-guard.git
cd php-patch-guard
less php-patch-guard.sh          # read it
sudo ./php-patch-guard.sh        # check — changes nothing
sudo ./php-patch-guard.sh --update   # shows plan, asks, then fixes
```

---

## What you'll see

Check mode on an unpatched box:

```
php-patch-guard — php2shell (CVE-2026-109618 / CVE-2026-109619)
Host: web01   OS: ubuntu   Pkg: apt
-------------------------------------------------------------------
  [VULNERABLE] PHP 8.3 (apt)  v8.3.6-0ubuntu0.24.04.12
            fix available: upgrade 8.3.6-0ubuntu0.24.04.12 → 8.3.6-0ubuntu0.24.04.13
-------------------------------------------------------------------
! Exposure found. Re-run with --update to fix (it will ask before changing anything).
```

`--update` then shows a plan and asks:

```
PLAN
  Will run:  apt-get install --only-upgrade -y php8.3-common php8.3-cli php8.3-fpm
  Then restart: php8.3-fpm apache2
  Then re-verify every PHP install against CVE-2026-109618 / CVE-2026-109619.

? Apply this update now? [y/N]
```

After you confirm, it upgrades, restarts, re-checks, and reports:

```
  [PATCHED   ] PHP 8.3 (apt)  v8.3.6-0ubuntu0.24.04.13
✓ All PHP installs now report PATCHED against CVE-2026-109618 / CVE-2026-109619.
```

---

## Options

| Flag | What it does |
|------|--------------|
| *(none)* / `--check` | Report status only. Never prompts, never changes. |
| `--update`, `--fix` | Detect, show the plan, **ask**, then upgrade + restart + verify. |
| `-y`, `--yes` | Apply without the prompt (for cron / automation). Implies `--update`. |
| `--mitigate` | Apply the temporary stopgap (disable `session.upload_progress`) instead of upgrading — only if you can't patch yet. |
| `--revert-mitigation` | Remove a stopgap this tool previously applied (asks first). |
| `--install` | Copy the script to `/usr/local/sbin/php-patch-guard` so later runs are just `sudo php-patch-guard`. |
| `--uninstall` | Remove the installed copy. |
| `--no-restart` | Upgrade/mitigate but don't restart services (you restart during a maintenance window). |
| `--json` | Machine-readable status output (for monitoring / Ansible). |
| `--no-color` | Plain output. |
| `--log FILE` | Append a timestamped log to `FILE`. |
| `-h`, `--help` | Help. |
| `--version` | Print version. |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | All PHP installs are patched. |
| `10` | At least one install needs updating (check mode). |
| `20` | An update was applied successfully. |
| `30` | An update or verification failed. |
| `2` | Unsupported OS / package manager. |
| `1` | Usage error. |

These make it easy to wire into monitoring: treat `0` as green, `10`/`30` as alert.

---

## Running across many servers (a fleet)

With Ansible:

```yaml
- hosts: web
  become: true
  tasks:
    - name: Copy php-patch-guard
      copy: { src: php-patch-guard.sh, dest: /usr/local/sbin/php-patch-guard, mode: "0755" }

    - name: Check status (JSON)
      command: /usr/local/sbin/php-patch-guard --json
      register: ppg
      changed_when: false
      failed_when: false

    - debug: { var: ppg.stdout }

    # Uncomment to auto-remediate after you've reviewed the check output:
    # - name: Patch php2shell
    #   command: /usr/local/sbin/php-patch-guard --yes --log /var/log/php-patch-guard.log
```

A quick `ssh` sweep, check-only:

```bash
for h in web01 web02 web03; do
  echo "== $h =="; ssh "$h" 'sudo ./php-patch-guard.sh --check --no-color'
done
```

---

## If no patch is available yet (stopgap)

If your distro hasn't published the fixed package yet, you can apply the temporary
mitigation PHP recommends and revert it once you've patched:

```bash
sudo ./php-patch-guard.sh --mitigate     # disable session.upload_progress
# ... later, after upgrading:
sudo ./php-patch-guard.sh --revert-mitigation
```

This blocks the confirmed upload-progress attack path only; it is **not** a complete
fix. Upgrading is still required.

---

## End-of-life PHP (8.1 and older)

PHP 8.1, 8.0, 7.x and 5.x are end-of-life and get **no official fix**. The tool flags
them as `EOL`. Your options:

- Move those sites to a supported branch (8.2+), **or**
- Use a vendor that ships backported patches for EOL PHP (e.g. an ELS provider), **or**
- Apply the `--mitigate` stopgap and take the risk knowingly until you migrate.

---

## How detection works

1. Enumerate every installed PHP branch (per `phpX.Y-common` on apt, per `*-common`
   rpm on dnf/yum), plus a CLI/source fallback.
2. **apt:** the install is *patched* if the installed package's
   `changelog.Debian.gz` names the CVE; *vulnerable* if a newer fixed candidate is
   offered; otherwise *unknown* (run `apt update`) or *eol*.
3. **dnf/yum:** *patched* if `rpm -q --changelog` names the CVE; *vulnerable* if
   `check-update` reports an update (exit 100); otherwise *unknown*/*eol*.
4. **source build:** compares `PHP_VERSION` against the upstream fixed table
   (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35).

---

## What has been tested

- **Ubuntu 24.04 (apt), real upgrade:** detect `…12` → VULNERABLE, upgrade to `…13`,
  re-verify → PATCHED (exit 20). Idempotent re-run → PATCHED (exit 0).
- Interactive prompt, decline-makes-no-change, `--yes`, `--json`, `--mitigate`,
  `--revert-mitigation`, `--no-restart`.
- `shellcheck -S warning` clean; 25 unit tests for the version/branch/status logic.
- Independently safety-reviewed (ERR-trap/`pipefail` edge cases, SIGPIPE in unit
  detection, and confirmation gating on every state-changing path, including
  `--revert-mitigation`).
- **Not yet exercised on real hardware:** the dnf/yum (RHEL-family) path and the
  systemd service-restart branch — the detection logic is implemented and unit-logic
  is covered, but test it in staging before fleet-wide automation on those systems.

Run the tests yourself:

```bash
bash tests/test_logic.sh
shellcheck -S warning php-patch-guard.sh
```

---

## Troubleshooting

- **"refusing to change anything" (non-interactive):** you piped input or ran it
  from a script without `--yes`. Add `--yes` for automation.
- **Status `unknown` on apt:** run `sudo apt update` first so the fixed candidate is
  visible, then re-run.
- **Config test failed, not restarting:** your PHP-FPM/Apache config has a
  pre-existing error. Fix it, then `sudo systemctl restart php*-fpm apache2`.
- **Share a log:** re-run with `--log /tmp/ppg.log` and attach that file.

---

## License

MIT — see [LICENSE](LICENSE).
