# PocketServer — Engineering Implementation Plan (v2.0: Antigravity Free-Tier Edition)

> **Document type:** Actionable Engineering & AI-Workflow Implementation Plan  
> **Version:** 2.0 (Refined & Fine-Tuned for Zero-Fault Execution)  
> **Target Environment:** No-root Android 8.0+ running Termux (F-Droid / GitHub Release)  
> **Development Environment:** Google Antigravity IDE (Optimized for Free-Tier Quota & Token Limits)  
> **Core Principle:** Zero-compilation dependencies, strict Termux OS compliance, and modular AI-sprint execution.

---

## 0. Key Architectural Improvements & Mistakes Prevented (v1.0 → v2.0)

To ensure a zero-mistake implementation on both the Android OS level and within Google Antigravity's free tier, the following critical flaws from v1.0 have been corrected:

1. **Eliminated the "Termux Compilation Trap" (`pip` C-Extensions):**
   * *The Mistake in v1.0:* Relying on generic `pip` packages or libraries like `psutil` and `pydantic`, which require `clang`, `rust`, and kernel headers to compile on Android ARM64—frequently failing or exhausting RAM. Furthermore, Android 10+ hides `/proc/stat`, causing `psutil` to crash with `PermissionError`.
   * *The Fix:* **Strict Native Package Policy.** Core Python packages (`python` via `pkg`) and pure-Python wheels only (`flask`, `werkzeug`). System metrics (RAM, storage, thermal) are read directly via safe Android-permitted `/proc/meminfo`, `os.statvfs()`, and `termux-api` fallbacks.
2. **Defeated the Android 12+ "Phantom Process Killer" & Doze Mode:**
   * *The Mistake in v1.0:* Treating wake locks and background survival as optional documentation notes. Without active wake locks, Android terminates background servers within 5 minutes of the screen turning off.
   * *The Fix:* `termux-wake-lock` is now integrated directly into the core Service Manager lifecycle (`P0`). Added an explicit diagnostic check and ADB copy-paste helper for disabling Android 12+ `max_phantom_processes`.
3. **Solved the No-Root Private Networking Trap:**
   * *The Mistake in v1.0:* Attempting to configure VPN/mesh networking inside Termux CLI. Without root, Termux has no `/dev/net/tun` access.
   * *The Fix:* Separated **Host-Level VPN** (running the official Android Tailscale/ZeroTier app using Android's native `VpnService` API, which automatically routes Termux ports over the `tun0` interface) from **User-Space Outbound Tunnels** (`cloudflared` binary running inside Termux).
4. **Replaced Custom Process Tracking with `termux-services` (`runit`):**
   * *The Mistake in v1.0:* Building a custom PID file tracker from scratch in Python, which breaks on PID recycling and race conditions.
   * *The Fix:* Built a clean Python wrapper around Termux's native `termux-services` (`sv` / `runit` daemon supervisor) with a lightweight pure-Python `subprocess` fallback for quick dev testing in Antigravity.
5. **Engineered for Google Antigravity Free-Tier Quota:**
   * *The Mistake in v1.0:* A massive 25+ file repository tree and a split Bash/Python architecture that forces the Antigravity AI agent to read dozens of files per prompt, rapidly burning through Free Tier context tokens and rate limits.
   * *The Fix:* Consolidated the repository into a **Flat, Context-Light Architecture** (1 thin `bootstrap.sh`, 7 core Python modules, 1 single-file HTML/CSS/Alpine.js dashboard template) and structured the roadmap into **8 Copy-Paste Antigravity Agent Sprints**.

---

## 1. Google Antigravity Free-Tier Strategy & Guardrails

To build this entire project on the **Antigravity Free Tier** without hitting rate limits or context exhaustion:

1. **Create `.antigravityignore` (or `.gitignore`) Immediately:**
   Prevent the Antigravity agent from indexing logs, virtual environments, backups, or data folders.
   ```text
   .venv/
   __pycache__/
   *.pyc
   var/
   logs/
   backups/
   data/
   ```
2. **Use `MOCK_TERMUX=1` in Antigravity's Local Terminal:**
   Antigravity runs in a standard Linux container/host, not an Android phone. We introduce an environment variable `POCKETSERVER_ENV=mock` (auto-enabled when `$PREFIX` does not contain `com.termux`). This maps `$PREFIX` to `./.mock_termux` so the Antigravity agent can run, test, and auto-verify every single feature inside the IDE before you deploy to your phone.
3. **One Sprint = One Agent Session:**
   Do not ask the agent to "build the whole project." Execute the 8 Sprints in **Section 11** sequentially. Start a fresh chat session after each Sprint passes its verification test to reset your token context window to zero.

---

## 2. Refined System Architecture & Directory Layout

### 2.1 Flat, Token-Optimized Repository Structure

```text
pocketserver/
├── .gitignore
├── README.md
├── bootstrap.sh              # Thin, idempotent Bash entry point (<120 lines)
├── pocketctl.py              # Main CLI entry point (`pocketctl start|stop|status|doctor`)
├── requirements.txt          # Pure-Python only: flask==3.0.3, werkzeug==3.0.3
├── core/
│   ├── __init__.py
│   ├── env.py                # Termux vs Mock detection, paths, wake-lock, sys metrics
│   ├── config.py             # JSON validator, atomic writes, secret generation
│   ├── supervisor.py         # Process lifecycle (runit/sv wrapper + subprocess mode)
│   ├── services.py           # Built-in profiles: Web, API, SSH, Git, Files, Tunnel, Worker
│   └── doctor.py             # Diagnostics, port scanner, Phantom Process detector, backup
├── dashboard/
│   ├── __init__.py
│   ├── app.py                # Flask app, session auth, CSRF, REST API, File & Git endpoints
│   └── templates/
│       └── index.html        # Single-file mobile UI (PicoCSS + vanilla JS, zero build step)
└── tests/
    ├── test_core.py          # Fast unit tests for config, supervisor, and path confinement
    └── test_api.py           # Fast integration tests for Flask API and auth security
```

### 2.2 Runtime Data Directory (Outside Git Repo)

- **On Real Termux:** `~/.pocketserver/`
- **In Antigravity Mock Mode:** `./.mock_termux/home/.pocketserver/`

```text
~/.pocketserver/
├── config.json               # Main validated configuration & hashed admin password
├── secret.key                # 32-byte hex key for Flask session signing
├── pids/                     # Active PID & state files
├── logs/                     # Bounded rotating logs (max 1MB per service, 2 backups)
├── data/
│   ├── www/                  # Static web server root (with default landing page)
│   ├── api/                  # Sample Python API script
│   ├── files/                # Confined file-sharing root directory
│   ├── git/                  # Bare Git repositories (`*.git`)
│   └── jobs/                 # Predefined allowlisted worker scripts
└── backups/                  # Timestamped `.tar.gz` archives
```

---

## 3. Core Technical Specifications (Mistake-Free Blueprint)

### 3.1 Environment & Hardware Telemetry (`core/env.py`)

Because Android restricts `/proc/stat` and `/proc/loadavg` on non-root devices, `core/env.py` must gather telemetry exclusively through permitted interfaces:

- **Termux Detection:** Check if `os.environ.get("PREFIX", "").startswith("/data/data/com.termux")` and `shutil.which("pkg")` exists. If `POCKETSERVER_ENV=mock` is set, use `./.mock_termux` cleanly.
- **Storage Metrics:** Use Python's standard `os.statvfs(data_dir)` to calculate total, used, and free disk space in MB/GB. Require at least `250 MB` free space before operations.
- **Memory Metrics:** Parse `/proc/meminfo` (`MemTotal`, `MemAvailable`), which remains readable on all Android versions without root.
- **Battery & Thermal (Optional Enrichment):** Check if `shutil.which("termux-battery-status")` is installed (via `termux-api` package). Run with a 2-second timeout; if unavailable, gracefully report `"N/A (Install termux-api)"` without failing.
- **Local IP Resolution:** Use a non-connecting UDP socket (`s.connect(("10.255.255.255", 1))`) inside a `try/except` block to reliably discover the phone's Wi-Fi LAN IP (`192.168.x.x`) and Tailscale/VPN IP (`100.x.y.z`) without external network traffic.
- **Wake Lock Management:** Automatically invoke `termux-wake-lock` when the first service starts, and `termux-wake-unlock` when all services are stopped.

### 3.2 Configuration & Security (`core/config.py`)

- **No External Schema Library Required:** Use a clean, deterministic Python validator checking types, port ranges (`1024–65535`), and allowed service IDs.
- **Atomic Writes:** Write updates to `config.json.tmp`, flush via `os.fsync()`, and replace via `os.replace()` so a sudden battery pull never corrupts `config.json`.
- **Credential Storage:** Admin password is never stored in plaintext. Hash with `werkzeug.security.generate_password_hash` (PBKDF2-SHA256) and verify with `check_password_hash`.

### 3.3 Process Supervisor (`core/supervisor.py`)

Handles starting, stopping, restarting, status checking, and bounded logging for all services:

1. **Execution Contract:** Services are defined purely as static Python dictionaries mapping a `service_id` to an explicit command list (`list[str]`), working directory, port, and health-check handler. **Never use `shell=True`.**
2. **Stale PID Protection:** When checking if a PID in `~/.pocketserver/pids/{id}.pid` is alive:
   - Check `os.kill(pid, 0)`.
   - Read `/proc/{pid}/cmdline` (always permitted for same-UID Termux processes) to verify the process name matches the expected binary (`python`, `sshd`, `cloudflared`). This eliminates false positives if Android recycles a PID.
3. **Bounded Log Rotation:** Redirect service `stdout` and `stderr` to `~/.pocketserver/logs/{id}.log`. Before starting or during status checks, if the log file exceeds `1 MB`, rotate `{id}.log` to `{id}.log.1` so logs can never fill phone storage.
4. **Graceful Termination:** Send `SIGTERM`, poll for up to 3 seconds, and escalate to `SIGKILL` if the process hangs.

---

## 4. Service Profiles Specification (`core/services.py`)

All 6 core services use non-privileged ports (`>1024`) and require zero compilation:

| Service ID | Display Name | Default Port | Command / Implementation | Health Check |
|---|---|---|---|---|
| `web` | Static Web Server | `8080` | `python3 -m http.server {port} --bind {bind_addr} --directory ~/.pocketserver/data/www` | HTTP `GET /` == 200 |
| `api` | Micro Python API | `8081` | Built-in lightweight WSGI/HTTP script serving JSON & `/health` | HTTP `GET /health` == 200 |
| `ssh` | OpenSSH Server | `8022` | Termux `sshd -D -p {port}` (foreground mode for clean PID tracking) | TCP socket connect on `8022` |
| `git` | Git-over-SSH | *(Uses 8022)* | Uses `sshd` + bare repositories in `~/.pocketserver/data/git/*.git` | Verify `git` binary + `ssh` running |
| `files` | Confined File Vault | *(Dashboard)* | Integrated into Dashboard `/api/files/*` with strict `os.path.realpath` confinement | Verify root dir writable |
| `worker` | Background Task Runner | *(None)* | Executes predefined Python/shell scripts in `~/.pocketserver/data/jobs/` with timeout | PID alive & exit code log |
| `tunnel` | Cloudflare Quick/Token Tunnel | *(Outbound)* | `cloudflared tunnel --url http://127.0.0.1:{target_port}` (only targets `web` or `api`) | Parse public `.trycloudflare.com` or custom URL from log |

### Strict Security Rules for Services:
- **SSH Hardening:** On setup, ensure `~/.ssh/authorized_keys` exists with `0600` permissions. Display the exact `ssh -p 8022 <whoami>@<lan-ip>` command and provide a one-command switch to disable password authentication (`PasswordAuthentication no` in `$PREFIX/etc/ssh/sshd_config`).
- **Git-over-SSH:** Creating a repo named `my-project` validates the name against `^[a-zA-Z0-9_-]+$` and runs `git init --bare ~/.pocketserver/data/git/my-project.git`. Outputs the ready-to-use clone URL: `ssh://<user>@<ip>:8022/data/data/com.termux/files/home/.pocketserver/data/git/my-project.git`.
- **File Vault Path Confinement:** Every file path requested via the API is resolved via `target = os.path.realpath(os.path.join(files_root, user_rel_path))`. If `not target.startswith(os.path.realpath(files_root) + os.sep)`, abort with `HTTP 403 Forbidden`. Reject symlinks (`os.path.islink()`).

---

## 5. Mobile Dashboard & Control API (`dashboard/`)

### 5.1 Single-File Frontend Architecture (`templates/index.html`)
- **Why Single-File?** Eliminates Node.js/Webpack build steps on the phone and lets the Antigravity agent edit the entire UI in one atomic file operation.
- **Stack:** Semantic HTML5 + **PicoCSS** (via CDN with inline fallback styles for offline LAN use) + clean Vanilla JS (`fetch()` API).
- **Mobile-First Tabs:**
  1. **Overview:** System RAM, Free Storage, Battery/Temp, Wake-Lock toggle, LAN IP, VPN IP (`tun0`), and Doctor status badge.
  2. **Services:** Start / Stop / Restart toggles, live health indicator, port badge, and LAN/Local bind toggle.
  3. **Files:** Upload (with free-space pre-check and `50 MB` default limit), download, delete, and folder view confined to `data/files/`.
  4. **Git & SSH:** Show Termux username, SSH port, authorized public keys manager (append-only via UI), and 1-click bare Git repo creator with copyable `git remote add` command.
  5. **Networking & Tunnel:** Displays Private VPN IP (`100.x.x.x` if Tailscale Android app is active) and controls the optional `tunnel` service to publish either `web` (`8080`) or `api` (`8081`) publicly with a 1-click **Revoke / Stop Tunnel** button.
  6. **Logs & Backups:** Tail last 100 lines per service (with secrets redacted), run `doctor` diagnostics, and create/download/restore configuration backups.

### 5.2 Control API Endpoints (`dashboard/app.py`)
All routes under `/api/*` (except `/api/login`) require an authenticated session cookie (`HttpOnly`, `SameSite=Lax`) and validate an `X-CSRF-Token` header:
- `POST /api/login` & `POST /api/logout`
- `GET /api/status` — System telemetry, IP addresses, wake-lock state, and all service statuses.
- `POST /api/services/<service_id>/<action>` — Where `<action>` is `start`, `stop`, or `restart`.
- `GET /api/logs/<service_id>` — Returns tail of service log with token/password regex redaction.
- `GET /api/files`, `POST /api/files/upload`, `GET /api/files/download/<path>`, `DELETE /api/files/<path>`
- `GET /api/git/repos`, `POST /api/git/repos`
- `POST /api/ssh/keys` — Safely appends a validated `ssh-ed25519` or `ssh-rsa` public key to `~/.ssh/authorized_keys`.
- `GET /api/doctor` — Runs the full diagnostic suite and returns structured pass/warn/fail results.
- `POST /api/backup/create` — Generates a clean `.tar.gz` backup of `config.json`, `www/`, `api/`, and `git/`.

---

## 6. Solving Android OS Limitations (`core/doctor.py`)

The `pocketctl doctor` command and Dashboard Doctor tab actively inspect and solve Android-specific failure modes:

| Check ID | What It Checks | Actionable Remediation Provided to User |
|---|---|---|
| `CHK-ENV` | Termux F-Droid vs Play Store build | Warns if legacy Play Store signatures or broken repos are detected. |
| `CHK-DISK` | Free storage $\ge 250\text{ MB}$ | Alerts before package installation or file uploads fail. |
| `CHK-DEPS` | `python3`, `git`, `sshd` binaries | Provides exact `pkg install -y python git openssh` command. |
| `CHK-WAKE` | Wake-lock active when services run | Runs `termux-wake-lock` and guides user to disable Android Battery Optimization for Termux. |
| `CHK-PHANTOM` | Android 12+ Phantom Process Killer | Detects Android SDK $\ge 31$ (`getprop ro.build.version.sdk`) and prints the exact Wireless ADB command to stop Android from killing background servers: `adb shell "/system/bin/device_config set_sync_disabled_for_tests persistent; /system/bin/device_config put activity_manager max_phantom_processes 2147483647"` |
| `CHK-PORTS` | Port collisions on `8080`, `8081`, `8022`, `8888` | Identifies which service or external process holds the port. |
| `CHK-BOOT` | `~/.termux/boot/start-pocketserver.sh` | Generates the auto-start boot script with `#!/data/data/com.termux/files/usr/bin/sh` if the user opts in. |

---

## 7. Step-by-Step Antigravity Execution Plan (8 Sprints)

Use these **8 structured Sprints** in Google Antigravity. Copy and paste one Sprint prompt at a time into the Antigravity Agent. Each Sprint is scoped to consume minimal tokens and includes an automated verification command.

### Sprint 1 — Foundation, Mock Environment & Hardware Telemetry
- **Goal:** Create repository structure, `.gitignore`, `requirements.txt`, and `core/env.py`.
- **Files Created:** `.gitignore`, `requirements.txt`, `core/__init__.py`, `core/env.py`.
- **Prompt for Antigravity:**
  > "Implement Sprint 1 of `POCKETSERVER_IMPLEMENTATION_PLAN.md`: Create `.gitignore`, `requirements.txt` (`flask>=3.0.0`, `werkzeug>=3.0.0`, `pytest`), and `core/env.py`. `core/env.py` must detect real Termux vs Mock mode (`POCKETSERVER_ENV=mock` or non-Termux host defaulting to `./.mock_termux`), ensure runtime directories (`config`, `pids`, `logs`, `data/www`, `data/api`, `data/files`, `data/git`, `data/jobs`, `backups`) exist, gather RAM from `/proc/meminfo`, disk metrics via `os.statvfs`, LAN/VPN IPs via UDP socket inspection, and manage `termux-wake-lock` safely."
- **Verification Command:** `python3 -c "import os; os.environ['POCKETSERVER_ENV']='mock'; from core.env import get_system_metrics; print(get_system_metrics())"`

### Sprint 2 — Atomic Configuration, Schema Validator & Auth Secrets
- **Goal:** Build `core/config.py` with atomic file writes, schema validation, and password hashing.
- **Files Created:** `core/config.py`.
- **Prompt for Antigravity:**
  > "Implement Sprint 2 of `POCKETSERVER_IMPLEMENTATION_PLAN.md`: Create `core/config.py`. Include default configuration generation (dashboard bound to `127.0.0.1:8888`, services `web:8080`, `api:8081`, `ssh:8022`, `tunnel`), strict validation (ports 1024-65535, valid bind addresses `127.0.0.1` or `0.0.0.0`), atomic file saves (`os.replace`), secret key generation, and admin password hashing/verification using `werkzeug.security`."
- **Verification Command:** `python3 -c "import os; os.environ['POCKETSERVER_ENV']='mock'; from core.config import ConfigManager; cm = ConfigManager(); cm.set_admin_password('testpass123'); assert cm.verify_password('testpass123')"`

### Sprint 3 — Process Supervisor, Bounded Logging & Built-in Services
- **Goal:** Build `core/supervisor.py` and `core/services.py` (including the default `www/index.html` and `api/server.py` payloads).
- **Files Created:** `core/supervisor.py`, `core/services.py`.
- **Prompt for Antigravity:**
  > "Implement Sprint 3 of `POCKETSERVER_IMPLEMENTATION_PLAN.md`: Create `core/services.py` and `core/supervisor.py`. Auto-seed a responsive default static page in `data/www/index.html` and a pure-Python JSON API server with `/health` and `/info` in `data/api/server.py`. In `core/supervisor.py`, manage start/stop/restart/status using `subprocess.Popen` (with `shell=False`), verify PIDs against `/proc/{pid}/cmdline` to prevent stale PID collisions, rotate logs at 1MB, redact secrets in log output, and run HTTP/TCP health checks."
- **Verification Command:** `python3 -c "import os, time; os.environ['POCKETSERVER_ENV']='mock'; from core.supervisor import Supervisor; s = Supervisor(); s.start('web'); time.sleep(1); st = s.status('web'); print(st); s.stop('web'); assert st['running']"`

### Sprint 4 — Diagnostics (`doctor`), Backups & `pocketctl.py` CLI
- **Goal:** Build `core/doctor.py` and the full CLI `pocketctl.py`.
- **Files Created:** `core/doctor.py`, `pocketctl.py`.
- **Prompt for Antigravity:**
  > "Implement Sprint 4 of `POCKETSERVER_IMPLEMENTATION_PLAN.md`: Create `core/doctor.py` (implementing checks `CHK-ENV`, `CHK-DISK`, `CHK-DEPS`, `CHK-WAKE`, `CHK-PHANTOM` with the Android 12+ ADB command helper, `CHK-PORTS`, `CHK-BOOT`, plus `.tar.gz` backup create and restore functions) and `pocketctl.py` supporting commands: `init`, `status`, `start <id>`, `stop <id>`, `restart <id>`, `logs <id>`, `doctor`, `backup`, `restore <file>`, and `passwd`."
- **Verification Command:** `POCKETSERVER_ENV=mock python3 pocketctl.py doctor`

### Sprint 5 — Secure Flask Control API, Confined File Vault & Git/SSH Manager
- **Goal:** Build `dashboard/app.py` with authentication, CSRF protection, service control routes, path-confined file management, and Git-over-SSH repo creation.
- **Files Created:** `dashboard/__init__.py`, `dashboard/app.py`.
- **Prompt for Antigravity:**
  > "Implement Sprint 5 of `POCKETSERVER_IMPLEMENTATION_PLAN.md`: Create `dashboard/app.py`. Include session authentication, CSRF token verification on state-changing requests, service lifecycle routes, path-confined file upload/download/delete/list (`os.path.realpath` check blocking traversal and symlinks), bare Git repo initialization (`git init --bare`), SSH public key append validation, and backup/doctor API endpoints."
- **Verification Command:** `python3 -c "import os; os.environ['POCKETSERVER_ENV']='mock'; from dashboard.app import create_app; app = create_app(); print('Routes:', [r.rule for r in app.url_map.iter_rules()])"`

### Sprint 6 — Single-File Mobile Dashboard UI (`dashboard/templates/index.html`)
- **Goal:** Build the complete responsive mobile dashboard in a single HTML file.
- **Files Created:** `dashboard/templates/index.html`.
- **Prompt for Antigravity:**
  > "Implement Sprint 6 of `POCKETSERVER_IMPLEMENTATION_PLAN.md`: Create `dashboard/templates/index.html` using a clean mobile-first dark/light layout with inline/CDN CSS and Vanilla JS. Include Login modal, Overview telemetry cards (RAM, Storage, LAN/VPN IPs, Wake-Lock), Service controls with live health badges, File Vault browser/uploader, Git repo creator & SSH key installer, Tunnel publisher with 1-click revoke, and Logs/Doctor/Backup views."
- **Verification Command:** Run `POCKETSERVER_ENV=mock python3 pocketctl.py start dashboard` (or run Flask test client) and verify `GET /` returns `200 OK`.

### Sprint 7 — Automated Unit & Security Test Suite (`tests/`)
- **Goal:** Prove every P0 and P1 requirement via automated `pytest` tests inside Antigravity.
- **Files Created:** `tests/test_core.py`, `tests/test_api.py`.
- **Prompt for Antigravity:**
  > "Implement Sprint 7 of `POCKETSERVER_IMPLEMENTATION_PLAN.md`: Create `tests/test_core.py` and `tests/test_api.py`. Test config validation, service start/health/stop lifecycle, backup & restore roundtrip, unauthorized API rejection, CSRF protection, path traversal prevention (`../../etc/passwd` returning 403), and bare Git repository creation. Run `pytest` and fix any issues."
- **Verification Command:** `POCKETSERVER_ENV=mock pytest -v`

### Sprint 8 — Idempotent Termux Installer, Uninstall & Documentation
- **Goal:** Create `bootstrap.sh`, `uninstall.sh`, and `README.md`.
- **Files Created:** `bootstrap.sh`, `uninstall.sh`, `README.md`.
- **Prompt for Antigravity:**
  > "Implement Sprint 8 of `POCKETSERVER_IMPLEMENTATION_PLAN.md`: Create `bootstrap.sh` (idempotent Termux setup checking `$PREFIX`, running `pkg update && pkg install -y python git openssh termux-api termux-services`, creating a symlink `$PREFIX/bin/pocketctl`, running `pocketctl init`, and printing clear next steps), `uninstall.sh` (stopping all services and preserving `~/.pocketserver/data` unless `--purge-data` is passed), and a comprehensive `README.md`."
- **Verification Command:** `bash -n bootstrap.sh && bash -n uninstall.sh && POCKETSERVER_ENV=mock pytest`

---

## 8. Final Acceptance Criteria Checklist (Zero-Mistake Gate)

- [ ] **Zero-Compile Install:** `requirements.txt` installs in `<10 seconds` on Termux without invoking `clang` or `rust`.
- [ ] **Android 10–15 Compatible:** Telemetry never calls restricted `/proc/stat` or `psutil` APIs that crash on non-root Android.
- [ ] **Background Survival:** `termux-wake-lock` triggers automatically when services run, and `pocketctl doctor` prints the exact Android 12+ Phantom Process fix.
- [ ] **CLI-First Resilience:** `pocketctl` starts, stops, inspects, and diagnoses all services even if the web dashboard is stopped.
- [ ] **Strict Security Gate:** Dashboard binds to `127.0.0.1` by default, requires PBKDF2-hashed password login, enforces CSRF tokens, and uses `shell=False` for all subprocess execution.
- [ ] **Confined File Sharing:** Path traversal (`../`) and symlink escapes in the File Vault are blocked and verified by `pytest`.
- [ ] **Idempotent & Recoverable:** Re-running `bootstrap.sh` or `pocketctl init` never overwrites user files or existing passwords; `uninstall.sh` preserves user data by default.