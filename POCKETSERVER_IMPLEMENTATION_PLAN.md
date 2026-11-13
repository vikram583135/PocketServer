# PocketServer implementation plan v3

Date: 2026-11-13  
Baseline reviewed: commit `7d84f56`  
Status: implementation specification; application changes have not been made  
Reference: `pocketserver_implementation_plan_antigravity_edition.md`, retained as historical context

This plan supersedes the reference plan for future implementation. It is based on reading every existing Python source file, including the embedded HTML and generated API program, the dependency manifest, ignore files, and repository audit instructions. The repository contains seven Python files, not the completed application described in the reference plan.

The objective is a maintainable, recoverable, single-owner server for non-root Termux. There is no credible guarantee of zero bugs or uninterrupted Android background execution. Instead, this plan defines ownership boundaries, failure behavior, tests, and release gates. A gate without evidence remains incomplete.

## 1. What exists and what must change

### 1.1 Repository inventory

| Existing file | Actual implementation | Disposition |
|---|---|---|
| `pocketctl.py` | CLI initialization, lifecycle commands, logs, diagnostics, backup/restore, password change | Retain the command entry point; repair contracts and error handling |
| `core/__init__.py` | Package marker and application version `2.0.0` | Keep; separate application and configuration schema versions |
| `core/env.py` | Environment/path selection, telemetry, wake-lock command wrappers | Refactor around an injectable runtime context and honest capability reporting |
| `core/config.py` | Partial JSON validation, cached config, password hashes, atomic replacement, secret generation | Harden persistence, validation, locking, initialization and migrations |
| `core/services.py` | Five process profiles, HTTP/TCP probes, generated web/API examples, tunnel URL parser | Separate profile definitions, supported HTTP servers, and example data |
| `core/supervisor.py` | Detached subprocesses, PID files, startup-only log rotation | Replace production lifecycle authority with runit; remove unsafe PID control |
| `core/doctor.py` | Diagnostics, boot script generation, direct tar backup/restore | Keep read-only diagnostics; move backup and boot responsibilities into focused modules |
| `requirements.txt` | Flask/Werkzeug version ranges plus pytest | Split production/development inputs and create a verified dependency lock |
| `.gitignore`, `.antigravityignore` | Runtime/cache exclusions | Preserve; extend for future build and test artifacts |
| `.gemini/skills/post-build-audit-and-verification/SKILL.md` | Repository verification/remediation workflow | Observe during implementation; evidence must distinguish tests from review |

Missing: dashboard package and UI, tests, actual runit integration, installer, uninstaller, README, Git/key management, confined file operations, and a worker implementation. Existing ignored mock configuration and credentials are user runtime state, not test fixtures. Their secret contents were not needed for this review.

### 1.2 Findings traced to the baseline

Locations below refer to the reviewed baseline, before any future refactoring. P0 means safety/security or data-loss blocker; P1 means functional/reliability release blocker; P2 means correctness/documentation gap. These are source-review findings, not results from an executed test suite or a successful kluster scan.

| ID | Priority | Evidence | Required resolution |
|---|---|---|---|
| F01 | P0 | `core/supervisor.py:132-145,280-295` | Windows liveness calls `os.kill(pid, 0)` before platform-specific handling. Replace it with a non-destructive backend. On Windows, Python documents non-console-event signals as termination requests. [Python OS documentation](https://docs.python.org/3/library/os.html#os.kill) |
| F02 | P0 | `core/supervisor.py:251-295` | Stop trusts a PID file and can signal an unrelated process. Persisted PIDs must never authorize termination. |
| F03 | P0 | `core/config.py:174-184` | Load errors silently replace configuration with defaults and an empty password hash. Preserve the file and fail closed. |
| F04 | P0 | `core/config.py:186-235,269-296` | No interprocess lock, shared temporary names, cached stale snapshots, racing secret creation, and invalid updates that poison in-memory state. Implement transactions. |
| F05 | P0 | `core/config.py:81-146,191-192` | Incomplete schema allows missing fields/metadata, wrong boolean types, non-finite durations and disabled CSRF. Enforce the full schema and invariants. |
| F06 | P0 | `core/doctor.py:346-370` | Restore extracts directly over live state, accepts unsafe member types, validates too late, and has no rollback or limits. Replace it with staged recovery. |
| F07 | P0 | `core/services.py:367-377` | SSH ignores bind configuration and inherits global sshd policy. Use a dedicated, validated, key-only configuration. |
| F08 | P0 | `core/services.py:380-405`; `core/supervisor.py:218-226` | Token mode does not use the local target restriction; full secret-bearing argv is persisted. Separate tunnel modes and remove secret-bearing state. |
| F09 | P0 | `core/env.py:69-86`; `core/config.py:197-202,269-294`; `core/doctor.py:327-341` | Private modes are not established for all directories/config/temp files/backups; existing secret validation is weak. Enforce private storage and explicit rotation. |
| F10 | P1 | `core/supervisor.py:160-249,251-327` | No serialized transitions, startup rollback, reliable readiness deadline, stop verification, or descendant ownership policy. |
| F11 | P1 | `core/supervisor.py:187-195,418-428` | Logs grow unbounded while running; tail reads the entire file. Use continuous rotation and bounded reads. |
| F12 | P1 | `core/supervisor.py:231-236,302-308`; `core/config.py:204-208` | Dashboard enabled changes affect a copy and are not persisted. Separate autostart preferences from observed state. |
| F13 | P1 | `core/services.py:408-421`; `core/supervisor.py:200` | Dashboard is missing, and its module launch from runtime cwd will also need an installed/importable application path. |
| F14 | P1 | `pocketctl.py:176-184,226-229` | Bulk start returns success on failures; bulk restart stops more profiles than it starts. Specify exact target sets and aggregate results. |
| F15 | P1 | `core/doctor.py:316-341` | Backups omit file-vault contents, can collide within a second, include sensitive/executable material without policy, and do not quiesce writers. |
| F16 | P1 | `core/env.py:259-312`; `core/supervisor.py:228-247` | Wake-lock commands ignore exit status; stale markers imply success; failed starts leak requested state. |
| F17 | P1 | `core/env.py:125-215`; `core/doctor.py:181-196` | Fake telemetry and unknown SDK can become success; a `100.*` address is treated as VPN proof. Report provenance and unknown states. |
| F18 | P1 | `core/doctor.py:149-166,210-224,239-246` | PID/script existence is mistaken for service ownership, wake-lock verification, or working boot integration. |
| F19 | P1 | `core/services.py:336-349`; reference plan sections 4-5 | Public static serving and file-vault security lack protection against ancestor links, races, active-content handling, and resource exhaustion. |
| F20 | P1 | `core/config.py:237-249`; `pocketctl.py:344` | Four-character passwords and password-in-argv setup are unsuitable for administration. Strengthen policy and use hidden input/stdin. |
| F21 | P1 | `requirements.txt:1-4`; reference plan sections 2,7,8 | Conflicting version policies, mixed dev dependencies, and no evidence that the transitive install avoids on-device compilation. |
| F22 | P2 | `core/supervisor.py:112-116`; `core/config.py:152-165`; `core/doctor.py:56-58` | Status/diagnostics construct managers that initialize/seed files. Make inspection read-only. |
| F23 | P2 | `core/services.py:299-309,449-455,468-480` | HTTP redirects/any listener can look healthy; tunnel health is unconditional and URL parsing selects old output. |
| F24 | P2 | `pocketctl.py:108-114`; `core/services.py:145-151` | Connection instructions advertise default ports and unreachable/misleading loopback/LAN links. Generate them from effective state. |
| F25 | P1 | Reference plan sections 0,3,6,8 | Claimed runit replacement conflicts with the Popen sprint; platform/availability claims exceed evidence; tests arrive too late. Resolve these before feature work. |

### 1.3 Corrections to the reference plan

- Use `POCKETSERVER_ENV` consistently; remove the unsupported `MOCK_TERMUX` instruction and broken sprint-section reference.
- Do not constrain security boundaries to an arbitrary file count, a one-file dashboard, or a shell-script line limit.
- A route-selected address is not proof of Wi-Fi identity, VPN membership, or inbound connectivity. No hardcoded `tun0` assumption.
- Wake locks are mitigation requests. Android Doze can restrict networking and ignore wake locks; force-stop, OOM, reboot and OEM policies remain outside this application's control. Remove the fixed five-minute claim. [Android Doze documentation](https://developer.android.com/training/monitoring-device-state/doze-standby)
- F-Droid/GitHub Termux builds are the initial qualification target. Do not identify installation origin from `PREFIX`, or label every Play Store build obsolete: Termux documents a separate experimental Play branch. [Termux installation documentation](https://github.com/termux/termux-app#installation)
- `/proc` availability is a capability to probe, not a universal promise. Failure must not crash status or invent values.
- No fixed installation-time promise. The measurable requirement is a reproducible installation with no compiler invocation on the phone.
- Mock tests establish application behavior under simulation. They cannot establish Android survival, Android filesystem behavior, or actual VPN reachability.

## 2. Product scope and security boundary

### 2.1 Supported modes

| Mode | Contract |
|---|---|
| Production | Non-root Termux on Android, app-private internal storage, runit backend, validated package/interpreter versions |
| POSIX development | Isolated temporary runtime; fake backend by default; real subprocess integration only in a harness that owns its child handles |
| Windows development | Schema/API/UI tests with fake backend and an optional foreground demo; no detached cross-invocation PID control |

Android 8+ remains a compatibility goal, not a certified range. Record actual tested Android, Termux, Python, architecture and OEM versions in the release matrix. Python 3.11 is the minimum code baseline; a Python minor version is release-supported only after its dependency/install/test matrix passes. No-root Android filesystem and process behavior must be tested on a physical device.

`POCKETSERVER_ENV=auto|termux|mock` selects mode. An invalid value is an error. Explicit Termux mode fails on missing capabilities rather than falling back. Auto mode reports the decision and rejects an ambiguous/broken Termux environment for mutating production operations. `POCKETSERVER_HOME` can supply an absolute runtime root; validate it and reject repository `.git`, external/shared Android storage for production, symlink roots, and unsafe permissions.

### 2.2 Capability model

| Identifier | Type | Delivery/default |
|---|---|---|
| `dashboard` | Managed process; private administration | Required; loopback port 8888 |
| `web` | Managed static-content process | Required; loopback port 8080 |
| `api` | Managed example/application HTTP process | Required; loopback port 8081 |
| `ssh` | Managed OpenSSH process | Optional dependency; key-only, loopback port 8022 |
| `tunnel` | Managed outbound Quick Tunnel process | Optional, explicit publication only; never autostart |
| `files` | Authenticated dashboard capability | Required; no independent PID or port |
| `git` | Repository management plus SSH transport | Optional dependency; no independent listener |
| `worker` | Bounded job capability hosted by an owned runner | Implement after core administration; disabled until jobs are registered locally |
| `controller` | Internal runit-managed operation/reconciliation process | Required infrastructure, bootstrapped by CLI/boot; no generic HTTP lifecycle controls |

All original capabilities have an implementation phase below. Remotely managed token/custom-domain tunnels, arbitrary remote command entry, public dashboard hosting, and browser-triggered restore are explicitly outside the first release. Their missing security/recovery contracts must be designed before adding them; they must not appear as functioning controls.

### 2.3 Trust assumptions

- One trusted owner administers the Termux account. Dashboard credentials, full-shell SSH keys, installed custom API code and locally registered jobs convey administrator-level trust within that account.
- Network clients, uploaded files, filenames, logs, imported archives and browser origins are untrusted inputs. A syntactically valid archive is not proof its scripts or Git hooks are safe.
- Same-UID malicious programs are outside the isolation boundary: they can access Termux files and secrets directly. File confinement is not a sandbox for hostile Python jobs or shell users.
- Administrative HTTP stays on loopback. Remote administration uses SSH local forwarding; the browser connects to a loopback endpoint. A raw LAN dashboard bind is rejected in the first release. This replaces the reference plan's unsafe LAN-admin toggle.
- Web/API may bind to LAN or be published only through explicit configuration/publication operations. They contain no control API, session keys, file vault, backup contents, or private telemetry.
- Browser cookies are not isolated by port. Supported web/API servers must not echo/log cookie headers; no secrets belong in public content. Untrusted executable applications require a separate origin/account boundary and are not sandboxed by this product.

## 3. Architecture and shared contracts

### 3.1 Module responsibilities

Keep existing public entry points where practical, but split risky responsibilities deliberately:

| Module or area | Responsibility |
|---|---|
| `core/runtime.py` | Immutable runtime context, mode, paths, capability adapters, injected clock/process/filesystem interfaces |
| `core/locking.py` | OS-backed process locks, timeouts and documented acquisition order |
| `core/config.py` | Schema, credential policy, transactional configuration and explicit migrations |
| `core/env.py` | Telemetry and wake-lock requests, without implicit initialization |
| `core/services.py`, `core/service_entry.py` | Validated profiles and trusted foreground entry points |
| `core/supervisor.py` | Backend interface, runit adapter, transitions, dependency ordering, observations |
| `core/storage.py` | Confined filesystem operations and aggregate disk reservations |
| `core/backups.py` | Archive policy, staging, maintenance and recovery journal |
| `core/ssh_git.py` | Dedicated SSH configuration, validated keys and repository operations |
| `core/jobs.py` | Local job definitions, queue, timeout/cancellation and result retention |
| `core/http_services.py` | Supported static and sample API WSGI applications |
| `core/doctor.py`, `core/boot.py` | Read-only diagnostics and explicit boot installation/removal |
| `dashboard/app.py`, `auth.py`, `routes.py` | App factory, authentication and thin routes calling core operations |
| `dashboard/templates/`, `dashboard/static/` | Offline mobile UI with local CSS/JS assets |
| `tests/`, `scripts/`, installer/docs | Contract tests, controlled device checks, packaging and user documentation |

Do not move all code at once. Introduce boundaries during the phase that needs them, preserving existing user data. Dependency direction is CLI/dashboard -> core operations -> adapters. Core modules must not import dashboard routes.

### 3.2 Runtime storage

Preserve the existing root `~/.pocketserver` and logical data paths during migration:

```text
config.json             versioned persistent settings, password hash, auth generation
secret.key              private session signing material
state.sqlite3           bounded sessions, operations, jobs and disk reservations
state/                  non-secret observations and recovery markers
locks/                  stable lock files; never removed as a way to break a live lock
logs/                   bounded app/job logs; runit logs have their registered locations
data/www/               public static content
data/api/               owner-controlled API assets/custom code
data/files/             private file vault
data/git/               bare repositories
data/jobs/              locally registered trusted jobs
ssh/                    PocketServer-only SSH config, host keys and authorized keys
backups/                complete private archives and manifest metadata
staging/                private temporary uploads/archive work
recovery/               durable restore/migration journal and preserved old files
```

Production directories use mode 0700; credentials/config/database/backups use 0600 from creation, with process umask 0077. Set executable permissions only on known launchers/scripts that require them. Verify ownership and reject symlink/reparse-point substitutions. Windows mock tests check functional behavior; do not describe POSIX modes as Windows ACL enforcement.

`sqlite3` is a standard-library capability checked at installation; it introduces no pip native dependency. Use short transactions, bounded busy timeouts, explicit schema versions, and a single operation executor. Never hold a database transaction while waiting for a service/network operation. State DB contents are excluded from backups and may be reconstructed only through explicit recovery; DB corruption must invalidate sessions and disable mutations, not silently recreate authentication state while requests are active.

### 3.3 Concurrency, operations and errors

- Separate a long-lived shared/exclusive maintenance lease from a short operation mutex. Uploads, Git writes and running jobs hold shared maintenance protection; backup/restore obtain exclusive protection. The operation mutex serializes bounded transitions across CLI, dashboard and boot, not the whole duration of a job or archive stream. In-process locks supplement process locks. Use `fcntl` on POSIX and a tested Windows adapter for mock data operations.
- Lock acquisition order: maintenance lease -> operation mutex -> configuration lock -> resource lock. No upgrades from shared to exclusive maintenance are allowed. Announce maintenance intent to reject new writers, then wait/refuse for existing writers outside the operation mutex. Cancellation, shutdown and completion bookkeeping may acquire the operation mutex without a new maintenance lease, but must never acquire maintenance afterward. This lets a job finish or cancel while backup waits. Read-only status uses bounded observations and performs no cleanup or repair.
- Acquire locks with a deadline. A timed-out request returns `busy`; it must not create a second unowned operation. OS locks release on process death; file timestamps do not establish ownership.
- Dashboard mutations that can outlast a request are handled by an independent runit-managed controller, using the bounded local operation store. A single dispatcher starts owned asynchronous jobs/archive work and remains available for cancellation/reconciliation; it does not block for a job's entire lifetime. CLI uses the same core layer while the dashboard is down. An exclusive lifetime lock prevents duplicate controller dispatchers. CLI-only stop/restart of the controller runs outside that controller, drains/reconciles queued work, and records the result externally.
- Operations carry an ID, actor, action, target, creation/update time, phase, result and sanitized error. Queue limit: 16 pending operations; retention: 200 terminal operations or seven days. Reject excess work instead of growing indefinitely.
- Accept an idempotency key for queued mutations. Repeating the same key/action/body returns the prior operation; reuse with a different body returns conflict. Interrupted operations are reconciled against actual ownership before retry, never blindly replayed.
- Structured errors use stable codes such as `invalid_config`, `not_initialized`, `unsupported`, `busy`, `port_in_use`, `start_failed`, `stop_failed`, `insufficient_storage`, `unsafe_path`, `invalid_archive` and `recovery_required`. Human messages are actionable but contain no raw secrets or traceback.

## 4. Configuration, initialization and migration

### 4.1 Schema

Introduce integer `schema_version: 3` independently of the app version and required integer `revision`, initially 1. Every successfully committed mutation increments revision once. An expected revision mismatch returns conflict without writing. Auth generation is a separate monotonic security counter that ordinary settings edits cannot supply/decrease; restore/recovery advances it relative to the current installation. The schema specifies every required field, optional field, default, type and bound. Reject unknown keys on normal writes; migration explicitly maps known legacy fields. Reject duplicate JSON keys and NaN/Infinity during decoding. Validate exact booleans and exact integer ports, not Python's permissive bool-as-int behavior.

Minimum schema decisions:

- Dashboard: fixed loopback bind, port 1024-65535, absolute session lifetime 8 hours, idle lifetime 30 minutes, both bounded by schema; explicit trusted host/origin settings.
- Processes: `autostart` is a preference; lifecycle status is never persisted here. Fresh initialization leaves all autostart flags false. Tunnel autostart is always false.
- Web/API/SSH: explicit port and bind; allowed binds are `127.0.0.1` and, for these data services only, `0.0.0.0`. No IPv6 listener in the first release. Advertise this limitation.
- Reserve unique numeric listener ports across all profiles and any internal health endpoint, including disabled ones, to avoid ambiguous future starts. Internal ports are loopback-only and never tunnel targets.
- Files: default maximum file size 50 MiB, permitted range 1-1024 MiB; request limits include bounded multipart overhead and field/part counts.
- Tunnel: Quick mode and target ID `web|api` only. Reject token/domain fields in new configuration; migration preserves them in the private legacy snapshot and disables that feature.
- Auth: recognized hash format, mandatory CSRF, integer auth generation and initialization state. No configuration switch disables CSRF.
- Jobs: local registry references only, concurrency one, queue ten, default timeout 60 seconds, maximum 3600 seconds. No command text in the HTTP-facing schema.
- Logs/backups/operations: explicit byte/count/time bounds; finite numbers only; metadata fields required and validated.

### 4.2 Persistence contract

Every configuration mutation acquires the config lock, reloads the latest committed data, checks an expected revision if supplied, applies changes to a copy, validates, writes a uniquely named same-directory temporary file, flushes and fsyncs it, atomically replaces the destination, and fsyncs the parent directory where supported. Validation or write failure before replacement leaves memory/disk at the previous state. Replacement is the logical commit point: if subsequent directory synchronization fails, reload/reconcile the committed revision and return `durability_uncertain`/`recovery_required`, blocking further mutations until resolved. Do not falsely promise rollback to the old file after a successful replace. Publish a successful snapshot only after the supported durability steps complete.

On a platform without directory synchronization, document the reduced power-loss durability instead of asserting a guarantee. All getters return detached values. File permission or parse failures do not rename/reset files during load. Recovery is an explicit command that preserves the original with a unique name.

Create a session key exactly once under the same initialization lock. Accept exactly 64 hexadecimal characters representing 32 random bytes. An unreadable or malformed existing key blocks authenticated startup; rotation is an explicit action and revokes existing sessions. Do not briefly create a world-readable temporary key and chmod it later.

### 4.3 Initialization and credentials

`init` alone creates directories and missing seed content using exclusive creation. Running it twice preserves passwords, keys and user content. Status/doctor on a fresh directory report `not_initialized` without creating anything. Constructors perform no filesystem writes.

Use hidden interactive password input, or explicit `--password-stdin` for automation. Remove plaintext password arguments. Enforce 12-128 characters centrally; no mandatory composition gimmicks. Password length cannot be recovered from a stored hash: preserve every legacy hash but mark its policy unverified, requiring local `passwd` before dashboard authentication is enabled. Keep PBKDF2-SHA256 through Werkzeug with an explicit reviewed work factor, rate limits and maximum input length; measure its cost on the target phone. Rehash obsolete accepted hashes after successful authentication. Password changes increment auth generation and revoke all existing sessions.

### 4.4 Upgrade from current v2 data

1. Read and validate the legacy input without modifying it; produce a migration report containing mappings, disabled features and required operator actions, with secrets redacted.
2. Refuse migration while legacy services may be running. PID files are clues only; never feed them to the existing unsafe stop logic. If safe ownership cannot be established, require the owner to close the known Termux session/processes or reboot, then retry.
3. Acquire maintenance/config locks and create a private immutable pre-migration snapshot. Quarantine legacy PID/wake markers as evidence, not live authority.
4. Map `enabled` to proposed `autostart` preferences, but require explicit enablement before first boot reconciliation. Force tunnel off; add SSH loopback/key-only policy; preserve public data and credentials exactly.
5. Write schema v3 transactionally; install runit entries in the down state. Record a migration version/journal and validate the new application without opening listeners.
6. On failure, leave services down and restore the preserved configuration. If data representation ever changes, rollback must restore the matching data snapshot as well as code.

No upgrade starts a public listener, rotates a password silently, or overwrites a user's API program with a new example.

## 5. Process lifecycle, logging and power state

### 5.1 Production authority

Use Termux's runit service directory with a reserved `pocketserver-` prefix. Generate only owned entries; never alter unrelated `sshd` or other installed services. Installer validates `sv`, `runsv`, `svlogd` and the service daemon before marking supervision available. Missing runit is a production error, never a hidden fallback to detached PIDs. Termux documents distinct service start/stop and enable/disable operations; preserve that distinction. [termux-services](https://github.com/termux/termux-services)

Each run script uses safely quoted, absolute installation paths and a fixed allowlisted service ID, then `exec`s a trusted foreground entry point. Launch with the installed interpreter and a defined working directory/import path; no dependency on the caller's cwd. Python subprocess APIs use argument arrays and `shell=False`. Generated runit/boot shell wrappers contain no interpolated request text or secrets.

Production status derives from runit ownership plus readiness. Persisted observation JSON is advisory only. Never adopt an arbitrary listener because it answers HTTP, or an arbitrary Python process because its name contains `python`. Validate every service ID before deriving paths in every public core method, including stop and logs. All ordinary service directories retain their `down` file so a fresh runsv daemon starts them down; only explicit controller reconciliation issues `sv up` for the permitted set. The controller's own owned launch gate checks initialization/recovery before dispatch. CLI can bootstrap/recover it without a working dashboard.

The fake backend has the same operation/status contract. Real host integration tests retain `Popen` handles and reap only their own children; they must not reopen and signal arbitrary PIDs on later CLI invocations. Windows production background services are not claimed.

### 5.2 State machine and semantics

Lifecycle: `stopped -> starting -> running -> stopping -> stopped`, with `failed`, `unsupported` and `unknown` outcomes. Readiness is a separate `ready|unready|unknown` value. A running but unready process displays `degraded`, never healthy.

Start protocol:

1. Validate initialized credentials where required, schema, backend, executable, paths, disk headroom and dependencies under the operation lock.
2. Reject conflicting listener configuration. A bind probe is advisory; actual child bind/readiness is authoritative because ports can race.
3. Request wake lock, start the owned runit service, and poll ownership/readiness with a monotonic deadline: 10 seconds normally, 30 seconds for tunnel establishment.
4. Confirm the profile-specific response and current run identity where available. On failure, request stop, verify stopped, remove only this operation's transient state, and reconcile wake demand.
5. Return a structured terminal result. Never report successful start just because 300 ms elapsed or a PID exists.

Stop protocol: request runit down first to suppress restart, allow 5 seconds for orderly shutdown, then a bounded 2-second hard-stop phase. Confirm stopped; preserve evidence and return `stop_failed`/`unknown` if ownership or termination is uncertain. Restart never starts a second instance after a failed stop.

Define process-family behavior explicitly. Web/API/dashboard use bounded threads. A job runner owns its subprocess group, forwards cancellation, kills remaining owned children and reaps them. For SSH, stopping the listener is not proof existing sessions were revoked: track/report active sessions, and block backup/restore quiescence while sessions capable of writing are still active. Never terminate unverified same-UID processes to make a check pass.

Bound restart storms: at most three automatic retries within 60 seconds, with 1/2/4-second delays; then hold the profile down with an actionable error until explicit retry. Runit respawns must pass an owned run/finish launch gate that atomically checks desired state, recovery state, a current controller activation epoch and the persisted retry budget before every payload exec. Controller polling alone is insufficient. Invalid/missing gate state keeps the payload down and reports failure, never launches optimistically. The gate waits without repeated payload launches until permitted; a real-runit crash-storm test verifies this. A new boot/controller recovery reconciles private services explicitly and invalidates tunnel activation. Tunnel dependency loss causes it to be taken down; restoring the target does not silently republish it.

`start all` means enabled autostart processes, excludes tunnel, and fails clearly when none are selected; it bootstraps the controller as infrastructure. `stop all` means every owned running process, with tunnel/jobs first and dashboard/controller last, orchestrated by an external CLI invocation. `restart all` snapshots the currently owned running set and restores that same set, bootstrapping infrastructure before payloads; tunnel publication requires explicit reapproval and is reported as stopped/reapproval-required rather than silently republished. Failed items produce a nonzero aggregate result. `enable`/`disable` change boot preference only. HTTP cannot request `all` or stop/restart its own dashboard/controller through an alias or operation queue.

### 5.3 Health and effective state

- Dashboard: a minimal unauthenticated `/healthz` response with a fixed service marker, no user/system details.
- Web: a reserved health path with a fixed marker; static content cannot override it.
- API: exact `/health` JSON contract; a redirect or HTML response does not count.
- SSH: verified runit ownership plus valid SSH banner and loaded dedicated configuration; not just any open TCP socket.
- Tunnel: origin ready, current connector ready, and a current-run URL. Process existence alone is insufficient. Report upstream connectivity unknown when the connector cannot establish it.
- Files/Git: capability prerequisites and confined-root checks, not fictional PIDs.

Status reports desired autostart, observed lifecycle, readiness, backend, effective bind/port, optional PID, run ID, monotonic-derived uptime, observation time, and sanitized last error. Report effective running configuration separately from pending configuration. Changing bind/port on a running service returns `restart_required`; stop a dependent tunnel before applying that restart.

### 5.4 Logs

Use `svlogd` for continuously drained production stdout/stderr. Configure 1 MiB rotation and two retained archives per process. Define and verify the actual maximum overshoot from the selected logger's input/line buffering; cap or split pathological lines before disk writes so a missing newline cannot defeat the bound. Use bounded chunks and a drop/backpressure policy that cannot exhaust RAM. Budget all runit/controller/job logs together, default 32 MiB total, and expose dropped-output counts.

Tail seeks backward with a byte ceiling of 64 KiB and a line range of 1-1000; huge single lines are truncated explicitly. No full-file reads. Prevent credentials from entering logs/state in the first place; redact known sensitive fields and configured secret values as defense in depth. Strip terminal control sequences from displayed logs. HTTP has no unredacted mode; local raw access is explicit owner access.

### 5.5 Wake locks and telemetry

Check command exit status and timeout. Store `requested|released|failed|unknown`, last result and boot/run context; a marker is never proof of an OS-held lock. Reconcile demand from owned active services and executing jobs, including failure paths and crashes. The controller runs reconciliation at most every five seconds and during each lifecycle transition. Its own idle process does not demand a wake lock.

Termux wake locks are shared with other work in the Termux app and are not safely attributable to this program. Offer an explicit installation policy: `pocketserver-managed` (owner delegates wake-lock control) or `manual` (PocketServer reports guidance and never unlocks). Do not claim per-application ownership the platform does not expose. A UI policy control follows this same contract, without a misleading verified-active toggle.

Telemetry values have `available`, `value`, `unit`, `source`, `observed_at` and `reason`. Missing memory/battery/network values are null, not zero or fabricated success. Fixtures must say simulated. Battery commands require both the CLI capability and a working compatible Termux:API app; timeout remains two seconds. Network lookup has bounded work, closes sockets on every path, and distinguishes discovered addresses from user-supplied advertisement and actual connectivity tests.

## 6. HTTP services and authenticated dashboard

### 6.1 Server and transport

Use Flask application factories with a vetted pure-Python Waitress deployment, debug/reloader disabled. Waitress is documented as a pure-Python WSGI server and buffers request bodies; set limits at the server boundary as well as in Flask. Do not assume an application streaming loop prevents upstream buffering. [Flask deployment documentation](https://flask.palletsprojects.com/en/stable/deploying/waitress/)

Initial dashboard bounds: four request threads, four open connections, 30-second inactive connection timeout, 16 KiB headers, 64 KiB route-level JSON bodies, and one active upload/backup writer. Queue overflow returns busy. The server-level body ceiling is the file limit plus 1 MiB multipart overhead. Public web/API have separate server-level ceilings of 64 KiB and at most 16 connections each; static routes accept GET/HEAD only. Per-IP/global limits must not depend on untrusted forwarded headers.

Choose the conservative reservation strategy: before each listener starts, reserve its entire connection-count times server-body-ceiling envelope, plus documented parser/queue overhead, application staging, and 250 MiB untouched headroom, summed across all listeners. Reservations for server buffers remain allocated for the listener lifetime and cannot be promised to backups/uploads again. Configure temporary-body storage inside private staging and prove the selected server bounds pipelining/body queues and enforces the ceiling before buffering. For default dashboard uploads the body envelope alone is 4 x 51 MiB. Reject listener start or settings increases when the full budget cannot be reserved. Flask authentication, route-level JSON checks and an upload semaphore happen too late to reduce this upstream envelope. Stress unauthenticated/slow/chunked/pipelined bodies in integration tests; if the server cannot honor the budget, block release until a tested pre-buffer admission layer is supplied.

Dashboard binds to loopback; allow only configured Host values (`localhost` and `127.0.0.1` with the effective port by default). Reject invalid Host before processing requests; trust no arbitrary `Forwarded`/`X-Forwarded-*` headers. No wildcard CORS. HTTPS remote administration is a future explicit deployment mode; setting a Secure cookie on plain HTTP is not a substitute for designing it.

Public static serving uses `core/storage.py` confinement, disables directory listing, rejects dot/private files and link traversal, and serves only the declared public root. The example API exposes minimal public data and health, not Python/platform details or management telemetry. Custom code is trusted owner code. Before publication, require owner acknowledgment that content is public and custom code is not sandboxed.

### 6.2 Authentication and browser protections

- Uninitialized/invalid credential state refuses administration; setup and recovery are local CLI operations.
- `GET /api/session` creates a bounded pre-auth session and CSRF token; `POST /api/login` requires that token and a valid same-origin request. Rotate session ID and CSRF token on login.
- Store signed session IDs in HttpOnly, host-only, SameSite=Strict cookies. Session records in the private state database enforce expiry and logout revocation. Cookies contain no password hash, tunnel credential or authorization decision that bypasses the server record.
- Use absolute and idle expiry, cap authenticated sessions at 16, cap short-lived pre-auth sessions at 128, and prune expired records. Validate auth generation on every authenticated request.
- Require CSRF on all POST/PATCH/PUT/DELETE requests, including login/logout; compare tokens safely. Validate browser Origin against effective dashboard origin, with a narrowly defined same-origin Referer fallback. Reject absent/invalid origin evidence on browser mutations. Authenticated GET/downloads are nonmutating and do not require a custom header.
- Limit login attempts per client and globally: default five failures/client/minute and 20 total failures/minute, bounded buckets, uniform errors, maximum two concurrent hash verifications. Limit request body before password processing. Recovery remains possible via local CLI.
- Key installation, publication, destructive deletion and backup download require password reauthentication within five minutes. Reauth itself is CSRF-protected and rate-limited.
- Add CSP with local assets/nonces, `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, restrictive Referrer-Policy, and `Cache-Control: no-store` on administrative/private responses. Escape template output; render filenames/logs via text nodes, never arbitrary `innerHTML`.
- Ordinary file-vault downloads are attachments, including HTML/SVG. Do not execute uploaded content under the administrative origin.

Flask's security guidance covers resource limits, CSRF, attachment handling, cookie options and Host validation; ensure chosen versions actually provide any framework settings used. [Flask security considerations](https://flask.palletsprojects.com/en/stable/web-security/)

### 6.3 API contract

Use a consistent JSON envelope: `ok`, `data` or `error {code,message}`, and `request_id`. Validation rejects unknown fields and unexpected content types. Use 400 for invalid input, 401 for missing/expired auth, 403 for CSRF/origin/authorization, 404 for absent resources, 409 for conflict/busy/restart-required, 413 for size, 429 for rate limiting, and 503 for unavailable capabilities. Unexpected exceptions produce sanitized 500 responses and private diagnostic IDs.

| Route | Behavior |
|---|---|
| `GET /healthz` | Minimal process health, public |
| `GET /api/session`, `POST /api/login` | Bounded session bootstrap and login |
| `POST /api/logout`, `POST /api/reauth` | Session revocation and recent-auth renewal |
| `GET /api/status` | Sanitized service/capability/telemetry snapshot |
| `POST /api/services/<id>/<action>` | Allowlisted start/stop/restart; queue operation and return 202 + operation ID; dashboard/controller self-stop/restart is CLI-only |
| `PATCH /api/services/<id>/config` | Allowlisted bind/port/autostart edits with config revision; enforce policy and restart-required result |
| `GET /api/operations/<id>` | Progress and terminal outcome for retained owner operations |
| `GET /api/logs/<id>?lines=N` | Bounded, redacted text payload |
| `GET /api/files?path=...` | Paginated confined directory list; empty path explicitly means root |
| `POST /api/files/upload` | One bounded file, default no overwrite, atomic publication |
| `GET /api/files/download?path=...` | Authenticated attachment from a verified file descriptor |
| `DELETE /api/files?path=...` | Delete regular file or empty directory after recent auth; never root/recursive deletion |
| `GET /api/git/repos`, `POST /api/git/repos` | List/create validated bare repositories |
| `GET /api/ssh/keys`, `POST /api/ssh/keys`, `DELETE /api/ssh/keys/<fingerprint>` | Manage only PocketServer's keys; recent auth for changes |
| `POST /api/tunnel/start`, `POST /api/tunnel/stop` | Explicit target and publication acknowledgment; bypass through generic lifecycle endpoint is forbidden |
| `PATCH /api/power-policy` | Select managed/manual policy through the same config contract |
| `GET /api/doctor` | Cached/read-only diagnostic results; no implicit repair |
| `GET /api/backups`, `POST /api/backups` | List metadata/create an offline-consistent operation |
| `GET /api/backups/<id>/download`, `DELETE /api/backups/<id>` | Recent-auth private download/delete of completed archives only |
| `GET /api/jobs`, `POST /api/jobs/<id>/runs` | Enumerate registered jobs and queue fixed definitions |
| `GET /api/job-runs/<id>`, `POST /api/job-runs/<id>/cancel` | Bounded result/status and owned-child cancellation |

There is no remote restore, arbitrary config replacement, arbitrary filesystem path, shell-command endpoint, or generic target URL input. Configuration edits to tunnel/autostart cannot bypass explicit publication. CLI and API call the same validators and core operation layer.

## 7. Files, SSH, Git, tunnels and jobs

### 7.1 File confinement and resource control

Use descriptor-relative no-follow path walking on production POSIX (`dir_fd`, `O_NOFOLLOW`, `fstat`) from an opened trusted root. Reject symlinks in every ancestor, not only the last path. Reject absolute paths, drive/UNC syntax, NUL/control characters, `..`, excessive depth/length and unexpected separators. Decode URL input once. Empty path is permitted for listing only. Reject hard-linked files (`st_nlink != 1`) for exposed reads/writes where confinement could otherwise disclose another private file.

The capability check for secure descriptor operations is a release gate. Windows fake tests cover syntax and contracts; if secure real filesystem behavior is unavailable, those operations are unsupported rather than implemented using a knowingly weaker string-prefix check. Test root changes, ancestor swaps and final-file swaps during operations. Local malicious same-UID code remains outside the threat model.

Listener startup has already reserved upstream buffering capacity as specified in section 6.1. Upload operations separately reserve application staging space under a lock before copying buffered data; never count the same free bytes twice. Maintain 250 MiB untouched headroom using exact bytes and enforce actual size while reading, including missing/false Content-Length. Unique private temp files, fsync, and no-clobber publication prevent partial files and accidental overwrite. Initial API rejects existing names with 409; future overwrite needs a separate version/precondition contract. Clean abandoned partials only after proving their operation is no longer active.

Downloads open once and stream from the verified descriptor, so a later rename cannot change the target. Listings cap at 200 entries/page; path depth at 32 components, relative path length at 1024 characters, and each component at 255 UTF-8 bytes (also respect filesystem-specific limits). Delete never follows links, removes the root, or recursively removes trees.

### 7.2 SSH and Git

Generate PocketServer-specific host keys and configuration under `ssh/`; use `sshd -D -f <dedicated-config>`. Specify `ListenAddress`, port, host key paths, `AuthorizedKeysFile`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, and the intended forwarding policy. Validate with `sshd -t` before start/reload. Never rewrite the user's global sshd configuration or `~/.ssh/authorized_keys` implicitly. First key enrollment is local CLI input; refuse starting SSH with no usable key.

Full-shell keys are explicitly labeled owner keys. Allow local TCP forwarding only to the dashboard loopback endpoint for the administration workflow; disable agent/X11/remote forwarding unless a separately documented local-owner policy enables it. A Git-only key uses a forced command helper, no shell/forwarding/PTY, and a repository allowlist. Parse SSH_ORIGINAL_COMMAND with a strict grammar and pass only `git-upload-pack`/`git-receive-pack` plus a validated canonical repository path as an argv list. Never execute the original string as a shell command.

Accept one public-key line, with allowed algorithm, validated base64 and structural parsing through the installed OpenSSH tooling; reject options prefixes, embedded newlines, private-key material and arbitrary `command=` fields. Enforce a bounded input size, fingerprint/deduplicate, lock writes, and atomically replace the owned key file. Do not allow remote removal of the final usable owner key; local recovery remains available. Removing a key affects future authentication, not already established sessions; show that distinction.

Repository names match `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`. Create with an empty controlled Git template and `git init --bare` into a unique sibling directory, validate it, then publish without replacing an existing repo. Disable user/global Git configuration inheritance for managed operations, including hooks/template overrides; do not install executable hooks from web input or untrusted backups. Git-only pushes take the shared maintenance lock so backups can obtain exclusive access. Full-shell sessions remain trusted writers and must be closed for a consistent backup.

Generate clone/SSH commands from actual username, configured host/port and canonical private path. Quote shell examples safely. Do not print a LAN clone command when the listener is loopback-only.

### 7.3 Quick Tunnel

Implement only a fresh `cloudflared tunnel --url http://127.0.0.1:<validated-target-port>` with isolated controlled configuration context, no inherited credentials/ingress file and no token argument. Resolve target from a service ID; reject dashboard, files, SSH, arbitrary URLs and port aliases. Target must be ready and pass publication checks. Cloudflare describes Quick Tunnels as testing/development facilities, so do not attach a production availability claim. [Cloudflare Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/)

Use current-run bounded output/readiness information. A matching historical URL is not current state. Invalidate URL on stop/disconnect/restart, stop publication if target stops or its configuration changes, and require fresh explicit publication afterward. `stop` means the local connector is confirmed down, not that Cloudflare instantly erases an external URL or every cached response.

Named/token/custom-domain support remains a separate future feature: it must verify effective remote ingress and provide credential lifecycle, scope, audit and revocation tests. It cannot inherit the Quick Tunnel confinement claim just because local `target_service` is valid.

### 7.4 Worker

Only locally registered immutable job definitions may run: ID, absolute trusted script, fixed argv, allowed parameter schema, working directory, minimal environment and timeout. Do not infer executability from an uploaded file under `data/files`. Browser users cannot register/edit executable jobs or supply raw shell strings/environment variables.

One job runs at a time; queue at most ten. States are queued/running/succeeded/failed/timed_out/cancelled/interrupted. Capture bounded output and exit status. After controller restart, reconcile owned children and mark lost executions interrupted; never replay a potentially non-idempotent job automatically. The runner holds shared maintenance protection while writing data; backup waits for completion or refuses busy. Retain at most 100 results/seven days and enforce the global log/storage budget.

## 8. Backup and restore

### 8.1 Archive format and creation

Introduce format version 1 with exactly one manifest as the first archive member, maximum 4 MiB, containing app/schema versions, creation time, selected roots, consistency result, normalized relative paths, types, sizes and SHA-256 digests. Payload and manifest must correspond exactly: reject unlisted/missing members, duplicate manifests/destinations, type or size mismatches and digest failures. Bound metadata parsing before allocating from declared counts/lengths. Digests detect damage, not provenance or trustworthy code.

Default backup scope: validated configuration (including password hash), `data/www`, `data/api`, `data/files`, `data/git`, and `data/jobs`. Explicit exclusions: session signing key, live sessions/state DB, PID/wake state, logs, locks, staging/recovery data, other backups, SSH private keys/authorized keys and external Termux files. List exclusions in creation output and README. Do not describe it as a full device or SSH-identity backup.

Backups are sensitive, unencrypted local archives stored with 0600 permissions. Download requires recent auth and a notice that credentials and private data are included. Do not claim encryption; recommend owner-controlled encrypted storage for exported copies without inventing an encryption format here.

Creation obtains the maintenance lock and makes all managed writers quiescent: uploads/mutations paused, jobs finished or refused, relevant services stopped as required, Git transport writes excluded, active full-shell SSH sessions closed. If a consistent snapshot cannot be obtained, refuse rather than label a live copy consistent. The owner must stop external same-UID editors; the program cannot enforce that isolation.

Under exclusive maintenance, inventory and hash bounded regular files/directories to build the manifest before writing it as the first member; fail with the offending path on links/devices/sparse files instead of silently omitting data. Stream payloads in a second pass and verify identities, sizes and digests still match; external mutation aborts creation. Use a unique timestamp-plus-random-ID private `.partial`, bounded write time/bytes, validate manifest/digests, fsync, then rename to the final archive and sync its directory. A failed create never appears as a completed backup. Resume only the preexisting private service set after a successful or safely aborted backup; never automatically republish a tunnel.

Default archive limits: 10,000 entries, 256 MiB single regular file, 1 GiB expanded data, 1 GiB compressed input/output, 10-minute operation deadline, 250 MiB storage headroom, and at most five archives/2 GiB total retained. Apply bounded manifest/header parsing, including extended tar metadata. For larger legitimate datasets, a local operator can increase limits after preflight space checks; never silently skip oversized data. Reserve the new archive's worst-case size before creation, including temporary retention overshoot (up to one extra 1 GiB archive beyond the normal 2 GiB retention cap), ongoing server buffer allocations and headroom. Delete oldest completed archives only after a new one commits, never the sole previous recovery copy; if space is insufficient, fail with a storage estimate.

### 8.2 Restore safety

Restore is local CLI and offline. It requires an archive validation report, explicit `--apply` intent, and a separate `--trust-executable-content` acknowledgment for imported API/job trees. By default quarantine the entire restored API/job trees regardless of names or executable bits and disable their capabilities until locally reviewed. Always quarantine imported Git hooks, recreate an allowlisted bare-repository configuration, and reject external includes/alternates, hooksPath, upload-pack overrides and other executable/external-path metadata. The trust flag does not exempt Git metadata from this policy; any hook reinstatement is a later explicit local action. Legacy archives without the manifest are rejected by the normal restore path; a local `backup import-legacy` command must inspect them with the same bounded member policy, describe omissions, and produce a new manifest archive without executing anything.

Extraction filters differ across Python versions and do not provide an application transaction or all resource limits. Use explicit member policy rather than relying on the default of `tar.extract()`. [Python tarfile extraction guidance](https://docs.python.org/3/library/tarfile.html#extraction-filters)

Restore algorithm:

1. Open a bounded regular archive and freeze the input identity. Read the first bounded manifest, then reserve staging/expanded-data and any imported-input-copy budget before reading payloads, accounting for existing live data, other reservations and 250 MiB headroom. Stream into a fresh private same-filesystem staging directory, enforcing actual byte consumption/headroom throughout; reject input identity changes or truncation.
2. Reject absolute/drive/UNC paths, parent traversal, normalized duplicates/case collisions, links of every kind, devices, FIFOs, sockets, sparse files, excessive depth/count/size and paths outside the explicit backup roots. Materialize only regular files/directories with application-chosen modes; do not restore archive ownership or arbitrary permissions. Enforce actual decompressed bytes and deadline while streaming, not just declared sizes.
3. Verify exact manifest/payload correspondence, digests and required files, validate configuration without auto-repair, check target-version migration compatibility, and inspect Git repository structure under the restricted metadata policy. No subprocess may execute restored scripts/hooks or consult imported executable/external-path Git configuration during validation. Prepare staged config with all autostart flags false and a new auth generation above the current installation's value.
4. Recheck space for staged data, retained old data, finalization files and headroom. Obtain exclusive maintenance access without holding a lock needed by existing writers; confirm writers and relevant services are stopped. Immediately before journaling commit, take the operation/config locks, re-read the live revision and auth generation, advance both from those current values in staged config, and revalidate it. The earlier staging snapshot cannot authorize a stale credential generation. Preserve the previous live generation in `recovery/<id>`.
5. Commit with a durable journal containing the validated operation ID, exact allowed source/destination paths and completed steps. For each managed root: journal/fsync intent, rename old root into recovery, rename staged root into place, fsync both affected source and destination parent directories after each cross-directory rename, then journal/fsync completion. Apply the same directory-durability rule to rollback. Commit disabled-autostart config after data, then write/fsync a `DATA_COMMITTED` marker. This is not overall success.
6. Multiple renames are not globally atomic. Every entry point blocks service startup and mutations on any journal without `FINALIZED`. Without `DATA_COMMITTED`, compare journal and root locations and roll back all steps to preserved old roots; with `DATA_COMMITTED`, resume security finalization rather than announcing completion or deleting recovery files. Missing/inconsistent evidence stops with `recovery_required`, never guesses or deletes the only copy.
7. Finalization prepares/reuses an operation-specific newly generated session key, atomically installs it, confirms the advanced auth generation, clears old sessions/observations and verifies every service/tunnel remains stopped. Journal each step so a crash resumes idempotently. Only after all checks pass write/fsync `FINALIZED`; then bounded cleanup may proceed. Retain existing local SSH identity outside backup scope. Show restored, excluded and quarantined items and the rollback location; autostart stays disabled pending explicit owner review.

If rollback itself fails, preserve staging, archive and recovery files and expose a local recovery command/report. Never announce success after invalid config, partial extraction, failed stop, failed key rotation or an incomplete journal. Successful data commit with failed finalization remains recovery-required and cannot start services.

## 9. CLI, diagnostics, boot and installation

### 9.1 CLI behavior

Preserve `init`, `status`, `start`, `stop`, `restart`, `logs`, `doctor`, `backup`, `restore` and `passwd`. Add `enable/disable`, `config validate/migrate/set`, `ssh key add/list/remove`, `git create/list`, `job register/run/cancel`, `boot install/remove`, `recover`, and `serve --foreground` for development. Keep command groups small and use the same operations as HTTP.

Every read command supports `--json`. Exit codes: 0 success, 1 operation failure (including partial bulk failure), 2 invalid usage/config, 3 unsupported/missing capability, 4 busy/timeout, 5 recovery required. Status returns valid observations even if a service is stopped; `status --require-ready` provides a readiness gate. Doctor returns failure if required checks fail and offers `--strict` to treat warnings/unknown required checks as failure.

No password/token in argv, no shell-dependent environment syntax in cross-platform examples, no hidden repair from reads. Printed URLs reflect current effective bind/port, service readiness and verified/declared address provenance.

### 9.2 Diagnostics

Each check returns ID, `PASS|WARN|FAIL|UNKNOWN|NOT_APPLICABLE`, evidence, observation time, and specific remediation. Required versus optional capabilities determine severity. Checks cover runtime/Python/dependencies, config schema/private permissions, runit/controller readiness, storage budgets, logs, credentials/session policy, listeners/ownership, wake policy, Android restrictions, boot setup and pending recovery.

Occupied port with unknown owner remains occupied/unknown; do not claim a PID from a stale file. Unknown SDK is unknown. Do not guess installation signatures. Optional battery/VPN/SSH absence must not make unrelated core services fail.

Do not automatically apply global ADB process-limit/device-config changes. Provide a version-qualified troubleshooting reference only when the device has a relevant observed problem; any advanced mitigation must show applicability, effect, how to inspect the existing value, and how to undo it. An SDK number alone does not prove a kill cause or that a mitigation is enabled.

### 9.3 Boot

Boot is explicit opt-in and installs only an owned script. Use the actual prefix/interpreter/installed application paths, safe shell quoting, umask, bounded logging and the operation lock. Start/verify the runit service daemon before reconciliation. Reconcile enabled private services in dependency order; never start tunnel or bypass migration/recovery checks. Wake behavior follows configured policy and unwinds after failed starts.

Document compatible Termux:Boot installation, signing-source compatibility and launching the add-on once. Script existence is a setup check; readiness requires a recorded reboot test. [Termux:Boot instructions](https://github.com/termux/termux-boot#usage)

### 9.4 Dependencies and installer

Separate runtime requirements from pytest/development requirements. Select and lock reviewed versions of Flask, Werkzeug, Waitress and every transitive dependency, with hashes, Python compatibility and licenses. Current ranges are not a verified lock and must not be blindly retained or upgraded.

Distribution consumes a vetted wheelhouse: install with no-index, hashes and binary-only policy so the phone cannot fall back to an sdist/compiler. Produce any needed pure-Python fallback wheel off-device, verify its provenance, universal compatibility tag and absence of native extensions, and include its hash in release artifacts. This matters because MarkupSafe's upstream build includes optional C speedups; naming Flask/Werkzeug alone does not prove a compilation-free transitive install. [MarkupSafe build configuration](https://github.com/pallets/markupsafe/blob/main/setup.py)

Gate this strategy on a clean Termux device before promising it. If compatible vetted wheels cannot be produced for the chosen versions, block release and revise the packaging decision explicitly; do not silently install compilers or weaken integrity checks. Runtime Python, runit and optional OpenSSH/Git/cloudflared come from verified Termux packages. Record installed versions; do not assume ordinary Linux binaries work on Android.

`bootstrap.sh` must validate environment, storage, required commands and current installation before modifying anything. Create a versioned application/venv location and a stable launcher using the correct interpreter; publish it only after import and contract checks pass. Fresh initialization is local/interactive or stdin-driven. Keep the previous app generation for application/config rollback. Before package changes, inspect the package-manager transaction: an app upgrade must refuse any transaction replacing shared Python/native runtime components required by the old installation. Such runtime upgrades need a separate explicit maintenance/backup/recovery procedure and cannot be rolled back merely by restoring a venv. Report residual newly installed shared packages after failure; do not promise package-manager rollback.

Do not perform an unrequested blanket system upgrade. Optional services install optional packages deliberately. Installer reruns preserve data, passwords, SSH keys and user's service preferences. Run from a path containing spaces/metacharacters during acceptance. Never symlink a generic Python shebang and assume it selects the venv.

Uninstall stops only owned services/controller, removes only owned runit/boot/launcher/app artifacts, and preserves the runtime root by default. `--purge-data` requires an explicit preview and affirmative local confirmation or a deliberate noninteractive flag; resolve and verify the exact target against the registered installation root before deletion. Never remove shared Termux packages, global SSH keys or unrelated services.

## 10. Implementation phases and acceptance gates

A phase is complete only when its specified behavior and negative cases pass and evidence is recorded. Tests belong to each phase, not a final retrofit. Dependencies below are mandatory; optional features cannot postpone repairs to existing dangerous behavior.

| Phase | Depends on | Deliverables | Mandatory exit evidence |
|---|---|---|---|
| P0: Baseline and packaging proof | None | Read-only inventory, support matrix, temp-root fixtures, regression cases for F01-F25, verified wheelhouse experiment, threat-model decisions | No user runtime touched; Windows liveness test invokes no signal; clean Termux installation demonstrates no on-device compiler; missing device evidence explicitly blocks release qualification |
| P1: Runtime/config foundation | P0 | Runtime context, locking, full schema, private creation, explicit init, password policy, migration/recovery skeleton | Concurrent init/writes, invalid config/types, NaN/duplicate keys, disk/permission failure, secret race, stale revision, idempotent init, migration rollback all pass |
| P2: Lifecycle/logging/power | P1 | runit backend/controller, fake backend, state machine, dependency ordering, bounded logging and honest wake/health | Duplicate starts, stop/restart races, unrelated PID, crash at every start step, failed stop, restart storm, long-line flood, full disk, missing daemon, CLI-down/dashboard-down control cases pass |
| P3: Confined storage and HTTP payloads | P1-P2 | Descriptor-based vault/static boundary, reservation accounting, hardened web/sample API, WSGI runtime | Traversal/link/race/oversized/parallel uploads, descriptor-stable download, no-overwrite, malicious HTML attachment, loopback/LAN bind and server buffering limits pass |
| P4: SSH/Git | P1-P3 | Dedicated SSH config/keys, key manager, restricted Git command helper, repo create/list | Wrong keys/password rejected; global SSH files unchanged; loopback inaccessible from LAN; command injection and malicious keys rejected; Git push/clone/maintenance-lock behavior verified on Termux |
| P5: Backup/recovery | P1-P4 | Manifest archives, full vault inclusion, quiescence, bounded staged restore, journal/rollback and legacy import | Full round trip; corrupt/link/duplicate/bomb archives; two same-second creates; active SSH/Git writers; disk failure; process interruption at every swap/finalization step; next-start recovery verified |
| P6: Authenticated control API | P1-P5 | App factory/auth/session store, CSRF/origin/Host checks, rate limits, route matrix and async operation results | Unauthorized matrix, expired/revoked sessions, login/logout CSRF, DNS rebinding, arbitrary forwarding headers, rate/resource bounds, secret redaction and config/tunnel bypass rejection pass |
| P7: Mobile dashboard | P6 | Local assets; overview/services/files/Git/SSH/logs/doctor/backups; visible progress/error states | Phone-width browser walkthrough, keyboard use, offline assets, XSS filenames/logs, interrupted polling/upload, stale config conflict, session-expiry recovery and actual download behavior verified |
| P8: Explicit Quick Tunnel | P2-P3,P6-P7 | Controlled origin-only publication, current-run URL/readiness, revocation UI | Wrong/aliased origin rejected; inherited cloudflared config isolated; target loss/port change stops tunnel; stale URL cleared; dashboard/vault inaccessible through publication; real network test recorded |
| P9: Bounded workers | P2-P3,P5-P7 | Local registration, queue/run/cancel/result API and UI | No arbitrary commands/uploads executed; timeout kills owned descendants; repeated request deduped; crash is interrupted rather than replayed; maintenance lock and output caps verified |
| P10: Install/upgrade/boot/uninstall | P0-P9 | Idempotent scripts, stable launcher, package/data rollback, documentation and explicit boot policy | Clean install, rerun, upgrade failure/rollback, foreign cwd, quoted paths, actual reboot, preserved user data and owned-only uninstall pass |
| P11: Release qualification | P10 | Complete evidence table, threat review, tested support matrix, release notes and known limits | Every required gate below passes; unavailable checks recorded as blocked, not silently skipped |

Parallel work is safe after interfaces are fixed: UI mock work can proceed against the route contract, and archive fixtures/docs can be prepared while lifecycle work completes. Only one owner edits a shared core module at a time. Avoid implementing endpoints against unfinished security primitives.

For each coding task: state the finding/requirement IDs; implement only that slice; perform the required kluster review immediately after file changes; report findings before fixes; then run the meaningful tests for that slice and record limitations. Run dependency validation before dependency edits/package operations. A review service outage is an unavailable gate, never a clean result. Automated review does not substitute for functional/security tests. Observe the repository's remediation-review workflow without adding permission gates to already authorized work.

## 11. Test strategy and release checklist

### 11.1 Test organization

Use focused suites such as `test_config.py`, `test_runtime.py`, `test_supervisor_contract.py`, `test_storage_security.py`, `test_backup_recovery.py`, `test_auth_api.py`, `test_ssh_git.py`, `test_tunnel.py`, `test_jobs.py` and device integration scripts. Fixture roots are unique temporary directories; force mock adapters by default. Real network/process/device tests are opt-in and must assert they cannot touch the default user's runtime, SSH files or services.

Unit tests cover validators/policies; integration tests cover actual request limits, operation persistence, real child lifetime and filesystem semantics; fault injection covers failed writes/fsync/rename/start/stop and crashes; device tests cover Termux behavior. Assert outcomes and external effects, not implementation-specific call sequences. Include reference regression tests for all F01-F25. Record relevant platform skips explicitly.

Planned test entry points, once those tests/dependencies exist:

```text
python -m pytest tests/test_config.py tests/test_runtime.py
python -m pytest tests/test_supervisor_contract.py tests/test_storage_security.py
python -m pytest tests/test_backup_recovery.py tests/test_auth_api.py
python -m pytest tests/test_ssh_git.py tests/test_tunnel.py tests/test_jobs.py
python -m pytest tests
```

These commands are future verification instructions, not claims that tests currently exist or were run during this planning review. Tests set mock mode/root through fixtures; no shell-specific environment prefix is needed.

### 11.2 Required release evidence

- [ ] **Inventory:** every original capability is implemented or explicitly marked deferred/unsupported in code, UI and README; no successful-looking stubs.
- [ ] **Ownership:** stale/unrelated PIDs cannot be signaled; Windows inspection is non-destructive; two concurrent starts yield one owned process.
- [ ] **Recovery:** corrupt config never resets credentials; migrations and restore recover after interruption at every persistent boundary.
- [ ] **Storage:** file-vault and public static confinement withstand traversal/link/race cases; temporary files, concurrent bodies, logs and archives have enforced budgets.
- [ ] **Authentication:** no uninitialized control access; CSRF/login/origin/Host/session revocation matrix passes; secrets never appear in public output.
- [ ] **Network exposure:** dashboard is loopback-only; SSH uses dedicated key-only policy; publishing web/API cannot publish administration or vault data.
- [ ] **Lifecycle:** startup/readiness/stop failures are honest, bulk operations return partial failures, no unintended autostart/publication, no unlimited restart storm.
- [ ] **Jobs:** bounded concurrency/output/time and owned-child cancellation; interrupted non-idempotent work is not automatically replayed.
- [ ] **Packaging:** hash-verified dependencies install on a clean phone without a compiler; supported interpreter versions are recorded; previous app/config survives a failed app-only upgrade, and incompatible shared-runtime package changes are refused until the separate recovery procedure is selected.
- [ ] **Boot/removal:** actual reboot starts the enabled private set; failure leaves actionable logs; default uninstall preserves user data and unrelated services.
- [ ] **UI:** usable at 360 px width, keyboard accessible, offline assets, escaped untrusted text, disabled/busy/error/unknown states, no hidden-only security controls.
- [ ] **Device qualification:** at least one physical ARM64 device; before claiming an Android range, test representative versions from that range. Record terminal closure, 30-minute screen-off run, network loss/reconnect, Wi-Fi change, forced child crash, Termux force-stop/relaunch, reboot and missing optional APIs.
- [ ] **Soak:** eight-hour controlled run plus high-output, slow-request, repeated login and interrupted-transfer exercises; disk growth remains within configured bounds and no owned process/FD growth remains unexplained. Record battery/thermal observations, without claiming universal device behavior.
- [ ] **Review:** required security/quality review completed, all actionable findings resolved, test evidence and residual limitations attached to the release.

Device-dependent unknowns (package versions, OEM background policy, supported secure filesystem operations, actual logger overshoot and optional VPN reachability) are explicit release gates. They are not permission to guess, claim success from mock output, or leave an unsafe fallback enabled.

## 12. Completion record for this planning task

Completed: full tracked-source/reference-plan review, independent reviews of supervision/configuration/recovery, primary-source checks of material platform claims, and this replacement implementation specification. The original plan and application source remain unchanged.

No application, build, package installation or test suite was executed for this documentation task. Existing process-control routines were deliberately not exercised against live user processes. kluster initialization returned `connectionError`; automatic/manual/dependency review tools were not available, so no successful automated review or clean review result is claimed. Re-run the required review when the integration is connected before using review completion as a release gate.
