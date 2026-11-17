# PocketServer multi-model execution assignments

Date: 2026-11-15. Authority: `POCKETSERVER_IMPLEMENTATION_PLAN.md` v3, especially sections 10–11. The Antigravity edition is historical context. This document allocates work; it does not change security requirements or certify release readiness.

## Model routing

| Model | Default reasoning | Assigned responsibility |
|---|---|---|
| GPT-6.1 Sol | Medium; high for difficult integration | Coordination, normal implementation, meaningful tests, integration and evidence tracking |
| GPT-6 Astra | High, scoped to difficult boundaries | Configuration durability/migration, process ownership, filesystem confinement, restore/recovery, authentication and targeted security review |
| GPT-6 Luna | Low for copy; medium for bounded fixtures/UI | Documentation, evidence tables, synthetic fixtures and offline UI against accepted contracts |

These are workload-based starting assignments, not measured optimal settings. Start with a focused task and increase reasoning or escalate only when evidence shows it is needed. Do not spend Astra context on routine formatting. Do not give Luna independent authority over authentication, signaling, confinement, restore, dependency selection or destructive installation logic.

Official model-role guidance: https://developers.openai.com/api/docs/guides/latest-model . Delegation guidance: https://developers.openai.com/api/docs/guides/agents-api/multi-agent . Specific phase assignments below are project engineering decisions.

## Phase assignments and dependencies

An owner can work with a reviewer, but each file has exactly one active editor. Every implementation slice includes its own negative-case tests and evidence.

| Phase | Required predecessors | Primary assignment | Reviewer/helper | Principal files and evidence |
|---|---|---|---|---|
| P0 Baseline and packaging proof | None | Sol: isolated harness and baseline map | Astra: threat decisions; Luna: qualification record | `tests/conftest.py`, baseline tests, P0 documents; safe Windows observation, F01–F25 mapping, clean-device packaging proof |
| P1 Runtime/config foundation | P0 | Astra: runtime, locking, transactional config and migration | Sol: independent failure tests; Luna: synthetic inputs | `core/runtime.py`, `core/locking.py`, `core/config.py`; concurrent init, stale revision, secret races, failed writes and rollback |
| P2 Lifecycle/logging/power | P1 | Astra: ownership/controller and transitions; Sol: separate logging/telemetry slices | Independent boundary review before integration | `core/supervisor.py`, `core/services.py`, `core/service_entry.py`, `core/env.py`; unrelated PID untouched, racing transitions, failed stop, log flood, honest wake state |
| P3 Confined storage and HTTP payloads | P1–P2 | Astra: confinement/reservations; Sol: supported HTTP payloads | Cross-boundary review | `core/storage.py`, `core/http_services.py`; link/swap races, stable descriptors, concurrent admission limits, attachment and bind policies |
| P4 SSH/Git | P1–P3 | Sol | Astra: key roles, command parsing, writer protection | `core/ssh_git.py`; dedicated SSH files, injection rejection, real Termux Git operations and maintenance behavior |
| P5 Backup/recovery | P1–P4 | Astra: restore journal and recovery; Sol: separate archive/test slices | Independent crash-boundary review | `core/backups.py`; full vault round trip, unsafe archives, disk failures, interruption at each swap/finalization point |
| P6 Authenticated control API | P1–P5 | Astra: authentication/session policy; Sol: thin routes after interfaces freeze | Separate auth/route ownership | `dashboard/app.py`, `auth.py`, `routes.py`; full route/auth/CSRF/Host/Origin/revocation matrix and operation results |
| P7 Mobile dashboard | P6 | Sol: behavior/integration | Luna: local assets and copy; security review of rendering | `dashboard/templates/`, `dashboard/static/`; 360 px, offline/keyboard use, escaped text, request interruption and expiry |
| P8 Explicit Quick Tunnel | P2–P3, P6–P7 | Sol | Astra: target identity, exposure, revocation | Isolated tunnel implementation plus integrator-owned shared edits; current-run URL, no inherited config, target-loss shutdown, real network evidence |
| P9 Bounded workers | P2–P3, P5–P7 | Sol | Astra: child ownership/non-replay; Luna: fixed-contract UI | `core/jobs.py`; bounded queue/output/time, cancellation, deduplication, crash interruption and maintenance |
| P10 Install/upgrade/boot/uninstall | P0–P9 | Sol | Astra: rollback/runtime/deletion policy; Luna: verified docs | Install/remove scripts, `core/boot.py`, CLI and README; clean/rerun/failed upgrade, quoted paths, reboot and data preservation |
| P11 Release qualification | P10 | Sol: evidence integration | Astra: independent threat review; Luna: release/support tables | Every v3 section 11 gate supported by recorded evidence; unresolved checks remain blocked |

Integration order: `P0 → P1 → P2 → P3 → P4 → P5 → P6 → P7 → {P8, P9} → P10 → P11`.

Only P8 and P9 are independent feature implementations at that point. They still share route/UI/profile files: the coordinator reserves those for one integrator and queues changes. Earlier parallel tasks are preparation (synthetic fixtures, UI mocks, archive fixtures, docs), not security-dependent production endpoints. P0 device evidence can remain pending while independent preparation continues; pending evidence does not satisfy P0 or authorize a release.

## Contracts to freeze before implementation fans out

- Immutable runtime paths/modes/capabilities; constructors and status are read-only; explicit initialization owns creation.
- Schema v3, exact types, revision conflict behavior, separate authentication generation, fail-closed credentials and durability/recovery results.
- Maintenance → operation → configuration → resource lock order, bounded acquisition, no shared-to-exclusive upgrade, and documented completion/cancellation exception.
- Controller ownership, service observation/readiness/state, bounded operation queue, idempotency semantics and structured error codes.
- Descriptor-based file operations, aggregate reservations, no overwrite by default, archive contents and recovery commit/finalization states.
- V3 route matrix and JSON envelope; loopback administration, recent authentication, configure-versus-publish policy and no remote restore.

## Compact task brief and handoff

Give agents a fresh context (`fork_turns=none`), the repository path, relevant plan sections, requirement/finding IDs and exact allowed files. Pass accepted interface excerpts rather than whole conversation history. Read adjacent code only when necessary.

```text
Task/phase and finding IDs:
Model + reasoning:
Allowed files (exclusive owner):
Relevant plan sections + accepted interfaces:
One concrete behavior to implement:
Failure cases and acceptance evidence:
No-touch paths and operations:
Return: changed files, behavior, actual checks/results, limitations, review state.
```

Keep returned summaries around 300–600 words unless evidence needs more. Do not request duplicate full-repository reviews. The coordinator records decisions once and supplies only changed contracts downstream. Use at most three active subagents plus the coordinator. Keep tiny tasks and dependent integration local. Review the diff and relevant failure cases; broaden checks only for changed scope, failures or unresolved risks.

Escalate when the task crosses file ownership, needs a contract change, encounters a security/durability ambiguity, or fails its acceptance evidence. Return the concrete failure rather than silently expanding scope. Track tokens/cost where available and retry/rework counts; this run has not measured a savings percentage.

## Verification policy

Follow the supplied kluster rules: dependency review before dependency/package operations, immediate automatic review after file changes, announce findings before fixes, preserve any returned chat ID and complete returned action items. Then run the meaningful functional checks. Review and tests are separate forms of evidence. An unavailable review is never a clean result. Do not invent review issue counts or passing tests.

Use unique temporary runtime roots and fake adapters. Never exercise legacy start/stop against live user processes. Never inspect runtime credentials as fixtures. Physical Termux filesystem/runit/SSH/package behavior, real tunnel reachability, reboot, background behavior and soak tests require actual device evidence.

## Initial dispatch

The user authorized assignments and starting P0. Three planning agents were dispatched with fresh contexts and the explicit models above. P0 implementation ownership is now:

- Sol: only `tests/`, isolated fixtures and a small set of real baseline regressions. Known failures are narrowly marked strict expected failures, not represented as fixed defects.
- Astra: only `docs/P0_THREAT_MODEL.md`, including the F01–F25 regression map.
- Luna: only `docs/P0_PACKAGING_QUALIFICATION.md`, including unexecuted device/package evidence fields.
- Coordinator: this allocation document, integration, local verification and status. Application source and dependencies are outside this P0 slice.

Current limitations: automatic kluster/dependency review tools are not exposed in this session; only the initialization/failure-notification tool is exposed. No physical Termux device or vetted wheelhouse has been established. P0 starts here and remains incomplete until its required evidence is obtained. Subsequent phase assignments are scheduled responsibilities, not claims that those implementations have started.

## P0 evidence recorded in this run

- Baseline: repository HEAD `68c1193`; application sources remain unchanged. The v3 finding inventory references its reviewed source baseline `7d84f56`.
- Created isolated fixture and five baseline tests in `tests/conftest.py` and `tests/test_p0_safety.py`. The fixture redirects the legacy runtime adapter into a unique temporary directory, forces mock mode and intercepts process creation/signaling. No live service commands were exercised.
- Created `docs/P0_THREAT_MODEL.md` with all F01–F25 mapped to future acceptance suites, and `docs/P0_PACKAGING_QUALIFICATION.md` with outstanding support/device/wheelhouse evidence.
- First local test attempt failed during collection because an automatically loaded external `pytest_asyncio` plugin is incompatible with installed pytest. No package changes were made.
- Rerun with external plugin autoload disabled: **3 passed, 2 xfailed**, exit status 0. Strict expected failures reproduce F01 (Windows liveness attempts signaling) and F03 (corrupt configuration is replaced with defaults). Neither defect was fixed in this P0 slice. The process probes are intercepted, not actual Windows PID operations.
- Mandatory automatic kluster review remains unavailable, not passed. No dependency operations were attempted. Physical ARM64 Termux installation, wheelhouse/hash/compiler proof and all device-specific checks remain unexecuted. P0 is started, not complete; P1 implementation has not begun.

Reproduce the focused checks in PowerShell using the existing environment:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = '1'
python -m pytest tests/test_p0_safety.py -q -ra
```

The environment setting applies to the current shell and its children. These tests require the project's existing development dependencies; the command does not install or modify them.

## Implementation continuation — 2026-11-17

The user subsequently authorized the complete implementation. Runtime/configuration, lifecycle, storage, SSH/Git, backups/recovery, authenticated API, offline UI, Quick Tunnel, bounded jobs and installation/boot/removal code are now present. Astra implemented and reviewed critical foundations/recovery; Sol implemented lifecycle/integration and corrected UI behavior; Luna prepared bounded assets/documentation. The coordinator integrated and fixed the review findings.

Final local checks: Linux 251 passed/1 Windows-only skip; Windows 225 passed/27 platform skips; dashboard 18 behavioral tests passed; shell syntax and offline hashed runtime installation passed. See `docs/RELEASE_EVIDENCE.md` and `docs/LOCAL_TEST_RESULTS.json`. P11 physical/device/network/soak/visual/review gates remain incomplete. The earlier P0-only status in this document is a historical checkpoint.
