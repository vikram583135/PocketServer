# Release evidence — 2026-11-17

Status: **implemented and locally tested; physical Termux release qualification remains incomplete**. See `LOCAL_TEST_RESULTS.json` for the tested Python source hashes and machine-readable results. All recorded application/test source hashes match the final Linux snapshot. Documentation updates followed those checks.

## Current verification

| Environment/check | Observed result | Scope |
|---|---|---|
| Ubuntu WSL2, CPython 3.12.3 | **251 passed, 1 skipped** | Full Python suite. The skip covers Windows replacement sharing semantics. Includes actual owned-process timeout/cancellation, descriptor filesystem operations and crash recovery. |
| Windows, CPython 3.13 | **225 passed, 27 skipped** | Full Python suite. Skips cover POSIX filesystem/recovery/process behavior and unavailable symlink privileges. |
| JavaScript | **18 passed**; syntax check passed | Dependency-free VM/DOM behavioral tests; does not establish visual rendering. |
| Installer/remover shell syntax | **Both passed** | `sh -n` against the repository scripts. Does not install/remove anything. |
| Offline runtime installation | **8 pinned wheels installed successfully** | Hash-verified, no-index, binary-only installation in isolated Windows and Linux environments. MarkupSafe's Python fallback was confirmed active. |
| Git whitespace check | **Passed** | `git diff --check`. |
| Android availability | **No attached devices** | `adb devices -l`, 2026-11-17. |
| Required kluster review | **Unavailable** | No completed scan, issue count or clean review result. |

Counts from different environments are not additive. The original P0 result (3 passed, 2 expected failures) is historical; those expected failures were replaced with current regression tests after the implementation changed.

## Implementation and qualification map

| Phase | Implemented work and local evidence | Outstanding qualification |
|---|---|---|
| P0 | F01–F25 threat/regression mapping, isolated roots, exact runtime lock and offline wheelhouse. | Physical compiler-free ARM64 Termux install and support matrix. |
| P1 | Read-only runtime discovery, OS-backed leases, strict schema/revisions, explicit initialization/migration, credential policy, prepared durability journal, signing-key rotation and offline database reconstruction. Fault/interruption tests pass. | Android permissions/filesystem durability and password-cost measurement. |
| P2 | Fake and owned runit backends, controller dispatcher, launch/finish gates, restart limits, readiness/rollback, bounded/redacted logs, honest wake/telemetry. Contract tests pass. | Real runit crash storms, logger overshoot and power-policy behavior on device. |
| P3 | Descriptor no-follow confinement, stable downloads, no-clobber uploads, admission/reservations, public payloads and bounded Waitress configuration. Real loopback declared/chunked/pipelined body rejection and POSIX race tests pass. | Android descriptor support; sustained slow/unauthenticated load and measured total buffering. |
| P4 | Dedicated key-only SSH policy, key roles, strict Git forced-command grammar and isolated repo creation. Tests use controlled external-tool responses. | Real sshd/key rejection, Git push/clone, LAN isolation and transport behavior on Termux. |
| P5 | Manifest-first USTAR, strict bounded validation, v2 gzip/PAX import, full vault inclusion, writer quiescence, quarantine and journaled restore/finalization. Tests include every managed-root rename and postcommit interruption, plus corrupt-state repair during restore. | Physical-device power loss and storage behavior. |
| P6 | Authenticated thin routes, signed server-side sessions, CSRF/Host/Origin checks, expiry/revocation, recent-auth enforcement, rate limits, bounded operations and durable job cancellation. Negative cases pass. | Physical remote-administration workflow. |
| P7 | Offline mobile dashboard with settings, files, Git/SSH, logs, doctor, backups, tunnel and jobs; safe DOM, session recovery, busy/error states and keyboard modal handling. 18 behavioral tests pass. | Actual 360 px visual/keyboard/download walkthrough. The browser connector timed out; native interaction was stopped when concurrent user input was detected. |
| P8 | Explicit owned web/API Quick Tunnel publication, isolated connector environment, current-run URL tracking and revocation. Contract tests pass. | Real external-network exposure/revocation; no production availability claim. |
| P9 | Immutable local job definitions, bounded queue/results/output, durable cancel, maintenance protection and non-reaping process ownership through group cleanup. Real POSIX timeout/cancel tests pass. | Android descendant/process behavior and extended resource stability. |
| P10 | Offline staged generation installer, rollback journal, quoted stable launcher, explicit boot policy, owned-only uninstall and data preservation. Inert-runner failure tests and shell syntax pass. | Actual Termux install/rerun/upgrade/uninstall and reboot. |
| P11 | This evidence ledger and tested source snapshot. | Release remains blocked by the gates below. |

## Reproduce locally

PowerShell, with the existing development environment (the short isolated root avoids Windows path-length limits):

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = '1'
$testRoot = Join-Path (Get-Location).Path ('.build\win-' + [guid]::NewGuid().ToString('N').Substring(0,8))
.\.test-venv\Scripts\python.exe -m pytest tests -q -ra --basetemp $testRoot
node --check dashboard/static/app.js
node --test tests/test_ui.js
```

`scripts/verify_posix.py` copies only source/test/runtime-wheel inputs to a fresh Linux temporary directory, installs the runtime lock offline, and runs the full suite including opt-in owned-process tests. It expects development wheels under `.build/test-wheels` (pytest 9.2.0, pip 25.3 and their dependencies). The development download/preparation is separate from the phone's runtime wheelhouse. It retains the Linux snapshot and writes `.build/posix-evidence.json` and JUnit output. It never reads the user's `.mock_termux` runtime.

## Remaining release gates

- Qualify the pinned wheelhouse and derived pure-Python MarkupSafe artifact on a clean physical ARM64 Termux device. `qualified_on_termux` remains false; `--allow-unqualified` is only a deliberate qualification override.
- Verify real runit, OpenSSH/Git, loopback/LAN exposure, network publication, boot/reboot and Android/OEM background behavior.
- Complete phone-width visual/keyboard/download checks, required network changes and eight-hour soak/resource measurements.
- Complete the required kluster security/quality review when its integration is available.

No unavailable gate is represented as passed. SSH sessions and lost job descendants remain uncertain within the same/unknown boot; a distinct verified kernel boot ID can prove earlier processes cannot survive. Private recovery evidence is preserved, and saved PIDs never authorize termination. Source changes remain uncommitted for user review.
