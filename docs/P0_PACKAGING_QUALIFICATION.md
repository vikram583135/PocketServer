# P0 Packaging Qualification and Evidence

Historical P0 preparation record: the wheelhouse has since been built and tested offline on Windows/Linux; current results and remaining physical-device gates are in `RELEASE_EVIDENCE.md`.

Status: **blocked for release qualification**. This document records the evidence required by P0 and the current baseline. It does not claim that packaging, device, or release checks have passed.

## Current environment and evidence

| Evidence item | Current record | Required evidence to close |
|---|---|---|
| Work environment | Windows development environment; no Termux device used in this task | OS/build, shell, Python version/architecture, date, operator, and command transcript |
| Device qualification | Not executed; ARM64 device not available in this task | Physical ARM64 device model, Android/Termux versions, architecture, storage context, and reproducible results |
| Wheelhouse | Not built or inspected; no downloads performed | Artifact inventory, source/provenance, wheel tags, hashes, license records, and confirmation no native extensions or phone-side compilation |
| Runtime/dependency versions | No versions selected or validated | Exact Python compatibility and reviewed Flask, Werkzeug, Waitress, and transitive dependency versions; rationale and support matrix |
| Hash policy | Not exercised | Locked hashes verified against the exact wheelhouse artifacts |
| Import/contract checks | Not executed | Clean-install transcript and import/contract-check results on the target environment |
| Compiler constraint | Not exercised on device | Evidence that the clean Termux install succeeds without invoking a compiler or falling back to source distributions |
| Package transaction safety | Not executed | Installer dry-run/transaction evidence showing shared runtime components are not replaced by app-only upgrade |

“Not executed” means there is no result to interpret. Do not replace missing evidence with mock output, a Windows-only result, or an assumed package compatibility claim.

## Required support and qualification matrix

Fill one row per supported interpreter/device combination. Do not infer a supported range from a single passing environment.

| Python | Android | Termux distribution/source | Device/ABI | Dependency lock ID | Wheelhouse manifest | Install without compiler | Import/contract checks | Outcome/evidence link |
|---|---|---|---|---|---|---|---|---|
| TBD | TBD | TBD | TBD | TBD | TBD | Not run | Not run | Not qualified |

Record failed, skipped, and unavailable checks with the reason and evidence location. A release claim requires the applicable rows and gates to pass; unavailable physical-device evidence blocks release qualification.

## Packaging experiment procedure

Run only in a disposable, clean Termux qualification environment after versions and hashes have been reviewed. Preserve transcripts and artifact manifests outside the tested installation. Do not run a blanket system upgrade. First capture Python version/ABI, architecture, Termux package versions, free space, and the package manager’s proposed transaction. Abort if an app-only change would replace shared Python/native runtime components.

Prepare an off-device vetted wheelhouse from the reviewed lock. Record each artifact’s filename, source, digest, wheel compatibility tag, license, and whether it contains native extensions. Review transitive dependencies, including build behavior; a top-level Flask/Werkzeug version alone does not establish a compiler-free installation. Any pure-Python fallback wheel needs documented provenance, universal compatibility tag, no-native-extension inspection, and its hash in the release artifact manifest.

After installing the application into a fresh versioned application/virtual-environment location, verify imports and the phase’s contract checks before publishing the stable launcher. Keep the prior app generation available for app/config rollback. Record residual shared packages after a failed install; do not claim package-manager rollback. Repeat using an installation path containing spaces or shell metacharacters during acceptance.

Future command template (placeholders are intentional; do not run until the lock and wheelhouse are reviewed):

```sh
python -m pip install --no-index --find-links "<WHEELHOUSE_PATH>" \
  --require-hashes --only-binary=:all: -r "<LOCK_FILE>"
```

`<LOCK_FILE>` must pin every direct and transitive dependency to reviewed versions and include hashes matching the wheelhouse. `<WHEELHOUSE_PATH>` must identify the exact inspected artifact set. If compatible vetted wheels cannot be produced, mark packaging blocked and revise the decision explicitly; do not install a compiler or weaken integrity policy to get a pass.

## P0 gate and safe parallel work

P0 remains blocked until the required regression cases, support matrix, verified wheelhouse experiment, threat-model decisions, and clean-device compiler-free installation evidence are recorded. This block applies to release qualification, not to independent development-safe work. Work that uses isolated temporary fixtures and mock adapters may proceed when its interfaces and ownership are clear; it cannot be presented as device or packaging proof. Real device, network, process, or package-manager checks remain opt-in controlled qualification work and must not touch the user’s default runtime.

## Per-run evidence record

For every attempt, record: date/time and operator; host/device and software versions; exact command and working directory; inputs and artifact/lock identifiers; exit status; compiler invocation observed (yes/no/how observed); stdout/stderr transcript location; artifacts produced and their digests; import/contract-check outcomes; deviations, skips, failures, and cleanup; reviewer and disposition. Link evidence by stable path or release record ID. An empty field is incomplete evidence, not a pass.
