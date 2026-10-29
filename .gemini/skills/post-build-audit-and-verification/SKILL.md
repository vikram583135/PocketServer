---
name: post-build-audit-and-verification
description: Mandatory post-build testing, integrity verification, feature breakdown, and vulnerability audit gate. Evaluates every build, surfaces all bugs/vulnerabilities, and presents findings for user sign-off before modifying any code.
---

# Post-Build Audit & Verification Gate

## Core Directive
Whenever any component, service, API, or feature sprint is created or modified:
1. **NEVER assume code works without multi-layer verification.**
2. **NEVER silently fix discovered bugs or vulnerabilities behind the user's back.**
3. **Always execute the 5 verification phases below and present a structured Post-Build Audit Report to the user first.**

---

## The 5 Verification Phases

### Phase 1: Automated Unit & Regression Suite
- Execute the test suite (`pytest -v` or targeted test scripts).
- Test both "happy path" and defensive failure cases (invalid types, boundary values, malformed inputs).
- Verify zero syntax regressions, unhandled exceptions, or silent failures.

### Phase 2: System & Runtime Integrity Testing
- **Non-Root Android / Termux Compliance:** Verify no restricted APIs (e.g. `/proc/stat`, `psutil`) or C-compiler requirements are introduced.
- **Process & Resource Boundaries:** Verify subprocesses run with `shell=False`, PIDs are validated against `/proc/{pid}/cmdline`, and log rotation (1 MB limit) is enforced.
- **Persistence & Storage Thresholds:** Verify atomic writes (`os.replace`, `os.fsync`) and minimum free disk space checks ($\ge 250\text{ MB}$).

### Phase 3: Feature Breakdown & Gap Analysis
- Break down the implemented feature into its core atomic capabilities.
- Compare what was actually implemented against the specification.
- Explicitly flag any:
  - Missing features or partial implementations.
  - Hardcoded stubs or placeholder functions.
  - Unhandled edge cases.

### Phase 4: Security & Vulnerability Audit
- **Path Traversal & Confinement:** Verify all file paths use canonical checks (`os.path.realpath`) and block symlinks (`os.path.islink`).
- **Injection & Command Execution:** Verify no raw string formatting or `shell=True` in subprocess calls.
- **Authentication & CSRF:** Verify sessions, password hashing (PBKDF2/bcrypt only, never plaintext), and CSRF token enforcement.
- **Information Disclosure:** Verify secrets, tokens, and credentials are redacted from logs and error responses.

### Phase 5: Human-in-the-Loop Presentation Gate
After completing Phases 1–4, format the results into this exact report structure:

```markdown
## 📋 Post-Build Audit Report: [Feature / Sprint Name]

### 1. 🧪 Test & Integrity Results
- **Unit Tests:** [X/Y Passed]
- **Runtime Integrity:** [Pass / Fail / Warn]
- **Environment Compliance (Termux / Mock):** [Verified]

### 2. 🧩 Feature Breakdown & Status
| Component / Capability | Status | Notes |
|---|---|---|
| [Feature A] | ✅ Complete | [Details] |
| [Feature B] | ⚠️ Partial / Stub | [What is missing] |

### 3. 🔍 Identified Bugs, Edge Cases & Gaps
- [List any bugs, race conditions, or unhandled exceptions]

### 4. 🛡️ Security & Vulnerability Findings
- [List any path traversal, injection, or permission issues, or 'None detected']

### 5. 💡 Proposed Remediation Plan
- [Step 1: Proposed fix]
- [Step 2: Proposed fix]

> ⚠️ **Awaiting Your Approval:** No changes will be applied until you approve this remediation plan.
```

---

## Execution Rule
Only when the user reviews the report and gives explicit confirmation (e.g., *"Proceed with fixes"* or *"Approved"*), apply the remediations and re-run the verification gate.

