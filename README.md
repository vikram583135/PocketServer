# PocketServer

PocketServer is a local-first phone server managed from Termux. The intended production setup uses a non-root Termux account and runit services. The administration dashboard binds to loopback; reach it from another machine through SSH local port forwarding. Do not expose the dashboard directly to a LAN or public network.

The CLI, service controller, dashboard, file vault, SSH/Git management, Quick Tunnel, workers, backup/restore, and installation/recovery code are implemented. Production release qualification remains incomplete. The bundled offline wheels are pinned and hash checked, and `wheelhouse/manifest.json` records that physical Termux qualification is pending. Installation requires `--allow-unqualified` for local qualification. The installer leaves system packages unchanged and uses pip only against the offline wheelhouse. Windows mock mode provides foreground demonstration and schema/contract work; it does not provide persistent production processes.

## Setup

Run from a source checkout in Termux. Install prerequisites such as Python, Git, OpenSSH, and termux-services through your normal device setup. PocketServer itself installs Python dependencies only from the bundled wheelhouse, with hashes and no index/network fallback.

```sh
python pocketctl.py --env termux --home "$HOME/.local/share/pocketserver-runtime" init
python pocketctl.py --env termux --home "$HOME/.local/share/pocketserver-runtime" install --source "$PWD" --allow-unqualified
```

`init` and `install` read the password from standard input when `--password-stdin` is used. The password must be 12–128 characters; it is not accepted as a command-line argument. Use a protected interactive prompt or a securely managed stdin source. Do not put the password in shell history or an environment variable.

The installer prints the stable launcher path; it does not change your PATH. For the default installation location, enable the dashboard and explicitly start/verify the service daemon and owned controller:

```sh
"$HOME/.local/share/pocketserver/pocketserver" enable dashboard
"$HOME/.local/share/pocketserver/pocketserver" boot reconcile
"$HOME/.local/share/pocketserver/pocketserver" status
```

The dashboard listens on loopback. From a trusted computer, forward the dashboard port through SSH, then open the forwarded local address in a browser. Confirm the configured port in status/configuration before forwarding. SSH service management is separate and requires locally enrolled keys.

## Commands

Below, `pocketserver` means the printed launcher path, or that launcher on your PATH. Global options (`--home`, `--env`, `--json`) can also precede the command. On Windows use `python pocketctl.py --env mock --home <absolute-temporary-directory> ...`. After local initialization, `serve --foreground` runs the dashboard on loopback. Mock lifecycle observations are simulated and do not persist across invocations; secure descriptor-based file operations report unsupported on Windows.

```text
pocketserver init --password-stdin
pocketserver status [target] [--require-ready]
pocketserver doctor [--strict]
pocketserver start [target|all]
pocketserver stop [target|all]
pocketserver restart [target|all]
pocketserver enable <dashboard|web|api|ssh> [--revision N]
pocketserver disable <dashboard|web|api|ssh> [--revision N]
pocketserver logs <target> [--lines N]
pocketserver passwd --password-stdin
pocketserver config validate
pocketserver config rotate-key
pocketserver config migrate [--apply] [--legacy-stopped]
pocketserver config set <field> <value> --revision N
pocketserver ssh key add <public_key_file> [--role owner|git] [--repository NAME ...]
pocketserver ssh key list
pocketserver ssh key remove <fingerprint>
pocketserver git create <name>
pocketserver git list
pocketserver job register <id> <script> [--arg ARG ...] [--cwd DIR] [--timeout SECONDS]
pocketserver job run <id> [--parameters JSON]
pocketserver job cancel <id>
pocketserver job status <run-id>
pocketserver job list
pocketserver tunnel publish <web|api> --acknowledge-public
pocketserver tunnel stop
pocketserver tunnel status
pocketserver backup [--external-writers-stopped]
pocketserver backup create --external-writers-stopped
pocketserver backup list
pocketserver backup validate <archive>
pocketserver backup import-legacy <v2-archive.tar.gz>
pocketserver restore <archive> [--apply] [--trust-executable-content] [--external-writers-stopped]
pocketserver recover
pocketserver recover --config
pocketserver recover --state [--apply]
pocketserver serve --foreground [--service dashboard|web|api]
pocketserver boot install|remove|reconcile|status
pocketserver uninstall [--purge-data --yes-purge-data]
```

Backups use uncompressed fixed USTAR `.tar` files with a first-member manifest and SHA-256 integrity checks. They are sensitive and **not encrypted**. They include configuration/password hashes and the public/API/vault/Git/job data trees, and exclude session signing material, the state database, SSH identity, logs and transient state. Limits include 10,000 entries, 256 MiB per file, 1 GiB archive/expanded data, a 4 MiB manifest and a ten-minute deadline. Paths that USTAR cannot represent fail explicitly. Normal restore rejects legacy archives; `backup import-legacy` performs bounded conversion of the original v2 gzip/PAX format.

Restore is local and previews validation by default. Applying requires `--apply --external-writers-stopped`; imported API/jobs are quarantined unless separately trusted, and Git hooks are always quarantined. A durable journal preserves old data and blocks startup through incomplete security finalization. Configuration repair, signing-key rotation and state-database reconstruction are explicit local actions. State reconstruction defaults to a preview; `recover --state --apply` preserves damaged files, revokes sessions and rebuilds volatile operation/session state only while services are offline.

Stop external editors before backup/restore. Stopping an SSH listener does not prove its owner sessions ended. Likewise, a crashed job controller cannot prove descendants exited from a saved PID. Surviving uncertainty markers block new work/recovery; a distinct verified kernel boot ID can establish that earlier sessions/children ended. Missing boot evidence remains unknown. No command signals an old PID to clear this condition.

First SSH owner-key enrollment is local CLI only. Keys/configuration remain under PocketServer's private runtime, separate from global SSH files. Quick Tunnel publishes only the current owned web/API origin after explicit acknowledgment; dashboard/vault publication and token/custom-domain modes are excluded. Locally registered jobs have fixed arguments and execute trusted owner code, with no browser command entry.

MarkupSafe's wheel is an off-device derived pure-Python fallback, with its optional native accelerator removed. The manifest retains upstream artifact hashes, license files and the transformation record. Rebuild tooling is in `scripts/build_wheelhouse.py`; phone installation uses only the resulting hashed wheels. This is not a claim that an upstream native wheel is compatible with Android.

## Release evidence

See [docs/RELEASE_EVIDENCE.md](docs/RELEASE_EVIDENCE.md) for the dated evidence ledger, reproduction command, and outstanding qualification gates. No physical Termux, reboot, network exposure, or extended soak evidence is claimed.
