"""Dedicated SSH identity and a strictly allowlisted Git transport.

An owner shell is a trusted writer. Until a device adapter can prove that its
sessions have ended, a launched listener leaves quiescence uncertain.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import sys
import uuid

from core.config import ConfigManager
from core.errors import PocketError
from core.locking import FileLock
from core.runtime import RuntimeContext, atomic_write, check_path, check_private, private_dir, read_private

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
ALGORITHMS = {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}


def _name(name):
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise PocketError("invalid_repository", "Use a repository name of 1–64 letters, digits, underscores or hyphens.")
    return name


def _binary(name):
    found = shutil.which(name)
    if not found:
        raise PocketError("unsupported", f"Install the optional {name} executable locally.", 503)
    return str(Path(found).absolute())


class SSHGitManager:
    def __init__(self, context, config=None, *, runner=None):
        self.context = context
        self.config = config or ConfigManager(context)
        self.runner = runner or subprocess.run
        self.ssh = context.paths["ssh"]
        self.repos = context.paths["git"]

    def _cfg(self):
        return self.config.get_config() if hasattr(self.config, "get_config") else self.config

    def _lease(self):
        self.context.ensure_mutable()
        from core.storage import maintenance_lease
        return maintenance_lease(self.context)

    def _keys(self):
        path = self.ssh / "keys.json"
        if not path.exists():
            check_path(path)
            return []
        try:
            value = json.loads(read_private(path, 256 * 1024))
            if not isinstance(value, list):
                raise ValueError()
            return value
        except (ValueError, TypeError) as exc:
            raise PocketError("recovery_required", "The dedicated SSH key registry is invalid.", 503) from exc

    def list_keys(self):
        return [{k: v for k, v in item.items() if k != "key"} for item in self._keys()]

    def _write_keys(self, keys):
        dashboard = self._cfg()["dashboard"]["port"]
        lines = []
        for item in keys:
            if item["role"] == "owner":
                options = f'restrict,pty,port-forwarding,permitopen="127.0.0.1:{dashboard}"'
            else:
                args = [sys.executable, "-m", "core.ssh_git", "--root", str(self.context.root), "--git-key", item["fingerprint"]]
                command = shlex.join(args).replace("\\", "\\\\").replace('"', '\\"')
                options = f'restrict,command="{command}"'
            lines.append(options + " " + item["key"])
        # Registry is authoritative to forced commands. A partially committed
        # removal can only deny access, never add a Git repository permission.
        atomic_write(self.ssh / "keys.json", json.dumps(keys, sort_keys=True).encode())
        atomic_write(self.ssh / "authorized_keys", ("\n".join(lines) + "\n").encode())

    def add_key(self, key, role="owner", repositories=None):
        repositories = [] if repositories is None else repositories
        if role not in ("owner", "git") or not isinstance(repositories, list) or len(repositories) > 100:
            raise PocketError("invalid_key", "Choose an owner or Git role with a bounded repository allowlist.")
        repos = sorted(set(_name(name) for name in repositories))
        if role == "git" and not repos or role == "owner" and repos:
            raise PocketError("invalid_key", "Git keys require repositories; owner keys have shell access.")
        if not isinstance(key, str) or len(key) > 16384 or any(c in key for c in "\r\n\x00"):
            raise PocketError("invalid_key", "Supply exactly one bounded public-key line.")
        parts = key.split()
        if len(parts) < 2 or parts[0] not in ALGORITHMS:
            raise PocketError("invalid_key", "Public-key options, private keys and this algorithm are not accepted.")
        try:
            blob = base64.b64decode(parts[1], validate=True)
            size = int.from_bytes(blob[:4], "big")
            if len(blob) < 8 or blob[4:4 + size].decode("ascii") != parts[0]:
                raise ValueError()
        except (ValueError, UnicodeError) as exc:
            raise PocketError("invalid_key", "Malformed public-key encoding.") from exc
        normalized = parts[0] + " " + parts[1]
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        with self._lease(), FileLock(self.context.paths["locks"] / "ssh-keys.lock"):
            path = self.ssh / ("validate-" + uuid.uuid4().hex + ".pub")
            try:
                atomic_write(path, (normalized + "\n").encode())
                result = self.runner([_binary("ssh-keygen"), "-l", "-E", "sha256", "-f", str(path)],
                                     capture_output=True, text=True, timeout=5, check=False)
                if result.returncode or fingerprint not in result.stdout.split():
                    raise PocketError("invalid_key", "OpenSSH rejected the public-key structure.")
            finally:
                path.unlink(missing_ok=True)
            keys = self._keys()
            if any(item["fingerprint"] == fingerprint for item in keys):
                raise PocketError("conflict", "This key is already enrolled.", 409)
            if len(keys) >= 100:
                raise PocketError("limit_exceeded", "At most 100 keys may be enrolled.", 409)
            keys.append({"fingerprint": fingerprint, "key": normalized, "role": role, "repositories": repos})
            self._write_keys(keys)
        return {"fingerprint": fingerprint, "role": role, "repositories": repos}

    def remove_key(self, fingerprint, *, local=False):
        with self._lease(), FileLock(self.context.paths["locks"] / "ssh-keys.lock"):
            keys = self._keys()
            remaining = [item for item in keys if item["fingerprint"] != fingerprint]
            if len(remaining) == len(keys):
                raise PocketError("not_found", "Unknown SSH key.", 404)
            if not local and any(item["role"] == "owner" for item in keys) and not any(item["role"] == "owner" for item in remaining):
                raise PocketError("last_owner_key", "The final owner key can only be removed locally.", 409)
            self._write_keys(remaining)
        return {"removed": fingerprint, "existing_sessions_revoked": False}

    def _git_env(self):
        home = self.ssh / "git-home"
        private_dir(home)
        env = {k: os.environ[k] for k in ("PATH", "PREFIX", "TMPDIR") if k in os.environ}
        env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), GIT_CONFIG_NOSYSTEM="1",
                   GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")
        return env

    def _git_prefix(self):
        empty = self.ssh / "empty-git-template"
        private_dir(empty)
        return [_binary("git"), "-c", "core.hooksPath=" + str(empty), "-c", "init.templateDir=" + str(empty)]

    def _repo(self, name):
        path = self.repos / (_name(name) + ".git")
        check_path(path)
        if path.exists():
            check_private(path, directory=True)
        return path

    def list_repos(self):
        check_private(self.repos, directory=True)
        result = []
        for path in sorted(self.repos.glob("*.git")):
            if NAME.fullmatch(path.stem):
                self._repo(path.stem)
                result.append({"name": path.stem, "path": str(path)})
        return result

    def create_repo(self, name):
        with self._lease(), FileLock(self.context.paths["locks"] / "git.lock"):
            target = self._repo(name)
            if target.exists():
                raise PocketError("conflict", "Repository already exists.", 409)
            temporary = self.repos / (".create-" + uuid.uuid4().hex)
            private_dir(temporary)
            try:
                command = self._git_prefix() + ["init", "--bare", "--shared=false", "--template=" + str(self.ssh / "empty-git-template"), str(temporary)]
                result = self.runner(command, env=self._git_env(), capture_output=True, text=True, timeout=30, check=False)
                if result.returncode or not (temporary / "HEAD").is_file() or not (temporary / "objects").is_dir():
                    raise PocketError("git_failed", "Git did not create a valid bare repository.", 503)
                os.rename(temporary, target)
            finally:
                if temporary.exists():
                    check_private(temporary, directory=True)
                    shutil.rmtree(temporary)
        return {"name": name, "path": str(target)}

    def git_command(self, fingerprint, original):
        # Exact quoted canonical path only; never execute the original string.
        if not isinstance(original, str) or len(original) > 4096:
            raise PocketError("forbidden", "Unsupported Git command.", 403)
        match = re.fullmatch(r"(git-upload-pack|git-receive-pack) '([^'\r\n]+)'", original)
        if not match:
            raise PocketError("forbidden", "Unsupported Git command.", 403)
        key = next((item for item in self._keys() if item["fingerprint"] == fingerprint and item["role"] == "git"), None)
        if not key:
            raise PocketError("forbidden", "Git key is no longer authorized.", 403)
        path = Path(match[2])
        name = path.name.removesuffix(".git")
        if name not in key["repositories"] or path != self._repo(name) or not path.is_dir():
            raise PocketError("forbidden", "Repository is outside this key's allowlist.", 403)
        return self._git_prefix() + [match[1].removeprefix("git-"), str(path)]

    def run_git(self, fingerprint, original):
        with self._lease():
            command = self.git_command(fingerprint, original)
            return self.runner(command, env=self._git_env(), check=False).returncode

    def foreground_command(self):
        self.context.ensure_mutable()
        if self.context.mode == "mock":
            raise PocketError("unsupported", "Mock mode cannot launch an SSH listener.", 503)
        if not self._keys():
            raise PocketError("no_keys", "Enroll a usable SSH key locally before starting SSH.", 409)
        with FileLock(self.context.paths["locks"] / "ssh-keys.lock"):
            self._write_keys(self._keys())
        cfg = self._cfg()
        hostkey = self.ssh / "ssh_host_ed25519_key"
        if not hostkey.exists():
            result = self.runner([_binary("ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-f", str(hostkey)],
                                 capture_output=True, timeout=10, check=False)
            if result.returncode:
                raise PocketError("ssh_failed", "Dedicated host-key generation failed.", 503)
        check_private(hostkey)
        entry = cfg["services"]["ssh"]
        quote = lambda value: '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'
        policy = ["Port " + str(entry["port"]), "ListenAddress " + entry["bind_address"],
                  "HostKey " + quote(hostkey), "AuthorizedKeysFile " + quote(self.ssh / "authorized_keys"),
                  "PidFile " + quote(self.ssh / "listener.pid"), "PasswordAuthentication no",
                  "KbdInteractiveAuthentication no", "PubkeyAuthentication yes", "AuthenticationMethods publickey",
                  "PermitEmptyPasswords no", "UsePAM no", "AllowAgentForwarding no", "X11Forwarding no",
                  "AllowTcpForwarding local", "GatewayPorts no", "PermitTunnel no", "PermitUserEnvironment no",
                  "HostbasedAuthentication no", "AuthorizedKeysCommand none", "TrustedUserCAKeys none", "PermitListen none",
                  "PermitUserRC no", "PermitOpen 127.0.0.1:" + str(cfg["dashboard"]["port"]),
                  "LogLevel VERBOSE", "StrictModes yes"]
        path = self.ssh / "sshd_config"
        atomic_write(path, ("\n".join(policy) + "\n").encode())
        executable = _binary("sshd")
        result = self.runner([executable, "-t", "-f", str(path)], capture_output=True, timeout=5, check=False)
        if result.returncode:
            raise PocketError("ssh_failed", "OpenSSH rejected the dedicated configuration.", 503)
        atomic_write(self.ssh / "sessions-uncertain", json.dumps({"boot_id": _kernel_boot_id(), "reason": "An owner session may outlive the listener."}).encode())
        atomic_write(self.ssh / "loaded-policy.json", json.dumps({"run_id": os.environ.get("POCKETSERVER_RUN_ID"),
                     "sha256": hashlib.sha256(read_private(path, 65536)).hexdigest(),
                     "port": entry["port"], "bind_address": entry["bind_address"]}).encode())
        return [executable, "-D", "-e", "-f", str(path)]

    def verify_quiescent(self):
        from core.supervisor import read_gate
        gate = read_gate(self.context, "ssh")
        marker = self.ssh / "sessions-uncertain"
        if marker.exists():
            try:
                earlier = json.loads(read_private(marker, 4096)).get("boot_id")
                earlier = earlier if isinstance(earlier, str) and re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", earlier) else None
            except (ValueError, PocketError):
                earlier = None
            current = _kernel_boot_id()
            # A kernel boot change proves prior sessions cannot still exist.
            # This read does not remove markers or adopt stale PID evidence.
            if current and earlier and current != earlier:
                return True
        if marker.exists() or gate.get("desired") or gate.get("payload"):
            raise PocketError("ssh_sessions_uncertain", "Close SSH sessions and verify quiescence locally; stopping the listener alone is insufficient.", 409)
        return True


def _kernel_boot_id():
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        return value if re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", value) else None
    except OSError:
        return None


def ssh_observation(context, run_id):
    """Readiness is independent of whether trusted owner sessions are quiescent."""
    try:
        policy = json.loads(read_private(context.paths["ssh"] / "loaded-policy.json", 4096))
        dedicated = read_private(context.paths["ssh"] / "sshd_config", 65536)
        if not run_id or policy.get("run_id") != run_id or hashlib.sha256(dedicated).hexdigest() != policy.get("sha256"):
            return {"ready": False, "reason": "dedicated_policy_unverified"}
        port = policy["port"]
        if type(port) is not int or not 1024 <= port <= 65535:
            return {"ready": False, "reason": "dedicated_policy_unverified"}
        with socket.create_connection(("127.0.0.1", port), timeout=0.5) as stream:
            banner = stream.recv(256)
        ready = banner.startswith(b"SSH-2.0-OpenSSH_")
        return {"ready": ready, "reason": None if ready else "ssh_banner_unverified"}
    except (OSError, ValueError, KeyError, PocketError):
        return {"ready": False, "reason": "dedicated_policy_unverified"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--git-key", required=True)
    args = parser.parse_args()
    context = RuntimeContext.discover(root=args.root)
    try:
        return SSHGitManager(context).run_git(args.git_key, os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    except PocketError as exc:
        sys.stderr.write(exc.message + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
