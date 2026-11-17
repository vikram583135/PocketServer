import base64
import hashlib
import json
from types import SimpleNamespace

import pytest

from core.config import ConfigManager
from core.errors import PocketError
from core.runtime import RuntimeContext, atomic_write, private_dir
from core.ssh_git import SSHGitManager


@pytest.fixture
def manager(isolated_runtime, monkeypatch):
    monkeypatch.setattr("core.config.PBKDF2_ITERATIONS", 1000)
    ctx = RuntimeContext(isolated_runtime, "mock")
    ConfigManager(ctx).initialize("a-long-safe-test-password")
    monkeypatch.setattr("core.ssh_git._binary", lambda name: "/trusted/" + name)
    return SSHGitManager(ctx)


def key():
    blob = b"\x00\x00\x00\x0bssh-ed25519" + b"\x00\x00\x00\x20" + b"x" * 32
    return "ssh-ed25519 " + base64.b64encode(blob).decode(), "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def test_keys_structural_validation_dedup_and_final_owner(manager):
    public, fingerprint = key()
    calls = []
    def runner(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout="256 " + fingerprint + " owner (ED25519)")
    manager.runner = runner
    assert manager.add_key(public)["fingerprint"] == fingerprint
    assert "permitopen=" in (manager.ssh / "authorized_keys").read_text()
    assert calls[0][1:4] == ["-l", "-E", "sha256"]
    with pytest.raises(PocketError, match="already enrolled"):
        manager.add_key(public)
    with pytest.raises(PocketError, match="final owner"):
        manager.remove_key(fingerprint)
    assert manager.remove_key(fingerprint, local=True)["existing_sessions_revoked"] is False


@pytest.mark.parametrize("public", ['command="evil" ssh-ed25519 eA==', "ssh-ed25519 eA==\n", "-----BEGIN PRIVATE KEY-----", "ssh-ed25519 !bad!"])
def test_malicious_keys_rejected_before_openssh(manager, public):
    manager.runner = lambda *a, **kw: pytest.fail("Invalid key reached OpenSSH")
    with pytest.raises(PocketError):
        manager.add_key(public)


def test_openssh_rejection_is_authoritative(manager):
    manager.runner = lambda *a, **kw: SimpleNamespace(returncode=1, stdout="")
    with pytest.raises(PocketError, match="structure"):
        manager.add_key(key()[0])
    assert manager.list_keys() == []


def test_restricted_git_grammar_and_environment(manager, monkeypatch):
    public, fingerprint = key()
    manager.runner = lambda *a, **kw: SimpleNamespace(returncode=0, stdout=fingerprint)
    manager.add_key(public, role="git", repositories=["demo"])
    private_dir(manager.repos / "demo.git")
    valid = "git-receive-pack '" + str(manager.repos / "demo.git") + "'"
    command = manager.git_command(fingerprint, valid)
    assert command[-2:] == ["receive-pack", str(manager.repos / "demo.git")]
    for evil in (valid + "; id", "git-upload-pack ../../secret", valid.replace("demo.git", "other.git"), "sh -c 'id'"):
        with pytest.raises(PocketError):
            manager.git_command(fingerprint, evil)
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
    env = manager._git_env()
    assert "GIT_CONFIG_COUNT" not in env
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"


def test_create_repo_stages_validates_and_never_overwrites(manager):
    def runner(argv, **kwargs):
        directory = __import__("pathlib").Path(argv[-1])
        atomic_write(directory / "HEAD", b"ref: refs/heads/main\n")
        private_dir(directory / "objects")
        return SimpleNamespace(returncode=0)
    manager.runner = runner
    manager.create_repo("demo")
    assert manager.list_repos()[0]["name"] == "demo"
    with pytest.raises(PocketError, match="already exists"):
        manager.create_repo("demo")
    with pytest.raises(PocketError):
        manager.create_repo("../escape")


def test_quiescence_refuses_possible_persisting_sessions(manager):
    assert manager.verify_quiescent() is True
    atomic_write(manager.ssh / "sessions-uncertain", b"listener was launched")
    with pytest.raises(PocketError) as exc:
        manager.verify_quiescent()
    assert exc.value.code == "ssh_sessions_uncertain"


def test_mock_never_launches_listener(manager):
    with pytest.raises(PocketError) as exc:
        manager.foreground_command()
    assert exc.value.code == "unsupported"


def test_dedicated_policy_validated_before_foreground_command(manager, monkeypatch):
    public, fingerprint = key()
    manager.runner = lambda *a, **kw: SimpleNamespace(returncode=0, stdout=fingerprint)
    manager.add_key(public)
    atomic_write(manager.ssh / "ssh_host_ed25519_key", b"owned private key test fixture")
    original = manager.context
    manager.context = SimpleNamespace(root=original.root, paths=original.paths, mode="termux", ensure_mutable=original.ensure_mutable)
    monkeypatch.setenv("POCKETSERVER_RUN_ID", "owned-run")
    calls = []
    def validate(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0)
    manager.runner = validate
    command = manager.foreground_command()
    policy = (manager.ssh / "sshd_config").read_text()
    assert calls[0][1:3] == ["-t", "-f"]
    assert command[1:3] == ["-D", "-e"]
    assert "PasswordAuthentication no" in policy and "PermitListen none" in policy
    assert "Include " not in policy
    assert json.loads((manager.ssh / "loaded-policy.json").read_text())["run_id"] == "owned-run"


def test_ssh_readiness_requires_current_dedicated_policy(manager, monkeypatch):
    from core.ssh_git import ssh_observation
    policy = b"PasswordAuthentication no\n"
    atomic_write(manager.ssh / "sshd_config", policy)
    atomic_write(manager.ssh / "loaded-policy.json", json.dumps({"run_id": "current", "port": 8022,
                 "sha256": hashlib.sha256(policy).hexdigest()}).encode())
    class Connection:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def recv(self, size):
            return b"SSH-2.0-OpenSSH_9.9\r\n"
    monkeypatch.setattr("core.ssh_git.socket.create_connection", lambda *a, **kw: Connection())
    assert ssh_observation(manager.context, "current")["ready"]
    assert not ssh_observation(manager.context, "stale")["ready"]
    atomic_write(manager.ssh / "sshd_config", b"changed")
    assert not ssh_observation(manager.context, "current")["ready"]
