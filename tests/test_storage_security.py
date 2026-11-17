import io
import os
from pathlib import Path

import pytest

from core.config import ConfigManager
from core.errors import PocketError
from core.runtime import RuntimeContext
from core.state import StateStore
from core.storage import FileVault, secure_filesystem_available, validate_relative


@pytest.mark.parametrize("bad", ["", "/absolute", "C:drive", "x/../private", "./x", "x//y", "x/",
                                "a\\b", "NUL.txt", "x\x00", "x\n", "a." , "a ", "a" * 256,
                                "/".join(["a"] * 33), "１２".encode(), "a/b:c"])
def test_path_syntax_rejects_nonportable_or_escaping_names(bad):
    with pytest.raises(PocketError) as issue:
        validate_relative(bad)
    assert issue.value.code == "unsafe_path"


def test_path_is_decoded_only_once():
    assert validate_relative("%2e%2e/visible.txt") == "%2e%2e/visible.txt"
    assert validate_relative("", allow_empty=True) == ""


def test_missing_descriptor_support_fails_closed(isolated_runtime, monkeypatch):
    from core import storage
    monkeypatch.setattr(storage, "secure_filesystem_available", lambda: False)
    files = FileVault(RuntimeContext.discover())
    for func, args in ((files.list, ()), (files.open_read, ("x",)), (files.delete, ("x",)),
                       (files.upload, ("x", io.BytesIO(b"data")))):
        with pytest.raises(PocketError) as issue:
            func(*args)
        assert issue.value.code == "unsupported"
    assert not isolated_runtime.exists()


@pytest.fixture
def vault():
    if not secure_filesystem_available():
        pytest.skip("requires descriptor-relative filesystem operations")
    manager = ConfigManager()
    manager.initialize("a local test password")
    StateStore(manager.context).initialize()
    return FileVault(manager.context)


def test_one_open_read_survives_rename_and_no_clobber(vault):
    vault.upload("file", io.BytesIO(b"initial"))
    with pytest.raises(PocketError) as conflict:
        vault.upload("file", io.BytesIO(b"changed"))
    assert conflict.value.status == 409
    with vault.open_read("file") as stream:
        (vault.root / "file").rename(vault.root / "old")
        (vault.root / "file").write_bytes(b"new")
        assert stream.read() == b"initial"
    assert vault.delete("file")["deleted"]


def test_reject_links_and_root_substitution(vault, tmp_path):
    external = tmp_path / "outside"
    external.write_bytes(b"secret")
    os.link(external, vault.root / "hard")
    (vault.root / "link").symlink_to(external)
    for name in ("hard", "link"):
        with pytest.raises(PocketError):
            vault.open_read(name)
    vault.list()
    vault.root.rename(vault.root.with_name("retained"))
    vault.root.mkdir()
    with pytest.raises(PocketError):
        vault.list()


def test_upload_limit_and_ancestor_swap_publish_nothing(vault, tmp_path):
    sub = vault.root / "sub"
    sub.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    class Swap(io.BytesIO):
        swapped = False
        def read(self, size):
            if not self.swapped:
                sub.rename(vault.root / "old")
                sub.symlink_to(outside, target_is_directory=True)
                self.swapped = True
            return super().read(size)
    with pytest.raises(PocketError):
        vault.upload("sub/x", Swap(b"data"))
    assert not (outside / "x").exists()
    with pytest.raises(PocketError) as too_large:
        vault.upload("too-large", io.BytesIO(b"123"), max_bytes=2)
    assert too_large.value.status == 413
    assert not (vault.root / "too-large").exists()
    assert list(vault.context.paths["staging"].iterdir()) == []


def test_directory_pagination_caps_page(vault):
    for n in range(201):
        (vault.root / str(n)).touch()
    first = vault.list()
    second = vault.list(offset=first["next_offset"])
    assert len(first["entries"]) == 200 and len(second["entries"]) == 1
    assert second["next_offset"] is None
