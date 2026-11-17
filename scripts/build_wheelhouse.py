"""Off-device deterministic pure-wheel assembly; never run this on the phone.

Input wheels are downloaded from the package index by an explicit operator step.
The manifest preserves their hashes. MarkupSafe's Python fallback is repackaged
without its optional native accelerator; all other wheels must already be pure.
This is a derived artifact, not an upstream-published universal MarkupSafe wheel.
"""
from __future__ import annotations
import argparse
import base64
import csv
import email
import hashlib
import io
import json
from pathlib import Path
import shutil
import zipfile

EXPECTED = {"flask": "3.1.3", "werkzeug": "3.1.9", "waitress": "3.0.2",
            "blinker": "1.9.0", "click": "8.5.1", "itsdangerous": "2.2.0",
            "jinja2": "3.1.6", "markupsafe": "3.0.4"}

def digest(data):
    return hashlib.sha256(data).hexdigest()

def pure_markupsafe(source, output):
    with zipfile.ZipFile(source) as archive:
        entries = {}
        for item in archive.infolist():
            name = item.filename
            if name.startswith("/") or ".." in Path(name).parts or "\\" in name:
                raise ValueError("Unsafe wheel path")
            if name.endswith((".pyd", ".so", ".dll", ".dylib", ".c", "/RECORD", "/RECORD.jws", "/RECORD.p7s")) or item.is_dir():
                continue
            entries[name] = archive.read(item)
        if "markupsafe/_native.py" not in entries or "markupsafe/__init__.py" not in entries:
            raise ValueError("Source wheel does not contain the expected Python fallback")
        dist_info = next(name.rsplit("/", 1)[0] for name in entries if name.endswith("/METADATA"))
        entries[f"{dist_info}/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: PocketServer-off-device-pure-fallback\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        rows = []
        for name, data in sorted(entries.items()):
            encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            rows.append([name, f"sha256={encoded}", str(len(data))])
        record_name = f"{dist_info}/RECORD"
        rows.append([record_name, "", ""])
        record = io.StringIO(newline="")
        csv.writer(record, lineterminator="\n").writerows(rows)
        entries[record_name] = record.getvalue().encode()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(entries.items()):
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)

def build(source, destination, lock):
    destination.mkdir(parents=True, exist_ok=True)
    found = {}
    for path in source.glob("*.whl"):
        with zipfile.ZipFile(path) as archive:
            metadata = email.message_from_bytes(archive.read(next(name for name in archive.namelist() if name.endswith("/METADATA"))))
        name, version = metadata["Name"].lower(), metadata["Version"]
        if name not in EXPECTED or EXPECTED[name] != version or name in found:
            raise ValueError(f"Unexpected or duplicate artifact: {path.name}")
        found[name] = (path, metadata)
    if set(found) != set(EXPECTED):
        raise ValueError(f"Missing locked packages: {sorted(set(EXPECTED) - set(found))}")
    manifest = {"format_version": 1, "qualified_on_termux": False, "wheels": []}
    requirements = ["# Runtime lock: locally inspected pure wheels, Python 3.11+.\n# MarkupSafe is a derived Python-fallback wheel; see wheelhouse/manifest.json.\n"]
    for name, (source_path, metadata) in sorted(found.items()):
        version = EXPECTED[name]
        target = destination / (f"markupsafe-{version}-py3-none-any.whl" if name == "markupsafe" else source_path.name)
        if name == "markupsafe":
            pure_markupsafe(source_path, target)
        else:
            if not source_path.name.endswith("-py3-none-any.whl"):
                raise ValueError(f"Non-universal runtime artifact: {source_path.name}")
            shutil.copyfile(source_path, target)
        with zipfile.ZipFile(target) as archive:
            if any(n.endswith((".pyd", ".so", ".dll", ".dylib")) for n in archive.namelist()):
                raise ValueError("Native extension found in runtime wheelhouse")
            licenses = [n for n in archive.namelist() if "license" in n.lower() or "copying" in n.lower()]
            if not licenses:
                raise ValueError(f"Missing license artifact: {target.name}")
        checksum = digest(target.read_bytes())
        requirements.append(f"{name}=={version} --hash=sha256:{checksum}\n")
        manifest["wheels"].append({"name": name, "version": version, "filename": target.name, "sha256": checksum,
                                  "source_filename": source_path.name, "source_sha256": digest(source_path.read_bytes()),
                                  "source": f"https://pypi.org/project/{metadata['Name']}/{version}/#files",
                                  "transformation": "remove optional native accelerator; rebuild WHEEL/RECORD deterministically" if name == "markupsafe" else "unchanged upstream wheel",
                                  "license": metadata.get("License-Expression") or metadata.get("License") or "see retained license files",
                                  "license_files": licenses})
    lock.write_text("".join(requirements), encoding="utf-8")
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Prepared {len(found)} pure wheels; physical Termux qualification remains required.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path(".build/wheels"))
    parser.add_argument("--output", type=Path, default=Path("wheelhouse"))
    parser.add_argument("--lock", type=Path, default=Path("requirements.lock"))
    args = parser.parse_args()
    build(args.input, args.output, args.lock)
