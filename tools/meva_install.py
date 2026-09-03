#!/usr/bin/env python3
"""Safe local MEVA contract installer used by install.sh and uninstall.sh."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


FORMAT = 1
PRODUCT = "MEVA"
MANIFEST = ".meva/install-manifest.json"
STATE = ".meva/state.json"
MERGE_MANUALLY = {"AGENTS.md", ".codex/config.toml"}
ROLE_FILES = {
    ".codex/agents/planner.toml",
    ".codex/agents/implementation_engineer.toml",
    ".codex/agents/platform_engineer.toml",
    ".codex/agents/validation_engineer.toml",
    ".codex/agents/reviewer.toml",
}
FIXED_FILES = (
    "AGENTS.md",
    ".codex/config.toml",
    *sorted(ROLE_FILES),
    "contracts/meva.schema.json",
    "templates/project-state.json",
    "tools/meva_check.py",
    "docs/reviewer-handbook.md",
)


class InstallError(Exception):
    """Expected user-facing installation error."""


def _digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode("utf-8") + b"\n")


def _strict_json(path: Path) -> object:
    def reject_duplicates(pairs: Sequence[Tuple[str, object]]) -> Dict[str, object]:
        result: Dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise InstallError(f"duplicate JSON key in {path}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8"),
                          object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InstallError(f"invalid JSON file: {path}") from error


def _is_digest(value: object) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(char in "0123456789abcdef" for char in value))


def _exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _regular_bytes(path: Path, label: str) -> bytes:
    if path.is_symlink():
        raise InstallError(f"{label} is a symlink: {path}")
    if not path.exists():
        raise InstallError(f"{label} is missing: {path}")
    if not path.is_file():
        raise InstallError(f"{label} is not a regular file: {path}")
    try:
        return path.read_bytes()
    except OSError as error:
        raise InstallError(f"cannot read {label}: {path}") from error


def _resolve_directory(value: str, label: str) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_symlink():
        raise InstallError(f"{label} must not be a symlink: {value}")
    if not candidate.is_dir():
        raise InstallError(f"{label} must be an existing directory: {value}")
    return candidate.resolve()


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _relative_parts(relative: str) -> Tuple[str, ...]:
    if (not isinstance(relative, str) or not relative or relative.startswith("/")
            or "\\" in relative or "\x00" in relative):
        raise InstallError("manifest contains an unsafe relative path")
    parts = tuple(relative.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        raise InstallError("manifest contains an unsafe relative path")
    return parts


def _safe_path(root: Path, relative: str) -> Path:
    parts = _relative_parts(relative)
    current = root
    for part in parts[:-1]:
        current /= part
        if current.is_symlink() or (_exists(current) and not current.is_dir()):
            raise InstallError(f"path parent is unsafe: {relative}")
    return root.joinpath(*parts)


def _parent_paths(relative: str) -> Iterable[str]:
    parent = PurePosixPath(relative).parent
    while str(parent) != ".":
        yield parent.as_posix()
        parent = parent.parent


def _allowed_release_file(relative: object) -> bool:
    if not isinstance(relative, str):
        return False
    if relative in FIXED_FILES:
        return True
    if relative.startswith("tests/conformance/"):
        parts = _relative_parts(relative)
        return (len(parts) >= 3 and "__pycache__" not in parts
                and not parts[-1].endswith((".pyc", ".pyo"))
                and parts[-1] != ".DS_Store")
    return False


def _source_files(source: Path) -> List[str]:
    files = list(FIXED_FILES)
    conformance = source / "tests" / "conformance"
    if not conformance.is_dir() or conformance.is_symlink():
        raise InstallError("MEVA source is missing tests/conformance")
    for path in sorted(conformance.rglob("*")):
        if path.is_symlink():
            relative = path.relative_to(source).as_posix()
            raise InstallError(f"MEVA source contains an unsafe file: {relative}")
        if path.is_dir():
            continue
        relative = path.relative_to(source).as_posix()
        if (path.name == ".DS_Store" or "__pycache__" in path.parts
                or path.suffix in {".pyc", ".pyo"}):
            continue
        if path.is_symlink() or not path.is_file():
            raise InstallError(f"MEVA source contains an unsafe file: {relative}")
        files.append(relative)
    return sorted(set(files))


def _check_source_package(source: Path) -> None:
    checker = source / "tools" / "meva_check.py"
    result = subprocess.run(
        [sys.executable, str(checker), "check-package", "--root", str(source)],
        cwd=str(source), capture_output=True, text=True)
    if result.returncode:
        detail = (result.stdout.strip() or result.stderr.strip() or
                  "no diagnostic returned")
        raise InstallError(f"MEVA source package check failed: {detail[-1200:]}")


def _validate_state(state: Path, schema: Path, source: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(source / "tools" / "meva_check.py"),
         "validate-state", str(state), "--schema", str(schema)],
        cwd=str(source), capture_output=True, text=True)
    if result.returncode:
        detail = (result.stdout.strip() or result.stderr.strip() or
                  "no diagnostic returned")
        raise InstallError(f"MEVA state validation failed: {detail[-1200:]}")


def _manifest_payload(payload: Mapping[str, object]) -> bytes:
    return _json_bytes(payload)


def _manifest_bytes(payload: Mapping[str, object]) -> bytes:
    return _json_bytes({
        "payload": payload,
        "payload_sha256": _digest(_manifest_payload(payload)),
    })


def _validate_payload(payload: object) -> Dict[str, object]:
    if not isinstance(payload, dict):
        raise InstallError("MEVA install manifest payload is invalid")
    if set(payload) != {"format", "product", "files", "state", "directories"}:
        raise InstallError("MEVA install manifest payload is incompatible")
    if payload.get("format") != FORMAT or payload.get("product") != PRODUCT:
        raise InstallError("MEVA install manifest is incompatible")
    files = payload.get("files")
    if not isinstance(files, dict) or not files:
        raise InstallError("MEVA install manifest has no managed files")
    for relative, metadata in files.items():
        if not _allowed_release_file(relative):
            raise InstallError(f"MEVA manifest contains an unexpected path: {relative}")
        if (not isinstance(metadata, dict)
                or set(metadata) != {"sha256", "created"}
                or not _is_digest(metadata.get("sha256"))
                or not isinstance(metadata.get("created"), bool)):
            raise InstallError(f"MEVA manifest has invalid metadata: {relative}")
    state = payload.get("state")
    if (not isinstance(state, dict)
            or set(state) != {"path", "sha256", "created"}
            or state.get("path") != STATE
            or not _is_digest(state.get("sha256"))
            or not isinstance(state.get("created"), bool)):
        raise InstallError("MEVA manifest has invalid state metadata")
    directories = payload.get("directories")
    if (not isinstance(directories, list)
            or any(not isinstance(item, str) for item in directories)
            or len(set(directories)) != len(directories)):
        raise InstallError("MEVA manifest has invalid directory metadata")
    for relative in directories:
        _relative_parts(relative)
    return dict(payload)


def _load_manifest(path: Path) -> Dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise InstallError("MEVA install manifest is not a regular file")
    value = _strict_json(path)
    if (not isinstance(value, dict)
            or set(value) != {"payload", "payload_sha256"}
            or not _is_digest(value.get("payload_sha256"))):
        raise InstallError("MEVA install manifest is invalid")
    payload = _validate_payload(value.get("payload"))
    if value["payload_sha256"] != _digest(_manifest_payload(payload)):
        raise InstallError("MEVA install manifest has been modified")
    return payload


def _missing_directories(target: Path, relatives: Iterable[str]) -> List[str]:
    needed = set()
    for relative in relatives:
        for parent in _parent_paths(relative):
            path = _safe_path(target, parent + "/.placeholder")
            directory = path.parent
            if directory.is_symlink() or (_exists(directory) and not directory.is_dir()):
                raise InstallError(f"target path is not a directory: {parent}")
            if not directory.exists():
                needed.add(parent)
    return sorted(needed, key=lambda item: (item.count("/"), item))


def _validate_manifest_targets(target: Path, payload: Mapping[str, object]) -> None:
    files = payload["files"]
    assert isinstance(files, dict)
    for relative, metadata in files.items():
        path = _safe_path(target, relative)
        body = _regular_bytes(path, "managed file")
        if metadata["created"] and _digest(body) != metadata["sha256"]:
            raise InstallError(f"managed file changed: {relative}")
    state = payload["state"]
    assert isinstance(state, dict)
    _regular_bytes(_safe_path(target, STATE), "MEVA state")


def _install_plan(source: Path, target: Path) -> Dict[str, object]:
    _check_source_package(source)
    source_files = _source_files(source)
    source_bodies = {
        relative: _regular_bytes(source / relative, "MEVA source file")
        for relative in source_files
    }
    source_digests = {relative: _digest(body)
                      for relative, body in source_bodies.items()}
    manifest_path = _safe_path(target, MANIFEST)

    if _exists(manifest_path):
        payload = _load_manifest(manifest_path)
        files = payload["files"]
        assert isinstance(files, dict)
        if set(files) != set(source_digests) or any(
                files[relative]["sha256"] != source_digests[relative]
                for relative in source_digests):
            raise InstallError(
                "existing MEVA installation uses a different source release; "
                "uninstall it before installing this release")
        _validate_manifest_targets(target, payload)
        return {
            "source": source,
            "target": target,
            "existing": True,
            "payload": payload,
            "source_bodies": source_bodies,
            "state_body": None,
            "manifest_body": None,
            "changed": [],
            "preserved": sorted(list(files) + [STATE]),
            "manual_merge": [],
            "directories": [],
        }

    schema = source / "contracts" / "meva.schema.json"
    template = source / "templates" / "project-state.json"
    _regular_bytes(schema, "MEVA schema")
    template_body = _regular_bytes(template, "MEVA state template")
    state_path = _safe_path(target, STATE)
    if _exists(state_path):
        state_body = _regular_bytes(state_path, "existing MEVA state")
        _validate_state(state_path, schema, source)
        state_metadata = {
            "path": STATE, "sha256": _digest(state_body), "created": False,
        }
    else:
        with tempfile.TemporaryDirectory(prefix="meva-state-check-") as name:
            temporary_state = Path(name) / "state.json"
            temporary_state.write_bytes(template_body)
            _validate_state(temporary_state, schema, source)
        state_body = template_body
        state_metadata = {
            "path": STATE, "sha256": _digest(state_body), "created": True,
        }

    conflicts = []
    manual_merge = []
    file_metadata = {}
    for relative in source_files:
        destination = _safe_path(target, relative)
        if destination.is_symlink() or (_exists(destination) and not destination.is_file()):
            raise InstallError(f"target path is not a regular file: {relative}")
        if destination.exists():
            if _digest(destination.read_bytes()) != source_digests[relative]:
                if relative in MERGE_MANUALLY:
                    manual_merge.append(relative)
                else:
                    conflicts.append(relative)
            file_metadata[relative] = {
                "sha256": source_digests[relative], "created": False,
            }
        else:
            file_metadata[relative] = {
                "sha256": source_digests[relative], "created": True,
            }
    if conflicts:
        raise InstallError(
            "conflicting MEVA-managed files (no changes made): "
            + ", ".join(sorted(conflicts)))

    directories = _missing_directories(
        target, list(file_metadata) + [STATE, MANIFEST])
    payload = {
        "format": FORMAT,
        "product": PRODUCT,
        "files": dict(sorted(file_metadata.items())),
        "state": state_metadata,
        "directories": directories,
    }
    changed = [relative for relative, metadata in file_metadata.items()
               if metadata["created"]]
    if state_metadata["created"]:
        changed.append(STATE)
    changed.append(MANIFEST)
    preserved = [relative for relative, metadata in file_metadata.items()
                 if not metadata["created"]]
    if not state_metadata["created"]:
        preserved.append(STATE)
    return {
        "source": source,
        "target": target,
        "existing": False,
        "payload": payload,
        "source_bodies": source_bodies,
        "state_body": state_body,
        "manifest_body": _manifest_bytes(payload),
        "changed": sorted(changed),
        "preserved": sorted(preserved),
        "manual_merge": sorted(manual_merge),
        "directories": directories,
    }


def _write_stage(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _remove_install_created(created: List[Tuple[Path, str]],
                            directories: List[str], target: Path) -> Optional[Exception]:
    failure: Optional[Exception] = None
    for destination, expected in reversed(created):
        try:
            if not destination.exists():
                continue
            if destination.is_symlink() or not destination.is_file():
                raise InstallError(f"rollback found an unsafe path: {destination}")
            if _digest(destination.read_bytes()) != expected:
                raise InstallError(f"rollback found a changed file: {destination}")
            destination.unlink()
        except Exception as error:
            failure = error
    for relative in sorted(directories, key=lambda item: item.count("/"), reverse=True):
        try:
            _safe_path(target, relative).rmdir()
        except OSError:
            pass
        except Exception as error:
            failure = error
    return failure


def _apply_install(plan: Mapping[str, object]) -> None:
    target = plan["target"]
    assert isinstance(target, Path)
    source_bodies = plan["source_bodies"]
    payload = plan["payload"]
    assert isinstance(source_bodies, dict) and isinstance(payload, dict)
    state_body = plan["state_body"]
    manifest_body = plan["manifest_body"]
    assert isinstance(state_body, bytes) and isinstance(manifest_body, bytes)
    file_metadata = payload["files"]
    state_metadata = payload["state"]
    directories = payload["directories"]
    assert isinstance(file_metadata, dict) and isinstance(state_metadata, dict)
    assert isinstance(directories, list)
    stage = Path(tempfile.mkdtemp(prefix=".meva-install-", dir=str(target)))
    created: List[Tuple[Path, str]] = []
    try:
        bodies = {
            relative: source_bodies[relative]
            for relative, metadata in file_metadata.items()
            if metadata["created"]
        }
        if state_metadata["created"]:
            bodies[STATE] = state_body
        bodies[MANIFEST] = manifest_body
        for relative, body in bodies.items():
            _write_stage(stage / relative, body)
        for relative in sorted(bodies):
            destination = _safe_path(target, relative)
            if _exists(destination):
                raise InstallError(
                    f"target changed during installation; refusing to overwrite: {relative}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(str(stage / relative), str(destination))
            created.append((destination, _digest(bodies[relative])))
    except Exception as error:
        rollback_error = _remove_install_created(created, directories, target)
        if rollback_error is not None:
            raise InstallError("install_rollback_failed") from error
        raise InstallError("installation failed; changes rolled back") from error
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _install(source_value: str, target_value: str, preview: bool) -> Dict[str, object]:
    source = _resolve_directory(source_value, "MEVA source")
    target = _resolve_directory(target_value, "target project")
    if source == target or _is_within(target, source) or _is_within(source, target):
        raise InstallError("MEVA source and target project must be separate directories")
    plan = _install_plan(source, target)
    result = {
        "ok": True,
        "path": str(target),
        "changed": plan["changed"],
        "noop": not plan["changed"],
        "preview": preview,
        "preserved": plan["preserved"],
    }
    if plan["manual_merge"]:
        result["manual_merge"] = plan["manual_merge"]
    if preview or plan["existing"]:
        return result
    _apply_install(plan)
    return result


def _planned_pruned_directories(target: Path, directories: Iterable[str],
                                candidates: Iterable[str]) -> List[str]:
    candidate_paths = {_safe_path(target, relative) for relative in candidates}
    prunable: List[str] = []
    for relative in sorted(directories, key=lambda item: item.count("/"), reverse=True):
        directory = _safe_path(target, relative)
        if not directory.is_dir() or directory.is_symlink():
            continue
        remaining = []
        for child in directory.iterdir():
            if child in candidate_paths:
                continue
            if any(child == _safe_path(target, item) for item in prunable):
                continue
            remaining.append(child)
        if not remaining:
            prunable.append(relative)
    return sorted(prunable)


def _uninstall_plan(target: Path, purge_state: bool) -> Dict[str, object]:
    manifest_path = _safe_path(target, MANIFEST)
    if not _exists(manifest_path):
        return {
            "target": target,
            "noop": True,
            "changed": [],
            "preserved": [],
            "candidates": [],
            "directories": [],
            "payload": None,
            "reason": "MEVA install manifest not found",
        }
    payload = _load_manifest(manifest_path)
    _validate_manifest_targets(target, payload)
    files = payload["files"]
    state_metadata = payload["state"]
    directories = payload["directories"]
    assert isinstance(files, dict) and isinstance(state_metadata, dict)
    assert isinstance(directories, list)
    candidates: List[str] = []
    preserved: List[str] = []
    for relative, metadata in files.items():
        path = _safe_path(target, relative)
        if metadata["created"]:
            if path.exists():
                body = _regular_bytes(path, "managed file")
                if _digest(body) != metadata["sha256"]:
                    raise InstallError(f"managed file changed: {relative}")
                candidates.append(relative)
        elif path.exists():
            preserved.append(relative)
    state_path = _safe_path(target, STATE)
    if state_metadata["created"] and purge_state:
        if state_path.exists():
            body = _regular_bytes(state_path, "MEVA-created state")
            if _digest(body) != state_metadata["sha256"]:
                raise InstallError("MEVA-created state changed; refusing purge")
            candidates.append(STATE)
    elif state_path.exists():
        preserved.append(
            STATE + (" (adopted/pre-existing state)"
                     if not state_metadata["created"]
                     else " (durable state preserved; use --purge-state to remove)"))
    manifest_body = _regular_bytes(manifest_path, "MEVA install manifest")
    candidates.append(MANIFEST)
    directories_to_prune = _planned_pruned_directories(
        target, directories, candidates)
    changed = sorted(set(candidates + [relative + "/"
                                       for relative in directories_to_prune]))
    return {
        "target": target,
        "noop": False,
        "changed": changed,
        "preserved": sorted(preserved),
        "candidates": sorted(set(candidates)),
        "directories": directories,
        "directories_to_prune": directories_to_prune,
        "payload": payload,
        "manifest_body": manifest_body,
        "purge_state": purge_state,
    }


def _apply_uninstall(plan: Mapping[str, object]) -> List[str]:
    target = plan["target"]
    assert isinstance(target, Path)
    payload = plan["payload"]
    candidates = plan["candidates"]
    assert isinstance(payload, dict) and isinstance(candidates, list)
    files = payload["files"]
    state_metadata = payload["state"]
    assert isinstance(files, dict) and isinstance(state_metadata, dict)
    backup = Path(tempfile.mkdtemp(prefix=".meva-uninstall-", dir=str(target)))
    moved: List[Tuple[Path, Path]] = []
    pruned: List[str] = []
    try:
        for relative in candidates:
            source = _safe_path(target, relative)
            if not source.exists():
                continue
            if relative == STATE:
                expected = state_metadata["sha256"]
            elif relative == MANIFEST:
                expected = _digest(plan["manifest_body"])
            else:
                expected = files[relative]["sha256"]
            body = _regular_bytes(source, "removal candidate")
            if _digest(body) != expected:
                raise InstallError(f"target changed during uninstall: {relative}")
            destination = backup / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(str(source), str(destination))
            moved.append((source, destination))
        for relative in sorted(plan["directories"],
                               key=lambda item: item.count("/"), reverse=True):
            directory = _safe_path(target, relative)
            if directory.is_symlink() or (_exists(directory) and not directory.is_dir()):
                raise InstallError(f"target directory became unsafe: {relative}")
            if directory.exists():
                try:
                    directory.rmdir()
                    pruned.append(relative)
                except OSError:
                    pass
    except Exception as error:
        rollback_error: Optional[Exception] = None
        for original, saved in reversed(moved):
            try:
                if _exists(original):
                    raise InstallError(f"rollback target is no longer empty: {original}")
                original.parent.mkdir(parents=True, exist_ok=True)
                os.replace(str(saved), str(original))
            except Exception as failure:
                rollback_error = failure
        shutil.rmtree(backup, ignore_errors=True)
        if rollback_error is not None:
            raise InstallError("uninstall_rollback_failed") from error
        raise InstallError("uninstall failed; changes rolled back") from error
    shutil.rmtree(backup, ignore_errors=True)
    return sorted(pruned)


def _uninstall(target_value: str, preview: bool, purge_state: bool) -> Dict[str, object]:
    target = _resolve_directory(target_value, "target project")
    plan = _uninstall_plan(target, purge_state)
    if plan["noop"]:
        return {
            "ok": True,
            "path": str(target),
            "changed": [],
            "noop": True,
            "preview": preview,
            "preserved": [],
            "reason": plan["reason"],
        }
    result = {
        "ok": True,
        "path": str(target),
        "changed": plan["changed"],
        "noop": False,
        "preview": preview,
        "preserved": plan["preserved"],
        "state": "purged" if purge_state else "preserved",
    }
    if preview:
        return result
    pruned = _apply_uninstall(plan)
    result["changed"] = sorted(set(plan["candidates"] + [relative + "/"
                                                          for relative in pruned]))
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="meva_install.py")
    commands = parser.add_subparsers(dest="command", required=True)
    install = commands.add_parser("install")
    install.add_argument("--source", required=True)
    install.add_argument("--target", required=True)
    install.add_argument("--preview", action="store_true")
    uninstall = commands.add_parser("uninstall")
    uninstall.add_argument("--target", required=True)
    uninstall.add_argument("--preview", action="store_true")
    uninstall.add_argument("--purge-state", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "install":
            result = _install(args.source, args.target, args.preview)
        else:
            result = _uninstall(args.target, args.preview, args.purge_state)
    except (InstallError, OSError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)},
                         sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
