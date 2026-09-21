"""Backup and restore: a whole vault directory as one gzip archive.

The vault is a directory of independently encrypted files, so a tarball of it is a
complete, portable, already-encrypted backup. Two consequences shape this module:

* **``backup`` needs no password.** Every file inside is ciphertext, so creating an
  archive reads bytes and gzips them. The archive is exactly as safe as the vault it
  came from -- which is to say, as safe as your keyfile plus your master password.
  It is not extra protection, and the CLI says so.

* **The config directory is deliberately excluded.** ``device_id``, ``state.json``
  and above all ``pin.unlock`` are per-device and must never travel. Bundling
  ``pin.unlock`` with the vault would hand a thief both halves of the PIN scheme,
  undoing the reason the PIN slot lives outside the vault in the first place. So a
  backup contains exactly what Syncthing would sync: the vault, nothing else.

The legacy project's ``restore_db`` overwrote the live database with no snapshot and
no validation -- the sharpest edge in the old code. ``restore`` here refuses to
overwrite an existing vault unless forced, snapshots what it replaces when forced,
rejects unsafe archive members, and verifies the result opens before reporting
success.
"""

from __future__ import annotations

import datetime
import io
import tarfile
from dataclasses import dataclass
from pathlib import Path

from . import format as fmt

__all__ = [
    "BackupError",
    "BackupInfo",
    "ARCHIVE_MARKER",
    "create_backup",
    "inspect_archive",
    "restore_backup",
]

#: A member present in every pipassword archive, used to recognise one before
#: extracting. Kept as a top-level path so ``inspect_archive`` can find it cheaply.
ARCHIVE_MARKER = "pipassword-backup/MANIFEST"

_ROOT = "pipassword-backup"


class BackupError(Exception):
    """A backup or restore could not be completed safely."""


@dataclass
class BackupInfo:
    """What an archive contains, without extracting it."""

    created: str
    vault_uuid: str | None
    keyfile_names: list[str]
    log_names: list[str]
    file_count: int

    @property
    def looks_valid(self) -> bool:
        return bool(self.keyfile_names)


# --------------------------------------------------------------------- create


def create_backup(vault_dir: Path, archive_path: Path) -> BackupInfo:
    """Archive a vault directory to a gzip tarball.

    Returns a description of what was written. Raises :class:`BackupError` rather
    than producing a useless archive.
    """
    vault_dir = Path(vault_dir)
    archive_path = Path(archive_path)

    if not vault_dir.is_dir():
        raise BackupError(f"no vault directory at {vault_dir}")
    if not fmt.find_keyfile_generations(vault_dir):
        raise BackupError(
            f"{vault_dir} has no keyfile; there is nothing to back up. Run "
            f"'pipw init' first."
        )

    # Refuse to write the archive inside the vault, or it would capture a partial,
    # inconsistent copy of itself.
    resolved_archive = archive_path.resolve()
    resolved_vault = vault_dir.resolve()
    if resolved_vault in resolved_archive.parents or resolved_archive == resolved_vault:
        raise BackupError(
            "refusing to write the backup inside the vault directory; choose a path "
            "outside it"
        )

    files = sorted(p for p in vault_dir.rglob("*") if p.is_file())
    keyfiles = [p.name for p in files if fmt._KEYFILE_NAME_RE.match(p.name)]
    logs = [p.name for p in files if p.suffix == ".mpl"]
    vault_uuid = _read_vault_uuid(vault_dir)

    manifest = _build_manifest(vault_uuid, keyfiles, logs, len(files))

    fmt.ensure_dir(archive_path.parent)
    tmp = archive_path.with_name(archive_path.name + ".tmp")
    try:
        with tarfile.open(tmp, "w:gz") as tar:
            info = tarfile.TarInfo(ARCHIVE_MARKER)
            info.size = len(manifest)
            info.mode = 0o600
            tar.addfile(info, io.BytesIO(manifest))

            for path in files:
                arcname = f"{_ROOT}/vault/{path.relative_to(vault_dir).as_posix()}"
                member = tar.gettarinfo(str(path), arcname=arcname)
                # Normalise: no owner leakage, restrictive mode, stable metadata.
                member.uid = member.gid = 0
                member.uname = member.gname = ""
                member.mode = 0o600
                with path.open("rb") as handle:
                    tar.addfile(member, handle)

        # Verify the archive round-trips before we move it into place.
        verify = inspect_archive(tmp)
        if not verify.looks_valid:
            raise BackupError("the archive was written but contains no keyfile")

        tmp.chmod(0o600)
        tmp.replace(archive_path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

    return _build_info(vault_uuid, keyfiles, logs, len(files))


# -------------------------------------------------------------------- inspect


def inspect_archive(archive_path: Path) -> BackupInfo:
    """Read an archive's manifest and member list without extracting anything."""
    archive_path = Path(archive_path)
    if not archive_path.is_file():
        raise BackupError(f"no archive at {archive_path}")

    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            names = tar.getnames()
            marker = next((m for m in tar.getmembers() if m.name == ARCHIVE_MARKER), None)
            manifest = {}
            if marker is not None:
                raw = tar.extractfile(marker)
                if raw is not None:
                    manifest = _parse_manifest(raw.read())
    except (tarfile.TarError, OSError) as exc:
        raise BackupError(f"{archive_path} is not a readable gzip archive: {exc}") from exc

    if ARCHIVE_MARKER not in names:
        raise BackupError(
            f"{archive_path} is not a pipassword backup (no manifest). Refusing to "
            f"treat it as one."
        )

    keyfiles = [
        Path(n).name
        for n in names
        if n.startswith(f"{_ROOT}/vault/") and fmt._KEYFILE_NAME_RE.match(Path(n).name)
    ]
    logs = [Path(n).name for n in names if n.endswith(".mpl")]
    file_count = sum(1 for n in names if n.startswith(f"{_ROOT}/vault/"))

    return BackupInfo(
        created=manifest.get("created", "unknown"),
        vault_uuid=manifest.get("vault_uuid") or None,
        keyfile_names=sorted(keyfiles),
        log_names=sorted(logs),
        file_count=file_count,
    )


# -------------------------------------------------------------------- restore


def restore_backup(
    archive_path: Path,
    vault_dir: Path,
    *,
    force: bool = False,
) -> BackupInfo:
    """Extract an archive into ``vault_dir``.

    Refuses to overwrite an existing vault unless ``force`` is set, and when forcing,
    moves the current vault aside first rather than deleting it. This is the direct
    fix for the legacy ``restore_db``, which clobbered the live database with no
    snapshot and no validation.
    """
    archive_path = Path(archive_path)
    vault_dir = Path(vault_dir)

    info = inspect_archive(archive_path)
    if not info.looks_valid:
        raise BackupError("archive contains no keyfile; refusing to restore it")

    existing = fmt.find_keyfile_generations(vault_dir) if vault_dir.exists() else []
    if existing and not force:
        raise BackupError(
            f"{vault_dir} already contains a vault. Restoring would overwrite it. "
            f"Re-run with force to replace it (the current vault is moved aside, not "
            f"deleted)."
        )

    moved_aside: Path | None = None
    if existing:
        stamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        moved_aside = vault_dir.with_name(f"{vault_dir.name}.replaced-{stamp}")
        vault_dir.replace(moved_aside)

    try:
        fmt.ensure_dir(vault_dir)
        with tarfile.open(archive_path, "r:gz") as tar:
            members = _safe_vault_members(tar)
            if not members:
                raise BackupError("archive has no vault contents to restore")
            for member, relative in members:
                target = vault_dir / relative
                fmt.ensure_dir(target.parent)
                source = tar.extractfile(member)
                data = b"" if source is None else source.read()
                fmt.atomic_write(target, data, mode=0o600)

        # Verify the restored vault actually opens as a vault before declaring success.
        if not fmt.find_keyfile_generations(vault_dir):
            raise BackupError("restore completed but no keyfile is present afterward")
        try:
            fmt.load_keyfile(vault_dir)  # parses, or raises
        except fmt.FormatError as exc:
            raise BackupError(f"restored vault does not open: {exc}") from exc
    except BaseException:
        # Roll back to the vault we moved aside, so a failed restore is not a loss.
        if moved_aside is not None:
            _remove_tree(vault_dir)
            moved_aside.replace(vault_dir)
        raise

    return info


def _safe_vault_members(tar: tarfile.TarFile):
    """Yield ``(member, relative_path)`` for regular files under the vault prefix.

    Rejects anything unsafe: directory traversal, absolute paths, symlinks, or
    devices. The archive was made locally, but treating archive contents as
    untrusted input is cheap and correct.
    """
    prefix = f"{_ROOT}/vault/"
    out = []
    for member in tar.getmembers():
        if member.name == ARCHIVE_MARKER:
            continue
        if not member.name.startswith(prefix):
            continue
        if not member.isreg():
            raise BackupError(f"archive member {member.name!r} is not a regular file")
        relative = member.name[len(prefix):]
        rel_path = Path(relative)
        if rel_path.is_absolute() or ".." in rel_path.parts:
            raise BackupError(f"archive member {member.name!r} has an unsafe path")
        out.append((member, rel_path))
    return out


# --------------------------------------------------------------------- helpers


def _read_vault_uuid(vault_dir: Path) -> str | None:
    try:
        return fmt.load_keyfile(vault_dir).vault_uuid_str
    except (fmt.FormatError, OSError):
        return None


def _build_manifest(vault_uuid, keyfiles, logs, count) -> bytes:
    import json

    return json.dumps(
        {
            "format": "pipassword-backup-v1",
            "created": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
            "vault_uuid": vault_uuid,
            "keyfiles": keyfiles,
            "logs": logs,
            "file_count": count,
        },
        indent=2,
    ).encode("utf-8")


def _parse_manifest(raw: bytes) -> dict:
    import json

    try:
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except (ValueError, UnicodeDecodeError):
        return {}


def _build_info(vault_uuid, keyfiles, logs, count) -> BackupInfo:
    return BackupInfo(
        created=datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        vault_uuid=vault_uuid,
        keyfile_names=sorted(keyfiles),
        log_names=sorted(logs),
        file_count=count,
    )


def _remove_tree(path: Path) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)
