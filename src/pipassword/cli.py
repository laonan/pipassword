"""Non-interactive command line.

Built for scripting and for large terminals, where a pipeline is often what you
actually want::

    pipw get github --field password | wl-copy

Two rules shape this module:

* Argument parsing happens inside :func:`run`, never at import time. The legacy
  ``minipassword.commands`` called ``parse_args()`` at module scope, so importing
  the library parsed ``sys.argv`` and could terminate the process.
* Secrets go to stdout only when explicitly asked for. Everything else, including
  prompts and progress, goes to stderr, so ``--field`` output stays pipeable.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence, TextIO

from . import __version__
from . import crypto, events as ev, format as fmt
from .importer import ImportError_ as _ImporterError
from .vault import (
    DuplicateNameError,
    RecordNotFoundError,
    Vault,
    VaultConfig,
    VaultError,
    default_config_dir,
    default_vault_dir,
)

__all__ = ["build_parser", "run", "Console", "main"]

MASK = "••••••••"


# ------------------------------------------------------------------- console


@dataclass
class Console:
    """Injectable IO, so every command is testable without a terminal."""

    stdin: TextIO
    stdout: TextIO
    stderr: TextIO
    secrets_from_stdin: bool = False
    assume_yes: bool = False

    def out(self, message: str = "") -> None:
        print(message, file=self.stdout)

    def err(self, message: str = "") -> None:
        print(message, file=self.stderr)

    def ask(self, prompt: str, default: str = "") -> str:
        self.stderr.write(prompt)
        self.stderr.flush()
        line = self.stdin.readline()
        if not line:
            raise EOFError("no input")
        return line.rstrip("\n") or default

    def _stdin_is_terminal(self) -> bool:
        try:
            return bool(self.stdin.isatty())
        except (AttributeError, ValueError):
            return False

    def ask_secret(self, prompt: str) -> str:
        """Read a secret without echoing it (requirement 2.13).

        The legacy project read passwords with ``input()``, so they were echoed to
        the screen and left in terminal scrollback.

        ``getpass`` is used only when stdin is an actual terminal. Otherwise the
        secret is read from the stream we were given, which is what a pipeline
        needs and what makes these paths testable. ``getpass`` opens ``/dev/tty``
        directly, so calling it unconditionally would block forever whenever stdin
        is a pipe.
        """
        if self.secrets_from_stdin or not self._stdin_is_terminal():
            line = self.stdin.readline()
            if not line:
                raise EOFError("no input")
            return line.rstrip("\n")
        return getpass.getpass(prompt, stream=self.stderr)

    def confirm(self, prompt: str) -> bool:
        if self.assume_yes:
            return True
        return self.ask(f"{prompt} [y/N]: ").strip().lower() in {"y", "yes"}


# ------------------------------------------------------------------ helpers


def resolve_vault_dir(args: argparse.Namespace) -> Path:
    """--vault, then PIPASSWORD_VAULT, then config.toml, then the XDG default."""
    if getattr(args, "vault", None):
        return Path(args.vault)
    if os.environ.get("PIPASSWORD_VAULT"):
        return default_vault_dir()
    configured = VaultConfig.load(resolve_config_dir(args)).vault_path
    return configured if configured is not None else default_vault_dir()


def resolve_config_dir(args: argparse.Namespace) -> Path:
    if getattr(args, "config_dir", None):
        return Path(args.config_dir)
    return default_config_dir()


def passphrase_advice(passphrase: str) -> str | None:
    """A deliberately modest strength heuristic.

    Not a security control, and not presented as one. The honest position is that
    Argon2id at 64 MiB buys perhaps 10-20 bits of work factor against an attacker
    with fast hardware, so passphrase entropy is what actually carries the
    security. A long multi-word passphrase is both stronger and easier to type on
    a BBQ20 thumb keyboard than a short one full of symbols.
    """
    stripped = passphrase.strip()
    words = [w for w in stripped.split() if w]
    if len(stripped) >= 20 or len(words) >= 4:
        return None
    if len(stripped) < 12:
        return (
            "That passphrase is short. Because an attacker runs the key derivation "
            "on fast hardware, its length matters more than its punctuation. Four "
            "or more unrelated words is stronger than a short complex string, and "
            "much easier to type on a thumb keyboard."
        )
    return (
        "Consider a longer passphrase. Several unrelated words beat a short complex "
        "string, and are easier to type on the Beepy."
    )


def open_vault(args: argparse.Namespace, console: Console) -> Vault:
    vault_dir = resolve_vault_dir(args)
    if not fmt.find_keyfile_generations(vault_dir):
        raise VaultError(
            f"no vault found at {vault_dir}. Run 'pipw init' to create one, or "
            f"pass --vault."
        )

    if getattr(args, "recovery_key", False):
        raw = console.ask_secret("Recovery key: ")
        return Vault.unlock(
            vault_dir,
            recovery_key=crypto.parse_recovery_key(raw),
            config_dir=resolve_config_dir(args),
        )

    password = console.ask_secret("Master password: ")
    return Vault.unlock(
        vault_dir, password=password, config_dir=resolve_config_dir(args)
    )


def report_health(vault: Vault, console: Console) -> None:
    """Surface anomalies, conflicts, clock skew, and what other devices changed."""
    for anomaly in vault.anomalies:
        console.err(f"warning: {anomaly}")

    if vault.clock_is_behind:
        console.err(
            "warning: this device's clock is behind timestamps already in the "
            "vault. Edits are still safe to make, but TOTP codes will be refused "
            "until the clock is corrected."
        )

    summary = vault.changes_since_last_open()
    if summary.is_empty:
        return

    parts = []
    if summary.added:
        parts.append(f"{len(summary.added)} added")
    if summary.updated:
        parts.append(f"{len(summary.updated)} updated")
    if summary.deleted:
        parts.append(f"{len(summary.deleted)} deleted")
    console.err(f"Since you last opened this vault: {', '.join(parts)}.")
    for record in list(summary.added)[:5]:
        console.err(f"  + {record.name}")
    for record in list(summary.updated)[:5]:
        console.err(f"  ~ {record.name}")


def format_record(record: ev.Record, *, show_password: bool) -> str:
    lines = [
        f"id       {record.id}",
        f"name     {record.name}",
    ]
    if record.login:
        lines.append(f"login    {record.login}")
    lines.append(
        f"password {record.password if show_password else MASK}"
        if record.password
        else "password (none)"
    )
    if record.url:
        lines.append(f"url      {record.url}")
    if record.totp:
        lines.append(f"totp     {'(set)' if not show_password else record.totp}")
    if record.legacy_id is not None:
        lines.append(f"legacy   {record.legacy_id}")
    if record.memo:
        lines.append("memo")
        for line in record.memo.splitlines():
            lines.append(f"  {line}")
    return "\n".join(lines)


# ------------------------------------------------------------------ commands


def cmd_init(args: argparse.Namespace, console: Console) -> int:
    vault_dir = Path(args.vault) if args.vault else default_vault_dir()
    config_dir = resolve_config_dir(args)

    if fmt.find_keyfile_generations(vault_dir):
        console.err(f"error: a vault already exists at {vault_dir}")
        return 1

    params = crypto.KdfParams(
        time_cost=args.time_cost,
        memory_cost_kib=args.memory_cost,
        parallelism=args.parallelism,
    )
    check = crypto.check_memory_available(params)
    if not check.sufficient:
        console.err(f"error: {check.detail}")
        return 1

    password = console.ask_secret("Choose a master password: ")
    if not password:
        console.err("error: a master password is required")
        return 1

    if not console.secrets_from_stdin:
        again = console.ask_secret("Repeat it: ")
        if again != password:
            console.err("error: the two entries did not match")
            return 1

    advice = passphrase_advice(password)
    if advice:
        console.err(f"note: {advice}")

    console.err(f"Deriving key (Argon2id, {params.memory_human})...")
    started = time.perf_counter()
    vault, recovery_key = Vault.create(
        vault_dir,
        password,
        params=params,
        config_dir=config_dir,
        check_memory=False,
    )
    elapsed = time.perf_counter() - started

    try:
        VaultConfig(vault_path=vault_dir, device_name=vault.device.name).save(
            config_dir
        )

        console.out(f"Vault created at {vault_dir}")
        console.out(f"Unlock takes about {elapsed:.1f}s on this device.")
        console.out("")
        console.out("=" * 64)
        console.out("RECOVERY KEY - write this on paper and store it somewhere safe.")
        console.out("It is the only way into this vault if you forget the password.")
        console.out("It is shown once and is not stored anywhere.")
        console.out("=" * 64)
        console.out("")
        console.out(f"    {crypto.format_recovery_key(recovery_key)}")
        console.out("")

        if not console.assume_yes:
            while True:
                answer = console.ask("Type 'recorded' once you have written it down: ")
                if answer.strip().lower() == "recorded":
                    break
                console.err("Please write the recovery key down first.")

        console.err("")
        console.err("Next steps:")
        console.err(f"  - point Syncthing at {vault_dir} to sync across devices")
        console.err("  - run 'pipw import-legacy --dry-run' to preview a migration")
    finally:
        vault.close()
    return 0


def cmd_list(args: argparse.Namespace, console: Console) -> int:
    with open_vault(args, console) as vault:
        report_health(vault, console)
        records = vault.all_records()
        if not records:
            console.err("The vault is empty.")
            return 0
        for record in records:
            suffix = f"  {record.login}" if record.login else ""
            console.out(f"{record.id[:8]}  {record.name}{suffix}")
        console.err(f"\n{len(records)} record(s).")
    return 0


def cmd_get(args: argparse.Namespace, console: Console) -> int:
    with open_vault(args, console) as vault:
        if not args.field:
            report_health(vault, console)

        matches = vault.search(args.query)
        if not matches:
            console.err(f"No record matches {args.query!r}.")
            return 1

        if len(matches) > 1 and args.field:
            console.err(f"{args.query!r} matches {len(matches)} records:")
            for record in matches:
                console.err(f"  {record.id[:8]}  {record.name}")
            console.err("Narrow the query, or use the id.")
            return 1

        if len(matches) > 1:
            for record in matches:
                console.out(format_record(record, show_password=args.show))
                console.out("")
            console.err(f"{len(matches)} record(s) matched.")
            return 0

        record = matches[0]
        if args.field:
            value = record.fields.get(args.field)
            if value is None:
                console.err(f"Record {record.name!r} has no {args.field}.")
                return 1
            # Bare value on stdout: this is the pipeable form.
            console.out(str(value))
            return 0

        console.out(format_record(record, show_password=args.show))
    return 0


def cmd_add(args: argparse.Namespace, console: Console) -> int:
    with open_vault(args, console) as vault:
        password = args.password
        if password is None:
            password = console.ask_secret("Password for this entry: ")
        try:
            record = vault.add(
                args.name,
                login=args.login or "",
                password=password or "",
                url=args.url or "",
                memo=args.memo or "",
                totp=args.totp or "",
            )
        except DuplicateNameError as exc:
            console.err(f"error: {exc}")
            return 1
        console.err(f"Added {record.name!r} ({record.id[:8]}).")
    return 0


def _resolve_one(vault: Vault, query: str, console: Console) -> ev.Record | None:
    try:
        return vault.get(query)
    except RecordNotFoundError:
        pass
    matches = vault.search(query)
    if not matches:
        console.err(f"No record matches {query!r}.")
        return None
    if len(matches) > 1:
        console.err(f"{query!r} matches {len(matches)} records:")
        for record in matches:
            console.err(f"  {record.id[:8]}  {record.name}")
        return None
    return matches[0]


def cmd_edit(args: argparse.Namespace, console: Console) -> int:
    with open_vault(args, console) as vault:
        record = _resolve_one(vault, args.query, console)
        if record is None:
            return 1

        changes: dict[str, Any] = {}
        for field in ("name", "login", "url", "memo", "totp"):
            value = getattr(args, field, None)
            if value is not None:
                changes[field] = value
        if args.password is not None:
            changes["password"] = args.password
        elif args.prompt_password:
            changes["password"] = console.ask_secret("New password: ")

        if not changes:
            console.err("Nothing to change. Pass a field such as --password.")
            return 1

        vault.update(record.id, **changes)
        console.err(f"Updated {record.name!r}: {', '.join(sorted(changes))}.")
    return 0


def cmd_delete(args: argparse.Namespace, console: Console) -> int:
    with open_vault(args, console) as vault:
        record = _resolve_one(vault, args.query, console)
        if record is None:
            return 1
        if not console.confirm(f"Delete {record.name!r}?"):
            console.err("Cancelled.")
            return 1
        vault.delete(record.id)
        console.err(
            f"Deleted {record.name!r}. Its history remains in the log, so it can "
            f"be recovered."
        )
    return 0


def cmd_export(args: argparse.Namespace, console: Console) -> int:
    if not args.plaintext:
        console.err(
            "error: refusing to export without --plaintext. The output contains "
            "every password in cleartext."
        )
        return 1

    with open_vault(args, console) as vault:
        document = vault.export_plaintext()
        text = json.dumps(document, ensure_ascii=False, indent=2)

        if args.output:
            target = Path(args.output)
            # Cleartext secrets: 0600 from creation, never briefly readable.
            handle = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(text + "\n")
            console.err(
                f"Wrote {len(document['records'])} record(s) to {target} "
                f"(mode 0600). This file is not encrypted; delete it when done."
            )
        else:
            console.out(text)
    return 0


def cmd_passwd(args: argparse.Namespace, console: Console) -> int:
    vault_dir = resolve_vault_dir(args)
    with open_vault(args, console) as vault:
        keyfile = vault.keyfile
        dek = vault.dek

        new_password = console.ask_secret("New master password: ")
        if not new_password:
            console.err("error: a master password is required")
            return 1
        if not console.secrets_from_stdin:
            if console.ask_secret("Repeat it: ") != new_password:
                console.err("error: the two entries did not match")
                return 1

        advice = passphrase_advice(new_password)
        if advice:
            console.err(f"note: {advice}")

        rotated = fmt.rotate_keyfile(vault_dir, keyfile, dek, new_password)

    # Reopen with the new password before archiving, so nothing is put out of
    # reach until the replacement is proven to work.
    verify = Vault.unlock(
        vault_dir, password=new_password, config_dir=resolve_config_dir(args)
    )
    verify.close()

    archived = fmt.archive_keyfile(vault_dir, keyfile.generation)
    console.out(f"Master password changed (generation {rotated.generation}).")
    console.err(f"Your printed recovery key still works; it was not changed.")
    console.err(
        f"The previous keyfile was moved to {archived.parent.name}/{archived.name}. "
        f"Until you delete it, someone who finds it can still use your OLD password, "
        f"so delete it once you are satisfied."
    )
    return 0


def cmd_calibrate(args: argparse.Namespace, console: Console) -> int:
    """Requirement 2.4. The numbers that matter must come from the real device."""
    params = crypto.KdfParams(
        time_cost=args.time_cost,
        memory_cost_kib=args.memory_cost,
        parallelism=args.parallelism,
    )
    check = crypto.check_memory_available(params)

    console.out(f"Argon2id parameters: {params}")
    console.out(
        f"  memory      {params.memory_human}\n"
        f"  time_cost   {params.time_cost}\n"
        f"  parallelism {params.parallelism}"
    )
    console.out(f"  memory check: {check.detail}")
    if not check.sufficient:
        console.err("error: not enough memory to run the key derivation here")
        return 1

    salt = crypto.generate_salt()
    timings = []
    for _ in range(max(1, args.runs)):
        started = time.perf_counter()
        crypto.derive_kek("calibration passphrase", salt, params)
        timings.append(time.perf_counter() - started)

    best = min(timings)
    console.out("")
    console.out(f"Unlock takes {best:.2f}s (best of {len(timings)}).")

    if best < 0.5:
        console.out(
            "That is fast. If every device that opens this vault is at least this "
            "quick, consider raising --time-cost to buy more resistance."
        )
    elif best > 3.0:
        console.out(
            "That is slow enough to be annoying on a device you unlock often. "
            "Lower --time-cost, or --memory-cost if RAM is tight."
        )
    else:
        console.out("That is a reasonable range for an interactive unlock.")

    console.err("")
    console.err(
        "Calibrate on the slowest device that will open this vault. Parameters are "
        "stored in the keyfile, so one setting governs every device, and a vault "
        "created with more memory than a board has will not open there at all."
    )
    return 0


def _run_import(
    args: argparse.Namespace,
    console: Console,
    records: list[Any],
    failures: list[tuple[str, str]],
    source: str,
) -> int:
    """Shared tail of both import commands: apply, close, reopen, verify."""
    from . import importer

    vault_dir = resolve_vault_dir(args)
    config_dir = resolve_config_dir(args)

    if args.dry_run:
        report = importer.apply_records(
            _DryRunVault(), records, source=source, dry_run=True, failures=failures
        )
        for line in report.lines():
            console.out(line)
        console.err("")
        console.err("Dry run: nothing was written.")
        if failures:
            console.err(
                "Some rows could not be decrypted. They will be skipped and listed "
                "again during the real import; the rest will still be imported."
            )
        return 0 if report.ok else 1

    password = console.ask_secret("Master password: ")
    vault = Vault.unlock(vault_dir, password=password, config_dir=config_dir)
    try:
        report = importer.apply_records(
            vault, records, source=source, failures=failures
        )
    finally:
        vault.close()

    # Requirement 5.6: verify against a vault reopened cold from disk, so what is
    # checked is what actually landed on the disk.
    console.err("Verifying against the source...")
    verifier = Vault.unlock(vault_dir, password=password, config_dir=config_dir)
    try:
        report.mismatches = importer.verify_against(verifier, records)
        report.verified = not report.mismatches
    finally:
        verifier.close()

    for line in report.lines():
        console.out(line)

    if not report.ok:
        console.err("")
        if report.mismatches:
            console.err(
                "error: verification FAILED. The new vault does not match the "
                "source. Your legacy data is untouched; do not delete it."
            )
        else:
            console.err(
                "error: some rows could not be imported. Your legacy data is "
                "untouched; do not delete it."
            )
        return 1

    console.err("")
    console.err("Verified: every field of every record matches the source.")
    console.err("")
    console.err(importer.ROTATION_ADVICE)
    return 0


class _DryRunVault:
    """Stands in for a Vault during a dry run so nothing can be written.

    Requirement 5.3 says a dry run writes nothing. Rather than trusting a boolean
    to be checked everywhere, this object simply has no write methods, so a code
    path that tried to mutate would fail loudly instead of quietly modifying a
    vault.
    """

    def all_records(self) -> list[Any]:
        return []


def cmd_import_legacy(args: argparse.Namespace, console: Console) -> int:
    from . import importer

    config_path, db_path = importer.find_legacy_paths(args.legacy_dir)
    console.err(f"Legacy config:   {config_path}")
    console.err(f"Legacy database: {db_path}")
    console.err("Both are opened read-only and will not be modified.")
    console.err("")

    key = importer.read_legacy_key(config_path)
    records, failures = importer.read_legacy_records(db_path, key)
    return _run_import(args, console, records, failures, str(db_path))


def cmd_import_json(args: argparse.Namespace, console: Console) -> int:
    from . import importer

    path = Path(args.path)
    console.err(f"Reading {path} (read-only).")
    console.err(
        "warning: this file holds every password in cleartext. Delete it once the "
        "import is verified."
    )
    console.err("")
    records, failures = importer.read_json_records(path)
    return _run_import(args, console, records, failures, str(path))


def cmd_where(args: argparse.Namespace, console: Console) -> int:
    vault_dir = resolve_vault_dir(args)
    config_dir = resolve_config_dir(args)
    console.out(f"vault      {vault_dir}")
    console.out(f"config     {config_dir}")
    console.out(f"device id  {config_dir / 'device_id'}")
    generations = fmt.find_keyfile_generations(vault_dir)
    console.out(f"keyfiles   {generations if generations else 'none'}")
    logs = fmt.find_logs(vault_dir / "log")
    console.out(f"logs       {[p.name for p in logs] if logs else 'none'}")
    return 0


# ------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pipw",
        description="A TUI password vault for Raspberry Pi hardware.",
    )
    parser.add_argument("--version", action="version", version=f"pipassword {__version__}")
    parser.add_argument("--vault", help="path to the vault directory")
    parser.add_argument("--config-dir", help="path to the config directory")
    parser.add_argument(
        "--password-stdin",
        dest="password_stdin",
        action="store_true",
        help="read passwords from stdin instead of prompting (for scripting)",
    )
    parser.add_argument(
        "-y", "--yes", action="store_true", help="assume yes for confirmations"
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_init = sub.add_parser("init", help="create a new vault")
    p_init.add_argument("--time-cost", type=int, default=3)
    p_init.add_argument(
        "--memory-cost", type=int, default=65536, help="Argon2 memory in KiB"
    )
    p_init.add_argument("--parallelism", type=int, default=4)
    p_init.set_defaults(func=cmd_init)

    p_list = sub.add_parser("list", help="list every record")
    p_list.add_argument("--recovery-key", action="store_true")
    p_list.set_defaults(func=cmd_list)

    p_get = sub.add_parser("get", help="show a record")
    p_get.add_argument("query")
    p_get.add_argument(
        "--field",
        choices=ev.FIELDS,
        help="print just this field, unadorned, for piping",
    )
    p_get.add_argument("--show", action="store_true", help="reveal the password")
    p_get.add_argument("--recovery-key", action="store_true")
    p_get.set_defaults(func=cmd_get)

    p_add = sub.add_parser("add", help="add a record")
    p_add.add_argument("name")
    p_add.add_argument("--login")
    p_add.add_argument("--password", help="omit to be prompted without echo")
    p_add.add_argument("--url")
    p_add.add_argument("--memo")
    p_add.add_argument("--totp")
    p_add.set_defaults(func=cmd_add)

    p_edit = sub.add_parser("edit", help="change fields on a record")
    p_edit.add_argument("query")
    p_edit.add_argument("--name")
    p_edit.add_argument("--login")
    p_edit.add_argument("--password")
    p_edit.add_argument(
        "--prompt-password", action="store_true", help="prompt without echo"
    )
    p_edit.add_argument("--url")
    p_edit.add_argument("--memo")
    p_edit.add_argument("--totp")
    p_edit.set_defaults(func=cmd_edit)

    p_delete = sub.add_parser("delete", help="delete a record")
    p_delete.add_argument("query")
    p_delete.set_defaults(func=cmd_delete)

    p_export = sub.add_parser("export", help="export every record as JSON")
    p_export.add_argument(
        "--plaintext", action="store_true", help="required; output is unencrypted"
    )
    p_export.add_argument("--output", help="write here at mode 0600")
    p_export.add_argument("--recovery-key", action="store_true")
    p_export.set_defaults(func=cmd_export)

    p_passwd = sub.add_parser("passwd", help="change the master password")
    p_passwd.add_argument("--recovery-key", action="store_true")
    p_passwd.set_defaults(func=cmd_passwd)

    p_cal = sub.add_parser("calibrate", help="measure unlock time on this device")
    p_cal.add_argument("--time-cost", type=int, default=3)
    p_cal.add_argument("--memory-cost", type=int, default=65536)
    p_cal.add_argument("--parallelism", type=int, default=4)
    p_cal.add_argument("--runs", type=int, default=3)
    p_cal.set_defaults(func=cmd_calibrate)

    p_imp = sub.add_parser(
        "import-legacy",
        help="import a minipassword vault (read-only; the original is untouched)",
    )
    p_imp.add_argument(
        "--legacy-dir",
        default="~/.minipassword",
        help="legacy data directory (default: ~/.minipassword)",
    )
    p_imp.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be imported and write nothing",
    )
    p_imp.set_defaults(func=cmd_import_legacy)

    p_json = sub.add_parser(
        "import-json", help="import the legacy plaintext JSON export format"
    )
    p_json.add_argument("path")
    p_json.add_argument("--dry-run", action="store_true")
    p_json.set_defaults(func=cmd_import_json)

    p_where = sub.add_parser("where", help="show vault and config paths")
    p_where.set_defaults(func=cmd_where)

    return parser


def run(
    argv: Sequence[str] | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if not getattr(args, "command", None):
        parser.print_help(stderr or sys.stderr)
        return 0

    console = Console(
        stdin=stdin or sys.stdin,
        stdout=stdout or sys.stdout,
        stderr=stderr or sys.stderr,
        secrets_from_stdin=bool(getattr(args, "password_stdin", False)),
        assume_yes=bool(getattr(args, "yes", False)),
    )

    try:
        return int(args.func(args, console))
    except _ImporterError as exc:
        console.err(f"error: {exc}")
        return 1
    except crypto.AuthenticationError:
        console.err(
            "error: could not unlock the vault. Wrong password, or the keyfile was "
            "modified."
        )
        return 1
    except crypto.InsufficientMemoryError as exc:
        console.err(f"error: {exc}")
        return 1
    except (VaultError, fmt.FormatError, crypto.CryptoError, ev.EventError) as exc:
        console.err(f"error: {exc}")
        return 1
    except KeyboardInterrupt:
        console.err("\ninterrupted")
        return 130
    except EOFError:
        console.err("error: unexpected end of input")
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    return run(argv)
