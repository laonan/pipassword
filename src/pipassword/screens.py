"""Pure screen rendering for the TUI.

Separated from :mod:`pipassword.tui` so the layout can be tested at exactly
50x15 without a terminal. Every function here takes data and dimensions and
returns a :class:`Screen`; none of them touch prompt_toolkit, the vault, or the
clock.

The 50x15 target is not arbitrary. The Beepy's 400x240 Sharp Memory LCD with
fbterm's 8x16 font gives exactly 50 columns by 15 rows.

Row budget at 15 rows::

    row  1        query and match counter
    rows 2..13    entry list (12 rows)
    row  14       status and key hints
    row  15       LEFT EMPTY for the fcitx candidate bar

Row 15 is reserved because ``fcitx-fbterm`` draws its Pinyin candidate bar over
the bottom of the terminal. Anything important there is covered the moment you
start composing Chinese.

This drops the decorative blank separator rows from the design mock. On a
15-row screen two blank lines cost two entries, which is a sixth of the visible
list, and the layout reads fine without them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .compat import SLOTS
from typing import Sequence

from .display import display_width, fit, pad, truncate, wrap
from .events import Record

__all__ = [
    "Screen",
    "RESERVED_BOTTOM_ROWS",
    "MASK",
    "SELECTED_MARKER",
    "UNSELECTED_MARKER",
    "render_list",
    "render_detail",
    "render_message",
    "render_form",
    "list_capacity",
    "entry_summary",
]

RESERVED_BOTTOM_ROWS = 1
"""Rows left blank at the bottom for the fcitx candidate bar (requirement 4.3)."""

MASK = "••••••••"
"""Password placeholder.

U+2022 is one column wide and present in the Beepy's console fonts. A fixed
width regardless of the real password length avoids leaking it.
"""

SELECTED_MARKER = "\u00bb "
UNSELECTED_MARKER = "  "
"""Selection is shown by reverse video *and* a marker.

Requirement 4.2: the Beepy console runs ``TERM=xterm-mono``, so nothing may
depend on colour. The marker means the selection is still visible even if
reverse video is unavailable or hard to see on a reflective LCD.
"""


@dataclass(**SLOTS)
class Screen:
    """Rendered lines plus which of them should be shown in reverse video.

    ``lines`` always has exactly ``height`` entries, each exactly ``width``
    display columns wide, so the caller never has to think about padding.
    """

    lines: list[str] = field(default_factory=list)
    reverse_rows: set[int] = field(default_factory=set)
    width: int = 0
    height: int = 0

    def text(self) -> str:
        return "\n".join(self.lines)

    def row(self, index: int) -> str:
        return self.lines[index]


def _blank(width: int) -> str:
    return " " * width


def _finish(
    lines: list[str], width: int, height: int, reverse: set[int]
) -> Screen:
    """Pad or clip to exactly ``height`` rows of exactly ``width`` columns."""
    out = [pad(truncate(line, width), width) for line in lines[:height]]
    while len(out) < height:
        out.append(_blank(width))
    return Screen(lines=out, reverse_rows=reverse, width=width, height=height)


def list_capacity(height: int) -> int:
    """How many entries fit, given the query, status and reserved rows."""
    return max(1, height - 2 - RESERVED_BOTTOM_ROWS)


def entry_summary(record: Record, width: int) -> str:
    """One entry as a single line: name, then login or url if there is room.

    The name gets priority because that is what you searched for. The secondary
    field is dropped entirely rather than squeezed to a useless stub.
    """
    name = record.name or "(unnamed)"
    secondary = record.login or record.url or ""
    if not secondary:
        return truncate(name, width)

    separator = " \u00b7 "
    name_width = display_width(name)
    needed = name_width + display_width(separator) + 4
    if needed > width:
        return truncate(name, width)

    room = width - name_width - display_width(separator)
    return name + separator + truncate(secondary, room)


def render_list(
    records: Sequence[Record],
    *,
    query: str = "",
    selected: int = 0,
    scroll: int = 0,
    width: int = 50,
    height: int = 15,
    status: str | None = None,
    total: int | None = None,
) -> Screen:
    """The entry list: query line, entries, status line, reserved row."""
    lines: list[str] = []
    reverse: set[int] = set()

    shown = len(records)
    counter = f"{selected + 1}/{shown}" if shown else "0/0"
    if total is not None and total != shown:
        counter = f"{shown}/{total}"
    counter_width = display_width(counter)

    prompt = "> " + query
    lines.append(
        pad(truncate(prompt, width - counter_width - 1), width - counter_width)
        + counter
    )

    capacity = list_capacity(height)
    visible = records[scroll : scroll + capacity]

    for offset, record in enumerate(visible):
        index = scroll + offset
        marker = SELECTED_MARKER if index == selected else UNSELECTED_MARKER
        body = entry_summary(record, width - display_width(marker))
        lines.append(marker + body)
        if index == selected:
            reverse.add(len(lines) - 1)

    if not visible:
        message = "no matches" if query else "vault is empty  (a to add)"
        lines.append("  " + message)

    while len(lines) < height - 1 - RESERVED_BOTTOM_ROWS:
        lines.append("")

    lines.append(status if status is not None else _list_hints(width))
    for _ in range(RESERVED_BOTTOM_ROWS):
        lines.append("")

    return _finish(lines, width, height, reverse)


def _list_hints(width: int) -> str:
    """Key hints, shortened as the terminal narrows."""
    full = "\u21b5 view  ^a add  ^g gen  ^r reveal  esc clear  ^q quit"
    medium = "\u21b5 view  ^a add  ^g gen  ^q quit"
    short = "\u21b5 view  ^q quit"
    for candidate in (full, medium, short):
        if display_width(candidate) <= width:
            return candidate
    return truncate(short, width)


def render_detail(
    record: Record,
    *,
    revealed: bool = False,
    totp_code: str | None = None,
    totp_seconds: int | None = None,
    totp_blocked: str | None = None,
    scroll: int = 0,
    width: int = 50,
    height: int = 15,
    status: str | None = None,
) -> Screen:
    """One record in full. Single column, no borders: rows are too scarce."""
    body: list[str] = []

    label_width = 6
    def row(label: str, value: str) -> None:
        body.append(fit(label, label_width) + truncate(value, width - label_width))

    if record.login:
        row("user", record.login)
    row("pass", record.password if revealed else MASK if record.password else "(none)")

    if record.totp:
        if totp_blocked:
            row("totp", "unavailable")
        elif totp_code:
            suffix = f"  ({totp_seconds}s)" if totp_seconds is not None else ""
            row("totp", f"{totp_code}{suffix}")
        else:
            row("totp", "(set)")

    if record.url:
        row("url", record.url)
    if record.legacy_id is not None:
        row("old id", str(record.legacy_id))

    if record.memo:
        body.append("")
        body.append("memo")
        body.extend(wrap(record.memo, width))

    if totp_blocked:
        body.append("")
        body.extend(wrap(totp_blocked, width))

    usable = height - 2 - RESERVED_BOTTOM_ROWS
    window = body[scroll : scroll + usable]

    lines = [truncate(record.name or "(unnamed)", width)]
    lines.extend(window)
    while len(lines) < height - 1 - RESERVED_BOTTOM_ROWS:
        lines.append("")

    more = len(body) > scroll + usable
    if status is None:
        status = _detail_hints(width, revealed=revealed, more=more)
    lines.append(status)
    for _ in range(RESERVED_BOTTOM_ROWS):
        lines.append("")

    return _finish(lines, width, height, {0})


def _detail_hints(width: int, *, revealed: bool, more: bool) -> str:
    reveal = "p hide" if revealed else "p reveal"
    parts = [reveal, "e edit", "d delete", "esc back"]
    if more:
        parts.insert(0, "\u2193 more")
    full = "  ".join(parts)
    if display_width(full) <= width:
        return full
    return truncate(f"{reveal}  e edit  esc back", width)


def render_message(
    title: str,
    body: str,
    *,
    width: int = 50,
    height: int = 15,
    status: str = "any key to continue",
) -> Screen:
    """A full-screen notice, used for warnings and the change summary."""
    lines = [truncate(title, width), ""]
    lines.extend(wrap(body, width)[: height - 4 - RESERVED_BOTTOM_ROWS])
    while len(lines) < height - 1 - RESERVED_BOTTOM_ROWS:
        lines.append("")
    lines.append(truncate(status, width))
    for _ in range(RESERVED_BOTTOM_ROWS):
        lines.append("")
    return _finish(lines, width, height, {0})


def render_form(
    title: str,
    fields: Sequence[tuple[str, str]],
    *,
    active: int = 0,
    secret_rows: Sequence[int] = (),
    width: int = 50,
    height: int = 15,
    status: str | None = None,
) -> Screen:
    """An add/edit form: one label and value per row.

    Secret rows render masked, so a password being typed never appears on screen
    or in scrollback.
    """
    lines = [truncate(title, width), ""]
    reverse: set[int] = {0}

    label_width = 9
    for index, (label, value) in enumerate(fields):
        shown = MASK if index in set(secret_rows) and value else value
        cursor = "_" if index == active else ""
        text = fit(label, label_width) + truncate(
            shown + cursor, width - label_width
        )
        lines.append(text)
        if index == active:
            reverse.add(len(lines) - 1)

    while len(lines) < height - 1 - RESERVED_BOTTOM_ROWS:
        lines.append("")
    lines.append(
        status
        if status is not None
        else truncate("\u21b5 next  ^s save  esc cancel", width)
    )
    for _ in range(RESERVED_BOTTOM_ROWS):
        lines.append("")
    return _finish(lines, width, height, reverse)
