"""Width-aware text helpers for a 50-column monochrome console.

Every function here measures text in **display columns**, never in characters.
That distinction is the whole reason this module exists: CJK characters occupy two
columns each, so ``len()`` understates their footprint by a factor of two. The
legacy project truncated menu entries with ``item[:40]``, which for a Chinese entry
name produced 80 display columns on a 50-column screen, wrapping the line and
corrupting the menu.

``wcwidth`` is used rather than a hand-rolled range check because it implements the
Unicode East Asian Width property properly, including combining marks (width 0) and
control characters (width -1).
"""

from __future__ import annotations

from wcwidth import wcswidth, wcwidth

__all__ = [
    "ELLIPSIS",
    "display_width",
    "truncate",
    "pad",
    "fit",
    "wrap",
    "columns",
]

ELLIPSIS = "…"
"""Truncation marker, one display column wide.

U+2026 is present in Terminus and WenQuanYi Bitmap Song, the fonts the Beepy
fbterm setup uses. If a console font ever lacks it, changing this to ``"~"`` is the
only edit required.
"""


def display_width(text: str) -> int:
    """Width of ``text`` in terminal columns.

    ``wcswidth`` returns -1 if the string contains a control character; in that
    case the string is measured character by character with unprintables counted as
    zero, so a stray control byte in a memo degrades the layout rather than
    breaking it.
    """
    width = wcswidth(text)
    if width >= 0:
        return width
    return sum(max(0, wcwidth(char)) for char in text)


def truncate(text: str, width: int, *, marker: str = ELLIPSIS) -> str:
    """Shorten ``text`` so it occupies at most ``width`` columns.

    Appends ``marker`` when something was removed. Never splits a double-width
    character in half, and never returns a string wider than ``width``.
    """
    if width <= 0:
        return ""
    if display_width(text) <= width:
        return text

    marker_width = display_width(marker)
    if width <= marker_width:
        # No room for content plus a marker; emit as much marker as fits.
        return marker[:width] if marker_width == len(marker) else ""

    budget = width - marker_width
    out: list[str] = []
    used = 0
    for char in text:
        char_width = max(0, wcwidth(char))
        if used + char_width > budget:
            break
        out.append(char)
        used += char_width
    return "".join(out) + marker


def pad(text: str, width: int, *, align: str = "left") -> str:
    """Pad ``text`` with spaces to exactly ``width`` columns.

    Does not truncate; use :func:`fit` when the input may be too long.
    """
    deficit = width - display_width(text)
    if deficit <= 0:
        return text
    if align == "right":
        return " " * deficit + text
    if align == "center":
        left = deficit // 2
        return " " * left + text + " " * (deficit - left)
    return text + " " * deficit


def fit(text: str, width: int, *, align: str = "left", marker: str = ELLIPSIS) -> str:
    """Truncate then pad, so the result is exactly ``width`` columns."""
    return pad(truncate(text, width, marker=marker), width, align=align)


def wrap(text: str, width: int) -> list[str]:
    """Wrap on display width, breaking long runs without spaces.

    Handles CJK, which has no spaces to break on, by falling back to a hard break
    at the column limit.
    """
    if width <= 0:
        return []

    lines: list[str] = []
    for paragraph in (text or "").splitlines() or [""]:
        if not paragraph:
            lines.append("")
            continue

        current: list[str] = []
        used = 0
        for word in _tokenise(paragraph, width):
            word_width = display_width(word)
            if current and used + word_width > width:
                lines.append("".join(current).rstrip())
                current, used = [], 0
            if word == " " and not current:
                continue  # no leading space after a break
            current.append(word)
            used += word_width
        if current:
            lines.append("".join(current).rstrip())
    return lines


def _tokenise(text: str, width: int) -> list[str]:
    """Split into words, spaces, and hard-broken chunks of over-long words."""
    tokens: list[str] = []
    buffer: list[str] = []

    def flush() -> None:
        if not buffer:
            return
        word = "".join(buffer)
        buffer.clear()
        while display_width(word) > width:
            head, used = [], 0
            for char in word:
                char_width = max(0, wcwidth(char))
                if used + char_width > width:
                    break
                head.append(char)
                used += char_width
            if not head:  # a single char wider than the whole line
                head = [word[0]]
            tokens.append("".join(head))
            word = word[len(head) :]
        if word:
            tokens.append(word)

    for char in text:
        if char == " ":
            flush()
            tokens.append(" ")
        elif max(0, wcwidth(char)) == 2:
            # CJK:每个字都可以单独换行, so treat each as its own token.
            flush()
            tokens.append(char)
        else:
            buffer.append(char)
    flush()
    return tokens


def columns(parts: list[tuple[str, int]], width: int, *, gap: str = " ") -> str:
    """Lay out ``(text, column_width)`` pairs, with the last part absorbing slack.

    A column width of ``0`` means "take whatever is left", which is how the entry
    list gives the name as much room as possible while keeping the counter aligned
    on the right.
    """
    gap_total = display_width(gap) * max(0, len(parts) - 1)
    fixed = sum(w for _, w in parts if w > 0)
    flexible = [index for index, (_, w) in enumerate(parts) if w == 0]

    remaining = max(0, width - fixed - gap_total)
    share = remaining // len(flexible) if flexible else 0

    rendered: list[str] = []
    for index, (text, column_width) in enumerate(parts):
        target = column_width if column_width > 0 else share
        rendered.append(fit(text, target))
    return gap.join(rendered)
