"""Pinyin search index, built at write time.

The problem this solves is specific to the Beepy. Entry names in this vault are
often Chinese, and locating one would otherwise mean switching input method with
``Ctrl+Space`` under fcitx, composing the characters, and only then searching. That
is a lot of ceremony to find a password.

With an index, typing ``qyyx`` or ``qiyeyouxiang`` finds ``企业邮箱`` from the
default Latin keyboard.

Two design choices follow from requirement 4.14:

* The index is computed when a record is **written** and stored inside the
  encrypted event. Reading a vault therefore never imports ``pypinyin``, whose data
  tables are several megabytes -- a real cost on a 512 MB Pi Zero 2 W.
* Because it lives inside the AEAD frame, the index inherits the vault's
  encryption. A plaintext search index sitting next to an encrypted vault would
  leak exactly the entry names the vault is meant to protect.

``pypinyin`` is imported lazily and its absence is tolerated: a vault written
without it simply has no index, and substring search over the original text still
works.
"""

from __future__ import annotations

import re
from typing import Mapping

__all__ = [
    "INDEXED_FIELDS",
    "contains_cjk",
    "pinyin_variants",
    "build_index",
    "pypinyin_available",
]

INDEXED_FIELDS = ("name", "memo")
"""Fields worth indexing.

``name`` because that is what you search for. ``memo`` because that is where notes
in Chinese end up. ``url`` and ``login`` are effectively always Latin, and
``password`` must never be searchable.
"""

_CJK = re.compile(
    r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]"
)

_NON_WORD = re.compile(r"[^a-z0-9]+")


def contains_cjk(text: str) -> bool:
    return bool(_CJK.search(text or ""))


def pypinyin_available() -> bool:
    try:
        import pypinyin  # noqa: F401
    except ImportError:
        return False
    return True


def pinyin_variants(text: str) -> list[str]:
    """Return searchable Latin forms of CJK text, longest-useful first.

    Produces three things, because people search in all three ways:

    * initials, so ``企业邮箱`` gives ``qyyx``
    * full syllables joined, giving ``qiyeyouxiang``
    * syllables space-separated, giving ``qi ye you xiang``, which also makes
      partial matches like ``youxiang`` work after normalisation

    Returns an empty list when the text has no CJK, or when ``pypinyin`` is not
    installed.
    """
    if not contains_cjk(text):
        return []
    try:
        from pypinyin import Style, lazy_pinyin
    except ImportError:
        return []

    try:
        syllables = [s for s in lazy_pinyin(text, style=Style.NORMAL) if s]
        initials = [
            s for s in lazy_pinyin(text, style=Style.FIRST_LETTER, errors="ignore") if s
        ]
    except Exception:  # pragma: no cover - defensive; pypinyin is pure data
        return []

    joined_initials = _NON_WORD.sub("", "".join(initials).lower())
    joined_full = _NON_WORD.sub("", "".join(syllables).lower())
    spaced = " ".join(_NON_WORD.sub("", s.lower()) for s in syllables).strip()

    variants = []
    for candidate in (joined_initials, joined_full, spaced):
        if candidate and candidate not in variants:
            variants.append(candidate)
    return variants


def build_index(fields: Mapping[str, object]) -> dict[str, str]:
    """Build the ``p`` map for an event from the fields being written.

    Only fields containing CJK get an entry, so an all-Latin vault carries no index
    overhead at all.
    """
    index: dict[str, str] = {}
    for key in INDEXED_FIELDS:
        value = fields.get(key)
        if not isinstance(value, str) or not value:
            continue
        variants = pinyin_variants(value)
        if variants:
            index[key] = " ".join(variants)
    return index
