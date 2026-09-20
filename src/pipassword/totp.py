"""TOTP codes, with a clock gate.

TOTP is fully offline by construction: RFC 6238 is an HMAC over a counter derived
from the current time, and it never touches the network. So the "must work fully
disconnected" requirement is satisfied by the algorithm itself.

The fragile input is the **clock**, not connectivity, and on this hardware that is a
real problem:

* No Raspberry Pi before the Pi 5 has a battery-backed real-time clock. A board that
  has been powered off boots with ``fake-hwclock`` restoring the timestamp saved at
  its last shutdown. After a week off, every code would be wrong.
* The Beepy's RP2040 does expose RTC registers, and its keyboard driver pushes NTP
  time into them when a network is available. But the firmware documents that RTC
  state is lost when the power switch is turned off or the device enters deep sleep,
  and deep sleep is the default auto-off path. So it survives a normal Pi-off but
  not a real power-down.

Hence the split in requirement 7.1 and 7.6: **secrets are always stored**, because
the seed backup is valuable regardless and is inert data; **codes are only shown
when the clock can be trusted**. Showing a silently wrong code is worse than showing
none, because a wrong code looks like the service rejecting you.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse

from . import events as ev

__all__ = [
    "TotpError",
    "TotpSecret",
    "TotpCode",
    "parse_secret",
    "generate",
    "DEFAULT_PERIOD",
    "DEFAULT_DIGITS",
]

DEFAULT_PERIOD = 30
DEFAULT_DIGITS = 6

_BASE32 = re.compile(r"^[A-Z2-7]+=*$")


class TotpError(Exception):
    """A TOTP secret could not be parsed or used."""


@dataclass(frozen=True, slots=True)
class TotpSecret:
    secret: str
    digits: int = DEFAULT_DIGITS
    period: int = DEFAULT_PERIOD
    algorithm: str = "SHA1"
    label: str = ""
    issuer: str = ""


@dataclass(frozen=True, slots=True)
class TotpCode:
    """Either a code, or an explanation of why there is not one."""

    code: str | None
    seconds_remaining: int = 0
    period: int = DEFAULT_PERIOD
    blocked_reason: str | None = None

    @property
    def available(self) -> bool:
        return self.code is not None


def parse_secret(value: str) -> TotpSecret:
    """Accept either a bare Base32 secret or a full ``otpauth://`` URI.

    Both are pasted around in practice: authenticator apps export URIs, while
    websites often print the bare secret in groups of four.
    """
    text = (value or "").strip()
    if not text:
        raise TotpError("no TOTP secret")

    if text.lower().startswith("otpauth://"):
        return _parse_uri(text)

    cleaned = re.sub(r"[\s-]", "", text).upper()
    if not _BASE32.match(cleaned):
        raise TotpError(
            "not a valid Base32 TOTP secret. Expected letters A-Z and digits 2-7, "
            "or a full otpauth:// URI."
        )
    return TotpSecret(secret=cleaned)


def _parse_uri(uri: str) -> TotpSecret:
    parsed = urlparse(uri)
    if parsed.netloc.lower() != "totp":
        raise TotpError(
            f"only otpauth://totp/ URIs are supported, not {parsed.netloc!r}. "
            f"HOTP is counter-based and cannot be shown as a timed code."
        )

    query = parse_qs(parsed.query)
    secret = (query.get("secret") or [""])[0]
    cleaned = re.sub(r"[\s-]", "", secret).upper()
    if not cleaned or not _BASE32.match(cleaned):
        raise TotpError("otpauth URI has no valid secret parameter")

    label = unquote(parsed.path.lstrip("/"))
    issuer = (query.get("issuer") or [""])[0]
    if not issuer and ":" in label:
        issuer = label.split(":", 1)[0]

    try:
        digits = int((query.get("digits") or [DEFAULT_DIGITS])[0])
        period = int((query.get("period") or [DEFAULT_PERIOD])[0])
    except ValueError as exc:
        raise TotpError(f"otpauth URI has invalid digits or period: {exc}") from exc

    if digits not in (6, 7, 8):
        raise TotpError(f"unsupported digit count {digits}")
    if period <= 0:
        raise TotpError(f"unsupported period {period}")

    return TotpSecret(
        secret=cleaned,
        digits=digits,
        period=period,
        algorithm=(query.get("algorithm") or ["SHA1"])[0].upper(),
        label=label,
        issuer=issuer,
    )


def generate(
    value: str,
    *,
    last_known_good_time: int = 0,
    now_micros: int | None = None,
    at_micros: int | None = None,
) -> TotpCode:
    """Produce a code, or refuse and say why.

    ``last_known_good_time`` is the highest timestamp the vault has ever seen. If
    the system clock is earlier than that, the clock went backwards, which on a Pi
    means it was powered off and ``fake-hwclock`` restored a stale time.

    ``at_micros`` overrides the clock entirely (requirement 7.5). That is the escape
    hatch for a disconnected Beepy: read the real time off a watch or phone, pass it
    in, and get a usable code. Supplying it bypasses the gate, because the user has
    asserted the time explicitly.
    """
    secret = parse_secret(value)

    if at_micros is not None:
        timestamp = at_micros
    else:
        timestamp = ev.now_micros() if now_micros is None else now_micros
        if timestamp < last_known_good_time:
            behind_s = (last_known_good_time - timestamp) / 1_000_000
            return TotpCode(
                code=None,
                period=secret.period,
                blocked_reason=(
                    f"This device's clock reads about {_humanise(behind_s)} earlier "
                    f"than changes already in the vault, so it cannot be trusted and "
                    f"any code shown would be wrong. Raspberry Pi boards before the "
                    f"Pi 5 have no battery-backed clock. Set the time (for example "
                    f"'sudo date -s \"...\"' or connect to a network), or pass the "
                    f"current time explicitly with --at."
                ),
            )

    try:
        import pyotp
    except ImportError:  # pragma: no cover - a declared dependency
        return TotpCode(
            code=None,
            period=secret.period,
            blocked_reason="pyotp is not installed, so codes cannot be generated",
        )

    if secret.algorithm not in ("SHA1", "SHA256", "SHA512"):
        raise TotpError(f"unsupported TOTP algorithm {secret.algorithm}")

    seconds = timestamp / 1_000_000
    try:
        totp = pyotp.TOTP(
            secret.secret,
            digits=secret.digits,
            interval=secret.period,
            digest=_digest_for(secret.algorithm),
        )
        code = totp.at(seconds)
    except Exception as exc:
        raise TotpError(f"could not generate a code: {exc}") from exc

    remaining = secret.period - int(seconds) % secret.period
    return TotpCode(
        code=code,
        seconds_remaining=remaining,
        period=secret.period,
    )


def _digest_for(algorithm: str):
    import hashlib

    return {
        "SHA1": hashlib.sha1,
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512,
    }[algorithm]


def _humanise(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.0f} seconds"
    if seconds < 5400:
        return f"{seconds / 60:.0f} minutes"
    if seconds < 172800:
        return f"{seconds / 3600:.0f} hours"
    return f"{seconds / 86400:.1f} days"
