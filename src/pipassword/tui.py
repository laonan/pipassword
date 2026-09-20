"""Full-screen terminal interface.

Wires the pure renderers in :mod:`pipassword.screens` to prompt_toolkit. All the
layout decisions live there; this module handles state, key bindings, and repaint
policy.

Three constraints from the target hardware shape this file:

**Repaint on input only** (requirement 4.4). There is no periodic refresh, no
animation, and no clock widget. Two reasons compound: the Sharp Memory LCD is
driven over SPI so full repaints are costly, and a repaint while ``fcitx`` is
showing Pinyin preedit erases the candidate bar mid-composition. The one
exception is a single-shot invalidate for the reveal timeout, explained at
:meth:`Tui._schedule_remask`.

**No colour** (requirement 4.2). ``TERM=xterm-mono``. Selection is reverse video
plus a ``»`` marker.

**Small keys, no chords where it matters** (requirements 4.6, 4.7). The BBQ20 has
no arrow keys and no function keys; its trackpad emits arrows. ``Ctrl+Space`` is
never bound because fcitx owns it for switching input method.

On the keymap conflict in the design: section 6.2 asked for both "any printable
goes to incremental search" and "j/k moves the selection". Those cannot both hold
in one view. Search wins in the list, because finding an entry is the dominant
action and every character typed should narrow it. Navigation therefore uses the
trackpad arrows plus ``Ctrl+N``/``Ctrl+P``, and the single-letter commands live in
the detail view where there is no query to type into.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Callable

from prompt_toolkit.application import Application
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.output import ColorDepth
from prompt_toolkit.styles import Style

from . import screens
from .display import truncate
from .events import Record
from .vault import Vault

__all__ = ["Tui", "run_tui", "REVEAL_SECONDS", "WIDE_THRESHOLD"]

REVEAL_SECONDS = 15
"""How long a password stays visible (requirement 4.10)."""

WIDE_THRESHOLD = 80
"""At or above this width, use the two-pane layout (requirement 4.9)."""

_STYLE = Style.from_dict(
    {
        # Monochrome only: reverse video carries selection, nothing else.
        "screen": "",
        "screen.reverse": "reverse",
    }
)

MODE_LIST = "list"
MODE_DETAIL = "detail"
MODE_MESSAGE = "message"
MODE_FORM = "form"


@dataclass
class Tui:
    """TUI state and behaviour, separable from the prompt_toolkit Application.

    Constructed with a vault and driven either by :meth:`run` or, in tests, by
    calling the ``on_*`` handlers directly and inspecting :meth:`render`.
    """

    vault: Vault
    width: int = 50
    height: int = 15
    reveal_seconds: int = REVEAL_SECONDS
    now: Callable[[], float] = field(default=None)  # type: ignore[assignment]

    mode: str = MODE_LIST
    query: str = ""
    selected: int = 0
    scroll: int = 0
    detail_scroll: int = 0
    revealed_at: float | None = None
    current_id: str | None = None
    message_title: str = ""
    message_body: str = ""
    form_title: str = ""
    form_target: str | None = None
    form_active: int = 0
    status_override: str | None = None
    should_exit: bool = False

    def __post_init__(self) -> None:
        if self.now is None:
            import time

            self.now = time.monotonic
        self._results: list[Record] = []
        self._form: list[list[str]] = []
        self._refresh_results()
        self._show_startup_notices()

    # ------------------------------------------------------------------ state

    def _refresh_results(self) -> None:
        self._results = self.vault.search(self.query)
        if self.selected >= len(self._results):
            self.selected = max(0, len(self._results) - 1)
        self._clamp_scroll()

    def _clamp_scroll(self) -> None:
        capacity = screens.list_capacity(self.height)
        if self.selected < self.scroll:
            self.scroll = self.selected
        elif self.selected >= self.scroll + capacity:
            self.scroll = self.selected - capacity + 1
        self.scroll = max(0, min(self.scroll, max(0, len(self._results) - 1)))

    @property
    def results(self) -> list[Record]:
        return self._results

    @property
    def current(self) -> Record | None:
        if self.mode == MODE_DETAIL and self.current_id:
            try:
                return self.vault.get(self.current_id)
            except Exception:
                return None
        if 0 <= self.selected < len(self._results):
            return self._results[self.selected]
        return None

    @property
    def revealed(self) -> bool:
        """Whether the password is currently visible.

        Checked on every render rather than tracked by a timer, so the reveal
        expires correctly even if no repaint happened in between.
        """
        if self.revealed_at is None:
            return False
        if self.now() - self.revealed_at >= self.reveal_seconds:
            self.revealed_at = None
            return False
        return True

    def _show_startup_notices(self) -> None:
        """Surface anomalies, clock skew, and what other devices changed.

        Shown as a screen rather than a log line because on 15 rows there is
        nowhere else for it to go, and because these are things the user should
        actually read.
        """
        notices: list[str] = []

        if self.vault.clock_is_behind:
            notices.append(
                "This device's clock is behind changes already in the vault. "
                "Edits are safe, but TOTP codes will be refused until the time "
                "is corrected."
            )
        if self.vault.conflicts:
            notices.append(
                f"{len(self.vault.conflicts)} Syncthing conflict file(s) found. "
                f"This should be impossible; two devices may share a device id."
            )
        for anomaly in self.vault.anomalies[:3]:
            notices.append(anomaly)

        summary = self.vault.changes_since_last_open()
        if not summary.is_empty:
            parts = []
            if summary.added:
                parts.append(f"{len(summary.added)} added")
            if summary.updated:
                parts.append(f"{len(summary.updated)} updated")
            if summary.deleted:
                parts.append(f"{len(summary.deleted)} deleted")
            names = ", ".join(r.name for r in (summary.added + summary.updated)[:3])
            notices.append(
                f"Since you last opened this vault: {', '.join(parts)}."
                + (f" {names}" if names else "")
            )

        if notices:
            self.mode = MODE_MESSAGE
            self.message_title = "Notices"
            self.message_body = "  ".join(notices)

    # ----------------------------------------------------------------- render

    @property
    def wide(self) -> bool:
        return self.width >= WIDE_THRESHOLD

    def render(self) -> screens.Screen:
        if self.mode == MODE_MESSAGE:
            return screens.render_message(
                self.message_title,
                self.message_body,
                width=self.width,
                height=self.height,
            )
        if self.mode == MODE_FORM:
            return screens.render_form(
                self.form_title,
                [(label, value) for label, _key, value in self._form],
                active=self.form_active,
                secret_rows=self._secret_rows(),
                width=self.width,
                height=self.height,
                status=self.status_override,
            )
        if self.mode == MODE_DETAIL:
            record = self.current
            if record is None:
                self.mode = MODE_LIST
                return self.render()
            return self._render_detail(record)
        if self.wide:
            return self._render_wide()
        return screens.render_list(
            self._results,
            query=self.query,
            selected=self.selected,
            scroll=self.scroll,
            width=self.width,
            height=self.height,
            status=self.status_override,
        )

    def _totp_state(self, record: Record) -> tuple[str | None, int | None, str | None]:
        """Compute the TOTP code for display, honouring the clock gate.

        Evaluated during render, which is on a keypress, so the countdown updates
        when you interact rather than on a timer.
        """
        if not record.totp:
            return None, None, None
        from . import totp as totp_module

        try:
            result = totp_module.generate(
                record.totp, last_known_good_time=self.vault.last_known_good_time
            )
        except totp_module.TotpError as exc:
            return None, None, str(exc)
        if not result.available:
            return None, None, result.blocked_reason
        return result.code, result.seconds_remaining, None

    def _render_detail(self, record: Record) -> screens.Screen:
        code, seconds, blocked = self._totp_state(record)
        return screens.render_detail(
            record,
            revealed=self.revealed,
            totp_code=code,
            totp_seconds=seconds,
            totp_blocked=blocked,
            scroll=self.detail_scroll,
            width=self.width,
            height=self.height,
            status=self.status_override,
        )

    def _render_wide(self) -> screens.Screen:
        """Two panes side by side on a larger terminal (requirement 4.9).

        The list keeps its own renderer at a reduced width and the detail pane is
        composed beside it, so the compact path stays the single source of truth
        for list layout.
        """
        left_width = max(24, self.width // 2 - 1)
        right_width = self.width - left_width - 1

        left = screens.render_list(
            self._results,
            query=self.query,
            selected=self.selected,
            scroll=self.scroll,
            width=left_width,
            height=self.height,
            status=self.status_override,
        )

        record = self.current
        if record is None:
            right = screens.render_message(
                "", "no entry selected", width=right_width, height=self.height,
                status="",
            )
        else:
            code, seconds, blocked = self._totp_state(record)
            right = screens.render_detail(
                record,
                revealed=self.revealed,
                totp_code=code,
                totp_seconds=seconds,
                totp_blocked=blocked,
                scroll=self.detail_scroll,
                width=right_width,
                height=self.height,
                status="",
            )

        lines = [
            f"{left.lines[i]}\u2502{right.lines[i]}" for i in range(self.height)
        ]
        return screens.Screen(
            lines=lines,
            reverse_rows=left.reverse_rows,
            width=self.width,
            height=self.height,
        )

    def formatted(self) -> FormattedText:
        screen = self.render()
        fragments: list[tuple[str, str]] = []
        for index, line in enumerate(screen.lines):
            style = (
                "class:screen.reverse"
                if index in screen.reverse_rows
                else "class:screen"
            )
            fragments.append((style, line))
            if index != len(screen.lines) - 1:
                fragments.append(("class:screen", "\n"))
        return FormattedText(fragments)

    # --------------------------------------------------------------- handlers

    def on_text(self, text: str) -> None:
        if self.mode == MODE_MESSAGE:
            self._dismiss_message()
            return
        if self.mode == MODE_FORM:
            self._form_key(text)
            return
        if self.mode == MODE_DETAIL:
            self._detail_key(text)
            return
        self.query += text
        self.selected = 0
        self.scroll = 0
        self.status_override = None
        self._refresh_results()

    def on_backspace(self) -> None:
        if self.mode == MODE_MESSAGE:
            self._dismiss_message()
            return
        if self.mode == MODE_FORM:
            self.form_backspace()
            return
        if self.mode == MODE_DETAIL:
            return
        if self.query:
            self.query = self.query[:-1]
            self.selected = 0
            self._refresh_results()

    def on_down(self) -> None:
        if self.mode == MODE_MESSAGE:
            self._dismiss_message()
            return
        if self.mode == MODE_FORM:
            self.form_next()
            return
        if self.mode == MODE_DETAIL:
            self.detail_scroll += 1
            return
        if self._results:
            self.selected = min(self.selected + 1, len(self._results) - 1)
            self._clamp_scroll()

    def on_up(self) -> None:
        if self.mode == MODE_MESSAGE:
            self._dismiss_message()
            return
        if self.mode == MODE_FORM:
            self.form_previous()
            return
        if self.mode == MODE_DETAIL:
            self.detail_scroll = max(0, self.detail_scroll - 1)
            return
        self.selected = max(0, self.selected - 1)
        self._clamp_scroll()

    def on_enter(self) -> None:
        if self.mode == MODE_MESSAGE:
            self._dismiss_message()
            return
        if self.mode == MODE_FORM:
            self.form_next()
            return
        if self.mode == MODE_LIST and self.current is not None:
            self.current_id = self.current.id
            self.mode = MODE_DETAIL
            self.detail_scroll = 0
            self.revealed_at = None
            self.status_override = None

    def on_escape(self) -> None:
        if self.mode == MODE_MESSAGE:
            self._dismiss_message()
            return
        if self.mode == MODE_FORM:
            self.form_cancel()
            return
        if self.mode == MODE_DETAIL:
            self.mode = MODE_LIST
            self.revealed_at = None
            self.detail_scroll = 0
            self.status_override = None
            return
        if self.query:
            self.query = ""
            self.selected = 0
            self._refresh_results()
        else:
            self.should_exit = True

    def on_quit(self) -> None:
        self.should_exit = True

    def _dismiss_message(self) -> None:
        self.mode = MODE_LIST
        self.message_title = ""
        self.message_body = ""

    def _detail_key(self, text: str) -> None:
        key = text.lower()
        if key == "p":
            self.toggle_reveal()
        elif key == "e":
            self.open_edit_form()
        elif key == "d":
            self.delete_current()
        elif key == "q":
            self.should_exit = True

    def toggle_reveal(self) -> None:
        """Requirement 4.10: reveal, then re-mask automatically."""
        if self.revealed:
            self.revealed_at = None
        else:
            self.revealed_at = self.now()
            self._schedule_remask()

    def _schedule_remask(self) -> None:
        """Arrange a single repaint when the reveal window expires.

        This is one ``call_later``, not a periodic refresh, so it does not
        conflict with requirement 4.4. Without it the password would stay visible
        on screen until the next keypress, which is exactly the shoulder-surfing
        case the timeout exists to prevent. If there is no running loop, as in
        tests, the reveal still expires because :attr:`revealed` is time-checked
        on every render.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        app = getattr(self, "_app", None)
        if app is None:
            return
        loop.call_later(self.reveal_seconds + 0.1, app.invalidate)

    def delete_current(self) -> None:
        record = self.current
        if record is None:
            return
        self.vault.delete(record.id)
        self.mode = MODE_LIST
        self.current_id = None
        self.revealed_at = None
        self._refresh_results()
        self.status_override = "deleted " + truncate(record.name, max(8, self.width - 10))

    # ------------------------------------------------------------------ forms

    FORM_FIELDS = (
        ("name", "name"),
        ("login", "login"),
        ("password", "password"),
        ("url", "url"),
        ("memo", "memo"),
        ("totp", "totp"),
    )

    def _secret_rows(self) -> list[int]:
        """Rows rendered masked while being typed.

        The password must not appear on screen even during entry: on a handheld
        used in public that is the shoulder-surfing case, and the legacy tool read
        passwords with input(), echoing them and leaving them in scrollback.
        """
        return [
            index
            for index, (_label, key, _value) in enumerate(self._form)
            if key == "password"
        ]

    def open_add_form(self) -> None:
        self.mode = MODE_FORM
        self.form_title = "Add entry"
        self.form_target = None
        self.form_active = 0
        self.status_override = None
        self._form = [[label, key, ""] for label, key in self.FORM_FIELDS]

    def open_edit_form(self) -> None:
        record = self.current
        if record is None:
            return
        self.mode = MODE_FORM
        self.form_title = f"Edit {truncate(record.name, max(8, self.width - 6))}"
        self.form_target = record.id
        self.form_active = 0
        self.status_override = None
        self._form = [
            [label, key, str(record.fields.get(key, ""))]
            for label, key in self.FORM_FIELDS
        ]

    def _form_key(self, text: str) -> None:
        self._form[self.form_active][2] += text

    def generate_into_form(self) -> None:
        """Fill the password field with a fresh generated password.

        Opens the add form first if it is not already open, so a single keystroke
        from the list takes you to a new entry with a password ready. Thumb mode is
        used on a narrow terminal, which is a reliable proxy for being on the
        Beepy, where symbols sit behind a modifier layer.
        """
        from . import generator

        if self.mode != MODE_FORM:
            self.open_add_form()
        password = generator.generate(length=20, thumb=not self.wide)
        for index, (_label, key, _value) in enumerate(self._form):
            if key == "password":
                self._form[index][2] = password
                self.form_active = index
                break
        self.status_override = "generated  ^s to save"

    def form_next(self) -> None:
        self.form_active = (self.form_active + 1) % len(self._form)

    def form_previous(self) -> None:
        self.form_active = (self.form_active - 1) % len(self._form)

    def form_backspace(self) -> None:
        value = self._form[self.form_active][2]
        self._form[self.form_active][2] = value[:-1]

    def form_cancel(self) -> None:
        self.mode = MODE_DETAIL if self.form_target else MODE_LIST
        self._form = []
        self.status_override = None

    def form_save(self) -> None:
        values = {key: value for _label, key, value in self._form}
        name = values.get("name", "").strip()
        if not name:
            self.status_override = "name is required"
            return

        try:
            if self.form_target is None:
                record = self.vault.add(
                    name,
                    login=values.get("login", ""),
                    password=values.get("password", ""),
                    url=values.get("url", ""),
                    memo=values.get("memo", ""),
                    totp=values.get("totp", ""),
                )
                self.current_id = record.id
            else:
                self.vault.update(self.form_target, **values)
        except Exception as exc:  # DuplicateNameError and validation failures
            self.status_override = truncate(str(exc), self.width)
            return

        self._form = []
        self.revealed_at = None
        self.mode = MODE_DETAIL if self.form_target else MODE_LIST
        self._refresh_results()
        self.status_override = "saved"

    # -------------------------------------------------------------- app glue

    def build_application(self) -> Application:
        bindings = self._build_key_bindings()
        control = FormattedTextControl(
            self.formatted, show_cursor=False, focusable=True
        )
        window = Window(content=control, always_hide_cursor=True, wrap_lines=False)

        return Application(
            layout=Layout(window),
            key_bindings=bindings,
            style=_STYLE,
            full_screen=True,
            # xterm-mono: asking for anything richer invites escape sequences
            # fbterm does not implement.
            color_depth=ColorDepth.DEPTH_1_BIT,
            mouse_support=False,
            refresh_interval=None,  # requirement 4.4: no periodic repaint
        )

    def _build_key_bindings(self) -> KeyBindings:
        bindings = KeyBindings()

        def exit_if_needed(event) -> None:
            if self.should_exit:
                event.app.exit()

        @bindings.add("<any>")
        def _(event) -> None:
            data = event.data
            if data and data.isprintable():
                self.on_text(data)
            exit_if_needed(event)

        @bindings.add("backspace")
        def _(event) -> None:
            self.on_backspace()

        @bindings.add("down")
        @bindings.add("c-n")
        @bindings.add("tab")
        def _(event) -> None:
            self.on_down()

        @bindings.add("up")
        @bindings.add("c-p")
        @bindings.add("s-tab")
        def _(event) -> None:
            self.on_up()

        @bindings.add("enter")
        def _(event) -> None:
            self.on_enter()

        @bindings.add("escape", eager=True)
        def _(event) -> None:
            self.on_escape()
            exit_if_needed(event)

        @bindings.add("c-q")
        @bindings.add("c-c")
        def _(event) -> None:
            self.on_quit()
            event.app.exit()

        @bindings.add("c-r")
        def _(event) -> None:
            self.toggle_reveal()

        @bindings.add("c-a")
        def _(event) -> None:
            if self.mode == MODE_LIST:
                self.open_add_form()

        @bindings.add("c-s")
        def _(event) -> None:
            if self.mode == MODE_FORM:
                self.form_save()

        @bindings.add("c-g")
        def _(event) -> None:
            self.generate_into_form()

        return bindings

    def run(self) -> None:
        app = self.build_application()
        self._app = app
        try:
            app.run()
        finally:
            self._app = None


def run_tui(vault: Vault, *, width: int | None = None, height: int | None = None) -> int:
    """Entry point used by ``pipw tui``."""
    import shutil

    size = shutil.get_terminal_size(fallback=(50, 15))
    tui = Tui(
        vault=vault,
        width=width or size.columns,
        height=height or size.lines,
    )
    tui.run()
    return 0
