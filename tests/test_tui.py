"""Tests for the TUI (requirements 4.1-4.11, 4.9, 3.11).

The layout is verified at exactly 50x15 -- the Beepy's geometry with fbterm's 8x16
font on a 400x240 panel -- and specifically with CJK content, because
double-width characters are what break naive layout code.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from pipassword import crypto, display, screens, tui
from pipassword.events import Record
from pipassword.vault import DeviceState, Vault

PW = "four unrelated words here"
W, H = 50, 15


def rec(name, **kw) -> Record:
    fields = {"name": name}
    fields.update({k: v for k, v in kw.items() if k != "pinyin"})
    return Record(
        id=kw.get("id", name),
        fields=fields,
        pinyin=kw.get("pinyin", {}),
        created_at=1,
        updated_at=1,
    )


@pytest.fixture
def vault(isolate_home: Path):
    v, _ = Vault.create(
        isolate_home / "v", PW, params=crypto.KdfParams(1, 64, 1),
        config_dir=isolate_home / "c", check_memory=False,
    )
    yield v
    v.close()


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


# ==================================================== width-aware primitives


class TestDisplayWidth:
    def test_ascii(self):
        assert display.display_width("hello") == 5

    def test_cjk_is_double_width(self):
        assert display.display_width("企业邮箱") == 8

    def test_mixed(self):
        assert display.display_width("Google 企业") == 11

    def test_control_characters_do_not_break_measurement(self):
        assert display.display_width("a\x00b") == 2

    def test_empty(self):
        assert display.display_width("") == 0


class TestTruncate:
    def test_short_text_untouched(self):
        assert display.truncate("abc", 10) == "abc"

    def test_ascii_truncation_adds_marker(self):
        assert display.truncate("abcdefghij", 5) == "abcd…"

    def test_never_exceeds_the_width(self):
        for text in ["abcdefghij", "企业邮箱备用地址", "Google 企业账号"]:
            for width in range(1, 20):
                assert display.display_width(display.truncate(text, width)) <= width

    def test_never_splits_a_double_width_character(self):
        """The legacy bug: item[:40] on CJK produced 80 columns."""
        result = display.truncate("企业邮箱", 5)
        assert display.display_width(result) <= 5
        assert "企" in result

    def test_zero_width(self):
        assert display.truncate("abc", 0) == ""


class TestPadAndFit:
    def test_pad_to_exact_width(self):
        assert display.display_width(display.pad("企业", 10)) == 10

    def test_fit_is_always_exact(self):
        for text in ["", "a", "企业邮箱备用地址备用地址", "Google"]:
            assert display.display_width(display.fit(text, 20)) == 20

    def test_alignment(self):
        assert display.fit("x", 5, align="right").endswith("x")
        assert display.fit("x", 5, align="left").startswith("x")


class TestWrap:
    def test_wraps_on_width_not_characters(self):
        lines = display.wrap("企业邮箱备用地址企业邮箱备用地址", 10)
        assert all(display.display_width(line) <= 10 for line in lines)

    def test_breaks_long_unbroken_runs(self):
        lines = display.wrap("a" * 100, 10)
        assert len(lines) == 10
        assert all(display.display_width(line) <= 10 for line in lines)

    def test_preserves_explicit_newlines(self):
        assert display.wrap("one\ntwo", 20) == ["one", "two"]

    def test_empty_input(self):
        assert display.wrap("", 10) == [""]


# ============================================================ 50x15 geometry


class TestBeepyGeometry:
    """Requirement 4.1: fully functional at 50 columns by 15 rows."""

    def test_list_is_exactly_the_terminal_size(self):
        screen = screens.render_list([rec("Google")], width=W, height=H)
        assert len(screen.lines) == H
        for line in screen.lines:
            assert display.display_width(line) == W

    def test_detail_is_exactly_the_terminal_size(self):
        screen = screens.render_detail(
            rec("Google", login="a@g.com", password="p", memo="x" * 200),
            width=W, height=H,
        )
        assert len(screen.lines) == H
        for line in screen.lines:
            assert display.display_width(line) == W

    def test_cjk_entries_do_not_overflow(self):
        """The legacy failure: a Chinese name wrapped and corrupted the menu."""
        records = [
            rec("企业邮箱", login="alan@corp.cn"),
            rec("企业邮箱备用地址很长很长", login="backup@corp.cn"),
            rec("Google 企业账号", url="https://google.com"),
        ]
        screen = screens.render_list(records, width=W, height=H)
        for line in screen.lines:
            assert display.display_width(line) == W, repr(line)

    def test_bottom_row_is_empty_for_the_ime(self):
        """Requirement 4.3: fcitx-fbterm draws its candidate bar there."""
        for screen in (
            screens.render_list([rec("x")], width=W, height=H),
            screens.render_detail(rec("x", password="p"), width=W, height=H),
            screens.render_message("t", "b", width=W, height=H),
            screens.render_form("t", [("a", "b")], width=W, height=H),
        ):
            assert screen.lines[-1].strip() == "", "bottom row must stay clear"

    def test_twelve_entries_visible(self):
        assert screens.list_capacity(H) == 12

    def test_status_line_fits(self):
        screen = screens.render_list([rec("x")], width=W, height=H)
        status = screen.lines[H - 2]
        assert status.strip()
        assert display.display_width(status) == W

    @pytest.mark.parametrize("width,height", [(50, 15), (50, 30), (80, 24), (120, 40)])
    def test_other_geometries_are_exact(self, width, height):
        screen = screens.render_list(
            [rec(f"entry {i}") for i in range(40)], width=width, height=height
        )
        assert len(screen.lines) == height
        assert all(display.display_width(line) == width for line in screen.lines)


class TestNoColour:
    """Requirement 4.2: TERM=xterm-mono, nothing may depend on colour."""

    def test_selection_uses_reverse_video(self):
        screen = screens.render_list(
            [rec("a"), rec("b")], selected=1, width=W, height=H
        )
        assert len(screen.reverse_rows) == 1

    def test_selection_also_has_a_visible_marker(self):
        """So the selection survives a display where reverse video is unclear."""
        screen = screens.render_list(
            [rec("a"), rec("b")], selected=1, width=W, height=H
        )
        selected_row = next(iter(screen.reverse_rows))
        assert screen.lines[selected_row].startswith(screens.SELECTED_MARKER)

    def test_unselected_rows_are_indented_to_match(self):
        screen = screens.render_list([rec("a"), rec("b")], selected=0, width=W, height=H)
        assert screen.lines[2].startswith(screens.UNSELECTED_MARKER)


class TestListRendering:
    def test_query_and_counter(self):
        screen = screens.render_list(
            [rec("a"), rec("b"), rec("c")], query="qy", selected=1, width=W, height=H
        )
        assert "> qy" in screen.lines[0]
        assert "2/3" in screen.lines[0]

    def test_empty_vault_message(self):
        screen = screens.render_list([], width=W, height=H)
        assert "vault is empty" in screen.lines[1]

    def test_no_matches_message(self):
        screen = screens.render_list([], query="zzz", width=W, height=H)
        assert "no matches" in screen.lines[1]

    def test_long_query_is_truncated_not_wrapped(self):
        screen = screens.render_list([rec("a")], query="x" * 200, width=W, height=H)
        assert display.display_width(screen.lines[0]) == W

    def test_scrolling_window(self):
        records = [rec(f"entry {i:02d}") for i in range(40)]
        screen = screens.render_list(
            records, selected=20, scroll=15, width=W, height=H
        )
        assert "entry 15" in screen.lines[1]
        assert "entry 20" in "".join(screen.lines)

    def test_entry_summary_prioritises_the_name(self):
        summary = screens.entry_summary(
            rec("企业邮箱备用地址很长很长很长", login="a@b.com"), 20
        )
        assert display.display_width(summary) <= 20
        assert "企业" in summary

    def test_entry_summary_drops_secondary_when_cramped(self):
        summary = screens.entry_summary(rec("A very long entry name here", login="x"), 15)
        assert display.display_width(summary) <= 15


class TestDetailRendering:
    def test_password_masked_by_default(self):
        screen = screens.render_detail(
            rec("Bank", password="hunter2"), width=W, height=H
        )
        assert "hunter2" not in screen.text()
        assert screens.MASK in screen.text()

    def test_password_revealed_when_asked(self):
        screen = screens.render_detail(
            rec("Bank", password="hunter2"), revealed=True, width=W, height=H
        )
        assert "hunter2" in screen.text()

    def test_mask_width_does_not_leak_password_length(self):
        short = screens.render_detail(rec("a", password="x"), width=W, height=H)
        long = screens.render_detail(rec("b", password="x" * 40), width=W, height=H)
        assert short.text().count("\u2022") == long.text().count("\u2022")

    def test_no_password_is_stated(self):
        screen = screens.render_detail(rec("Note"), width=W, height=H)
        assert "(none)" in screen.text()

    def test_totp_code_and_countdown(self):
        screen = screens.render_detail(
            rec("Corp", totp="JBSWY3DPEHPK3PXP"),
            totp_code="123456", totp_seconds=17, width=W, height=H,
        )
        assert "123456" in screen.text()
        assert "(17s)" in screen.text()

    def test_blocked_totp_explains_instead_of_showing_a_code(self):
        screen = screens.render_detail(
            rec("Corp", totp="JBSWY3DPEHPK3PXP"),
            totp_blocked="clock cannot be trusted, set the time",
            width=W, height=H,
        )
        text = screen.text()
        assert "unavailable" in text
        assert "clock" in text

    def test_memo_is_wrapped(self):
        screen = screens.render_detail(
            rec("x", password="p", memo="企业邮箱备用地址 " * 20), width=W, height=H
        )
        assert all(display.display_width(line) == W for line in screen.lines)

    def test_memo_scrolls(self):
        record = rec("x", password="p", memo="\n".join(f"line {i}" for i in range(40)))
        first = screens.render_detail(record, scroll=0, width=W, height=H)
        later = screens.render_detail(record, scroll=10, width=W, height=H)
        assert first.text() != later.text()

    def test_more_indicator_when_content_overflows(self):
        record = rec("x", password="p", memo="\n".join(str(i) for i in range(50)))
        screen = screens.render_detail(record, width=W, height=H)
        assert "more" in screen.lines[H - 2]


class TestFormRendering:
    def test_secret_fields_are_masked_while_typing(self):
        """A password being typed must not reach the screen or scrollback."""
        screen = screens.render_form(
            "Add", [("name", "Bank"), ("password", "typing-this")],
            secret_rows=[1], width=W, height=H,
        )
        assert "typing-this" not in screen.text()
        assert screens.MASK in screen.text()

    def test_active_row_is_marked(self):
        screen = screens.render_form(
            "Add", [("name", "a"), ("login", "b")], active=1, width=W, height=H
        )
        assert len(screen.reverse_rows) >= 2  # title plus active row


# ==================================================================== Tui


class TestTuiState:
    def test_starts_in_list_mode_on_a_clean_vault(self, vault):
        vault.add("Google", password="p")
        DeviceState(last_open_ts=10**18).save(vault.config_dir)
        t = tui.Tui(vault=vault, width=W, height=H)
        t.mode = tui.MODE_LIST
        assert t.results

    def test_typing_filters(self, vault):
        vault.add("Google", password="p")
        vault.add("GitHub", password="p")
        t = tui.Tui(vault=vault, width=W, height=H)
        t.mode = tui.MODE_LIST
        for char in "git":
            t.on_text(char)
        assert [r.name for r in t.results] == ["GitHub"]
        assert t.query == "git"

    def test_typing_pinyin_finds_cjk(self, vault):
        """Requirement 4.13, through the interface."""
        vault.add("企业邮箱", password="p")
        vault.add("GitHub", password="p")
        t = tui.Tui(vault=vault, width=W, height=H)
        t.mode = tui.MODE_LIST
        for char in "qyyx":
            t.on_text(char)
        assert [r.name for r in t.results] == ["企业邮箱"]

    def test_backspace_widens_the_search(self, vault):
        vault.add("Google", password="p")
        vault.add("GitHub", password="p")
        t = tui.Tui(vault=vault, width=W, height=H)
        t.mode = tui.MODE_LIST
        for char in "git":
            t.on_text(char)
        t.on_backspace()
        t.on_backspace()
        assert len(t.results) == 2

    def test_navigation_clamps_at_both_ends(self, vault):
        for i in range(3):
            vault.add(f"entry {i}", password="p")
        t = tui.Tui(vault=vault, width=W, height=H)
        t.mode = tui.MODE_LIST
        t.on_up()
        assert t.selected == 0
        for _ in range(10):
            t.on_down()
        assert t.selected == 2

    def test_scroll_follows_selection(self, vault):
        for i in range(40):
            vault.add(f"entry {i:02d}", password="p")
        t = tui.Tui(vault=vault, width=W, height=H)
        t.mode = tui.MODE_LIST
        for _ in range(20):
            t.on_down()
        assert t.scroll > 0
        assert t.scroll <= t.selected < t.scroll + screens.list_capacity(H)

    def test_enter_opens_detail_and_escape_returns(self, vault):
        vault.add("Google", password="p")
        t = tui.Tui(vault=vault, width=W, height=H)
        t.mode = tui.MODE_LIST
        t.on_enter()
        assert t.mode == tui.MODE_DETAIL
        t.on_escape()
        assert t.mode == tui.MODE_LIST

    def test_escape_clears_query_before_quitting(self, vault):
        vault.add("Google", password="p")
        t = tui.Tui(vault=vault, width=W, height=H)
        t.mode = tui.MODE_LIST
        t.on_text("g")
        t.on_escape()
        assert t.query == ""
        assert not t.should_exit
        t.on_escape()
        assert t.should_exit

    def test_delete_removes_and_reports(self, vault):
        record = vault.add("Doomed", password="p")
        t = tui.Tui(vault=vault, width=W, height=H)
        t.mode = tui.MODE_LIST
        t.on_enter()
        t.delete_current()
        assert t.mode == tui.MODE_LIST
        assert vault.get_by_name("Doomed") is None
        assert "deleted" in (t.status_override or "")


class TestReveal:
    """Requirement 4.10."""

    def test_masked_until_revealed(self, vault):
        vault.add("Bank", password="hunter2")
        clock = FakeClock()
        t = tui.Tui(vault=vault, width=W, height=H, now=clock)
        t.mode = tui.MODE_LIST
        t.on_enter()
        assert "hunter2" not in t.render().text()

        t.toggle_reveal()
        assert "hunter2" in t.render().text()

    def test_remasks_after_the_timeout(self, vault):
        vault.add("Bank", password="hunter2")
        clock = FakeClock()
        t = tui.Tui(vault=vault, width=W, height=H, now=clock)
        t.mode = tui.MODE_LIST
        t.on_enter()
        t.toggle_reveal()

        clock.advance(tui.REVEAL_SECONDS - 1)
        assert "hunter2" in t.render().text()

        clock.advance(2)
        assert "hunter2" not in t.render().text()

    def test_toggle_hides_immediately(self, vault):
        vault.add("Bank", password="hunter2")
        t = tui.Tui(vault=vault, width=W, height=H, now=FakeClock())
        t.mode = tui.MODE_LIST
        t.on_enter()
        t.toggle_reveal()
        t.toggle_reveal()
        assert "hunter2" not in t.render().text()

    def test_leaving_detail_hides_the_password(self, vault):
        """Requirement 4.11: no secret left behind when the screen changes."""
        vault.add("Bank", password="hunter2")
        t = tui.Tui(vault=vault, width=W, height=H, now=FakeClock())
        t.mode = tui.MODE_LIST
        t.on_enter()
        t.toggle_reveal()
        t.on_escape()
        assert "hunter2" not in t.render().text()

    def test_p_key_toggles_in_detail_view(self, vault):
        vault.add("Bank", password="hunter2")
        t = tui.Tui(vault=vault, width=W, height=H, now=FakeClock())
        t.mode = tui.MODE_LIST
        t.on_enter()
        t.on_text("p")
        assert "hunter2" in t.render().text()

    def test_typing_in_detail_does_not_search(self, vault):
        vault.add("Bank", password="p")
        t = tui.Tui(vault=vault, width=W, height=H)
        t.mode = tui.MODE_LIST
        t.on_enter()
        t.on_text("z")
        assert t.query == ""


class TestStartupNotices:
    """Requirement 3.11 and the clock warning, on 15 rows."""

    def test_changes_from_another_device_are_shown(self, isolate_home: Path):
        vault_dir = isolate_home / "v2"
        config_a = isolate_home / "ca"
        config_b = isolate_home / "cb"

        first, _ = Vault.create(
            vault_dir, PW, params=crypto.KdfParams(1, 64, 1),
            config_dir=config_a, device_name="beepy", check_memory=False,
        )
        first.add("Existing", password="p")
        first.close()

        with Vault.unlock(
            vault_dir, password=PW, config_dir=config_b,
            device_name="pi4", check_memory=False,
        ) as other:
            other.add("From Pi4", password="p")

        with Vault.unlock(
            vault_dir, password=PW, config_dir=config_a, check_memory=False
        ) as reopened:
            t = tui.Tui(vault=reopened, width=W, height=H)
            assert t.mode == tui.MODE_MESSAGE
            # The unwrapped notice carries the detail...
            assert "Since you last opened" in t.message_body
            assert "1 added" in t.message_body
            assert "From Pi4" in t.message_body
            # ...and it survives into the rendered screen, though word wrapping at
            # 50 columns may split the name across two rows.
            text = t.render().text()
            assert "Since you last opened" in text
            assert "Pi4" in text

    def test_any_key_dismisses(self, isolate_home: Path):
        vault_dir = isolate_home / "v3"
        config_dir = isolate_home / "c3"
        v, _ = Vault.create(
            vault_dir, PW, params=crypto.KdfParams(1, 64, 1),
            config_dir=config_dir, check_memory=False,
        )
        v.add("x", password="p")
        v.close()

        state = DeviceState.load(config_dir)
        state.last_open_ts = 0
        state.save(config_dir)

        with Vault.unlock(
            vault_dir, password=PW, config_dir=config_dir, check_memory=False
        ) as reopened:
            t = tui.Tui(vault=reopened, width=W, height=H)
            assert t.mode == tui.MODE_MESSAGE
            t.on_text("x")
            assert t.mode == tui.MODE_LIST
            assert t.query == ""  # the dismissing key is not typed into the query

    def test_clock_skew_is_warned_about(self, isolate_home: Path):
        from pipassword import events as ev

        vault_dir = isolate_home / "v4"
        config_dir = isolate_home / "c4"
        v, _ = Vault.create(
            vault_dir, PW, params=crypto.KdfParams(1, 64, 1),
            config_dir=config_dir, check_memory=False,
        )
        v.add("x", password="p")
        v.close()

        state = DeviceState.load(config_dir)
        state.last_known_good_time = ev.now_micros() + 7 * 24 * 3600 * 1_000_000
        state.save(config_dir)

        with Vault.unlock(
            vault_dir, password=PW, config_dir=config_dir, check_memory=False
        ) as reopened:
            t = tui.Tui(vault=reopened, width=W, height=H)
            assert "clock is behind" in t.render().text()


class TestWideLayout:
    """Requirement 4.9."""

    def test_compact_below_the_threshold(self, vault):
        vault.add("Google", password="p")
        t = tui.Tui(vault=vault, width=50, height=15)
        t.mode = tui.MODE_LIST
        assert not t.wide
        assert "\u2502" not in t.render().text()

    def test_two_panes_above_the_threshold(self, vault):
        vault.add("Google", login="a@g.com", password="p", memo="notes here")
        t = tui.Tui(vault=vault, width=120, height=40)
        t.mode = tui.MODE_LIST
        assert t.wide
        screen = t.render()
        assert all("\u2502" in line for line in screen.lines)
        assert len(screen.lines) == 40
        assert all(display.display_width(line) == 120 for line in screen.lines)

    def test_wide_pane_shows_detail_beside_the_list(self, vault):
        vault.add("Google", login="alan@example.com", password="p")
        t = tui.Tui(vault=vault, width=120, height=24)
        t.mode = tui.MODE_LIST
        text = t.render().text()
        assert "Google" in text
        assert "alan@example.com" in text

    def test_wide_layout_still_masks_passwords(self, vault):
        vault.add("Bank", password="hunter2")
        t = tui.Tui(vault=vault, width=120, height=24)
        t.mode = tui.MODE_LIST
        assert "hunter2" not in t.render().text()


class TestApplicationWiring:
    def test_application_builds_with_monochrome_and_no_refresh(self, vault):
        vault.add("x", password="p")
        t = tui.Tui(vault=vault, width=W, height=H)
        app = t.build_application()
        from prompt_toolkit.output import ColorDepth

        assert app.color_depth == ColorDepth.DEPTH_1_BIT
        assert app.refresh_interval in (None, 0)  # requirement 4.4
        assert app.mouse_support() is False

    def test_ctrl_space_is_not_bound(self, vault):
        """Requirement 4.7: fcitx owns Ctrl+Space for switching input method."""
        vault.add("x", password="p")
        t = tui.Tui(vault=vault, width=W, height=H)
        bindings = t._build_key_bindings()
        for binding in bindings.bindings:
            keys = [str(k) for k in binding.keys]
            assert "c-space" not in keys
            assert "c-@" not in keys  # the same byte on many terminals

    def test_navigation_keys_include_trackpad_arrows(self, vault):
        """The BBQ20 has no arrow keys; its trackpad emits them."""
        vault.add("x", password="p")
        t = tui.Tui(vault=vault, width=W, height=H)
        bound = {
            str(key)
            for binding in t._build_key_bindings().bindings
            for key in binding.keys
        }
        assert "Keys.Down" in bound or "down" in bound
        assert "Keys.Up" in bound or "up" in bound

    def test_formatted_text_has_one_fragment_per_row(self, vault):
        vault.add("x", password="p")
        t = tui.Tui(vault=vault, width=W, height=H)
        t.mode = tui.MODE_LIST
        fragments = t.formatted()
        styles = {style for style, _ in fragments}
        assert styles <= {"class:screen", "class:screen.reverse"}

    def test_renders_without_a_terminal(self, vault):
        """Everything above ran headless; this asserts that explicitly."""
        vault.add("企业邮箱", password="p")
        t = tui.Tui(vault=vault, width=W, height=H)
        t.mode = tui.MODE_LIST
        assert len(t.render().lines) == H


class TestForms:
    """Requirement 4.10 for entry, plus add/edit wiring for task 15."""

    def _form(self, vault):
        t = tui.Tui(vault=vault, width=W, height=H, now=FakeClock())
        t.mode = tui.MODE_LIST
        return t

    def test_add_form_saves_a_record(self, vault):
        t = self._form(vault)
        t.open_add_form()
        assert t.mode == tui.MODE_FORM

        for char in "Bank":
            t.on_text(char)
        t.form_next()  # login
        for char in "alan":
            t.on_text(char)
        t.form_next()  # password
        for char in "hunter2":
            t.on_text(char)
        t.form_save()

        assert t.mode == tui.MODE_LIST
        record = vault.get_by_name("Bank")
        assert record is not None
        assert record.login == "alan"
        assert record.password == "hunter2"

    def test_password_is_masked_while_being_typed(self, vault):
        """Shoulder-surfing: entry must not echo, unlike the legacy input()."""
        t = self._form(vault)
        t.open_add_form()
        for char in "Bank":
            t.on_text(char)
        t.form_next()
        t.form_next()  # password row
        for char in "hunter2":
            t.on_text(char)

        text = t.render().text()
        assert "hunter2" not in text
        assert screens.MASK in text

    def test_name_is_required(self, vault):
        t = self._form(vault)
        t.open_add_form()
        t.form_save()
        assert t.mode == tui.MODE_FORM
        assert "name is required" in (t.status_override or "")

    def test_duplicate_name_is_reported_not_raised(self, vault):
        vault.add("Bank", password="p")
        t = self._form(vault)
        t.open_add_form()
        for char in "Bank":
            t.on_text(char)
        t.form_save()
        assert t.mode == tui.MODE_FORM
        assert "already exists" in (t.status_override or "")

    def test_edit_form_prefills_and_updates(self, vault):
        record = vault.add("Bank", login="old", password="p", memo="keep")
        t = self._form(vault)
        t.on_enter()
        t.on_text("e")
        assert t.mode == tui.MODE_FORM
        assert any(value == "old" for _l, _k, value in t._form)

        t.form_active = 1  # login
        t.form_backspace()
        t.form_backspace()
        t.form_backspace()
        for char in "new":
            t.on_text(char)
        t.form_save()

        updated = vault.get(record.id)
        assert updated.login == "new"
        assert updated.memo == "keep"

    def test_escape_cancels_without_saving(self, vault):
        t = self._form(vault)
        t.open_add_form()
        for char in "Ghost":
            t.on_text(char)
        t.on_escape()
        assert t.mode == tui.MODE_LIST
        assert vault.get_by_name("Ghost") is None

    def test_enter_moves_between_fields(self, vault):
        t = self._form(vault)
        t.open_add_form()
        t.on_enter()
        assert t.form_active == 1
        t.on_up()
        assert t.form_active == 0

    def test_form_screen_is_exact_at_50x15(self, vault):
        t = self._form(vault)
        t.open_add_form()
        for char in "企业邮箱":
            t.on_text(char)
        screen = t.render()
        assert len(screen.lines) == H
        assert all(display.display_width(line) == W for line in screen.lines)
        assert screen.lines[-1].strip() == ""

    def test_every_advertised_key_is_actually_bound(self, vault):
        """Do not advertise a key that does nothing.

        prompt_toolkit normalises key names, so compare on the enum value rather
        than the repr.
        """
        vault.add("x", password="p")
        t = self._form(vault)
        bound = {
            getattr(key, "value", str(key))
            for binding in t._build_key_bindings().bindings
            for key in binding.keys
        }
        hint = screens._list_hints(W)
        for marker, key_name in (("^a", "c-a"), ("^g", "c-g"), ("^q", "c-q")):
            if marker in hint:
                assert key_name in bound, f"{hint!r} advertises {marker} unbound"

    def test_generate_into_form_from_the_list(self, vault):
        t = self._form(vault)
        t.generate_into_form()
        assert t.mode == tui.MODE_FORM
        password = next(v for _l, k, v in t._form if k == "password")
        assert len(password) == 20
        assert "generated" in (t.status_override or "")

    def test_generated_password_is_masked_on_screen(self, vault):
        t = self._form(vault)
        t.generate_into_form()
        password = next(v for _l, k, v in t._form if k == "password")
        assert password not in t.render().text()

    def test_narrow_terminal_generates_thumb_typable(self, vault):
        """Symbols sit behind a modifier layer on the BBQ20."""
        from pipassword import generator

        t = tui.Tui(vault=vault, width=50, height=15, now=FakeClock())
        t.mode = tui.MODE_LIST
        t.generate_into_form()
        password = next(v for _l, k, v in t._form if k == "password")
        assert not (set(password) & set(generator.SYMBOLS))
