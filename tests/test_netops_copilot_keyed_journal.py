# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pins the measured at-rest scorecard for the keyed, anchored NetOps Copilot change journal."""

import importlib.metadata as md

import pytest

pytest.importorskip("netops_copilot")

from agmi.adapters.netops_copilot_journal import NetopsCopilotKeyedJournalAdapter  # noqa: E402
from agmi.attacks.at_rest import AT_REST_ATTACKS_WITH_ERASE  # noqa: E402

MEASURED_ON = NetopsCopilotKeyedJournalAdapter.measured_on()


def test_version_is_the_measured_one():
    assert md.version("netops-copilot") == "0.2.0", "netops-copilot moved; re-measure and re-pin"


def test_ten_edits_refused_on_read():
    for cls in AT_REST_ATTACKS_WITH_ERASE:
        r = cls().run(NetopsCopilotKeyedJournalAdapter())
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert r.guard is None, f"{r.attack} did not land: {r.guard}"
        assert r.detected, f"{r.attack}: measured refused on read on {MEASURED_ON}"


def test_forged_line_with_an_unkeyed_digest_is_refused_on_read():
    a = NetopsCopilotKeyedJournalAdapter()
    a.setup()
    try:
        a.seed(3)
        a.write_raw(a.forge_record(a.read_all_raw()[-1]))
        assert a.verify() is False
        assert "does not verify against the journal key" in a.verify_detail
    finally:
        a.teardown()


def test_key_and_anchor_stay_outside_the_state_directory():
    a = NetopsCopilotKeyedJournalAdapter()
    a.setup()
    try:
        a.seed(1)
        state = a._root("lab-A").resolve()
        assert state not in (a._secrets / "journal.key").resolve().parents
        assert state not in (a._secrets / "anchors").resolve().parents
    finally:
        a.teardown()
