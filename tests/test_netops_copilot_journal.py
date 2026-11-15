# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pins the measured at-rest scorecard for the NetOps Copilot change journal."""

import importlib.metadata as md

import pytest

pytest.importorskip("netops_copilot")

from agmi.adapters.netops_copilot_journal import NetopsCopilotJournalAdapter  # noqa: E402
from agmi.attacks.at_rest import AT_REST_ATTACKS_WITH_ERASE  # noqa: E402

MEASURED_ON = NetopsCopilotJournalAdapter.measured_on()

# True: Store.verify_journal() reports the edit. False: the edited journal is served.
MEASURED = {
    "tamper": True, "truncate": False, "delete_middle": True, "reorder": True,
    "forge": False, "cross_replay": True, "rollback_replay": True, "metadata_tamper": True,
    "snapshot_rollback": False, "erase_resurrect": False,
}


def test_version_is_the_measured_one():
    assert md.version("netops-copilot") == "0.1.0", "netops-copilot moved; re-measure and re-pin"


def test_ten_edits_as_measured():
    for cls in AT_REST_ATTACKS_WITH_ERASE:
        r = cls().run(NetopsCopilotJournalAdapter())
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert r.guard is None, f"{r.attack} did not land: {r.guard}"
        assert r.detected == MEASURED[r.attack], (
            f"{r.attack}: measured {'reported' if MEASURED[r.attack] else 'accepted'} on {MEASURED_ON}")


def test_forged_line_carries_a_valid_unkeyed_digest():
    a = NetopsCopilotJournalAdapter()
    a.setup()
    try:
        a.seed(3)
        a.write_raw(a.forge_record(a.read_all_raw()[-1]))
        assert a.verify() is True
        assert "forged" in a.read_all_raw()[-1].fields["entry"]["request"]
    finally:
        a.teardown()
