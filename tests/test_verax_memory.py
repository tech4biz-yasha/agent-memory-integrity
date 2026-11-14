"""Pins the measured at-rest scorecard for Verax memory.

Runs only when AGMI_VERAX_DIR names a directory with @verax-ai/body installed
by npm (`npm install @verax-ai/body@0.8.2`) and Node 22.6 or later is on PATH
or named by AGMI_NODE. The read path is Verax's own memory.get over MCP, with
the body started from the published package in a fresh Node process for every
context that is read.

The two rows differ in one thing, whether the signing keys and the memory head
sit inside the state directory, and the tests pin that they differ on T9 and on
nothing else.
"""

import functools
import json
import os

import pytest

if not os.environ.get("AGMI_VERAX_DIR"):
    pytest.skip("AGMI_VERAX_DIR not set", allow_module_level=True)

from agmi.adapters.verax_memory import (  # noqa: E402
    PIN, SUBJECTS, VeraxMemoryAdapter, VeraxMemoryHeadOutsideAdapter, node_binary,
    package_dir, tenant_key, version_hash,
)
from agmi.attacks.at_rest import AT_REST_ATTACKS_WITH_ERASE  # noqa: E402

# Each record edit and the code memory.get answered with at 0.8.2.
REFUSED_WITH = {
    "tamper": "memory-integrity-mismatch",
    "truncate": "memory-integrity-missing",
    "delete_middle": "memory-integrity-missing",
    "reorder": "memory-integrity-mismatch",
    "forge": "memory-integrity-unattested",
    "cross_replay": "memory-integrity-mismatch",
    "rollback_replay": "memory-integrity-mismatch",
    "metadata_tamper": "memory-integrity-mismatch",
}
ROWS = (VeraxMemoryAdapter, VeraxMemoryHeadOutsideAdapter)


@functools.lru_cache(maxsize=None)
def _run(cls):
    return {r.attack: r for r in (c().run(cls()) for c in AT_REST_ATTACKS_WITH_ERASE)}


def test_the_installed_package_is_the_pinned_one():
    meta = json.loads((package_dir() / "package.json").read_text(encoding="utf-8"))
    assert meta["version"] == PIN == "0.8.2"


def test_node_meets_the_engine_the_package_declares():
    import subprocess
    v = subprocess.run([node_binary(), "--version"], capture_output=True, text=True, check=True).stdout
    major, minor = (int(x) for x in v.strip().lstrip("v").split(".")[:2])
    assert (major, minor) >= (22, 6)


def test_a_clean_store_is_served_whole_and_the_contexts_are_separate():
    a = VeraxMemoryAdapter()
    a.setup()
    try:
        a.seed(5)
        a.seed_other(5)
        assert a.verify() is True, a.verify_detail
        # Every record comes back through memory.get with the content it was written with.
        for ctx in ("a", "b"):
            rows = a._run([{"op": "get", "sub": SUBJECTS[ctx], "id": f"{ctx}{i}"} for i in range(1, 6)])
            assert len(rows) == 5
            for i, row in enumerate(rows, 1):
                assert a._answer(row)[0] == "served", row
                assert a._fact(ctx, i) in row["text"], row["text"]
        # One agent asking for the other's id is told it does not exist.
        crossed = a._run([{"op": "get", "sub": SUBJECTS["a"], "id": "b1"}])
        assert a._answer(crossed[0])[0] == "absent", crossed[0]
        first, other = a.read_all_raw(), a.read_other_raw()
        assert len(first) == len(other) == 5
        assert {r.fields["tenantKey"] for r in first} == {tenant_key("a")}
        assert {r.fields["tenantKey"] for r in other} == {tenant_key("b")}
        assert not ({a.payload_of(r) for r in first} & {a.payload_of(r) for r in other})
        assert a.owner_of(first[0]) == "a" and a.owner_of(other[0]) == "b"
    finally:
        a.teardown()


def test_the_forged_digest_is_the_one_the_store_computes():
    # T5 rests on this: the attacker can compute versionHash without a key.
    a = VeraxMemoryAdapter()
    a.setup()
    try:
        a.seed(3)
        for r in a.read_all_raw():
            assert version_hash(r.fields) == r.fields["versionHash"]
    finally:
        a.teardown()


def test_the_reorder_edit_swaps_two_objects_and_leaves_the_chain_alone():
    # What the reorder cell measures on this store: a content swap between two
    # object files, not a reorder of the signed commit chain.
    a = VeraxMemoryAdapter()
    a.setup()
    try:
        a.seed(5)
        chain = a._state() / "memory-commits.jsonl"
        chain_before = chain.read_bytes()
        records = a.read_all_raw()
        i = len(records) // 2
        first, second = records[i - 1], records[i]
        first.seq, second.seq = second.seq, first.seq
        a.write_raw(first)
        a.write_raw(second)
        after = a.read_all_raw()
        assert chain.read_bytes() == chain_before
        assert after[i - 1].fields == records[i].fields
        assert after[i].fields == records[i - 1].fields
        assert a.verify() is False
        assert "memory-integrity-mismatch" in (a.verify_detail or "")
    finally:
        a.teardown()


@pytest.mark.parametrize("cls", ROWS, ids=[c.name for c in ROWS])
def test_every_record_edit_is_refused_on_the_read_path(cls):
    results = _run(cls)
    for name, code in REFUSED_WITH.items():
        r = results[name]
        assert r.guard is None, f"{name}: {r.guard}"
        assert r.error is None, f"{name}: {r.error}"
        assert r.detected is True, f"{name} moved at @verax-ai/body {PIN}; re-measure"
        assert code in (r.detail or ""), f"{name}: {r.detail}"


def test_the_default_layout_accepts_a_whole_store_rollback():
    # Keys and head in keys/ inside the state directory: a restored older copy
    # brings its own older head, and the newest genuine record is gone with no error.
    r = _run(VeraxMemoryAdapter)["snapshot_rollback"]
    assert r.guard is None and r.error is None
    assert r.detected is False
    assert r.status == "VULNERABLE"


def test_keys_and_head_outside_refuse_the_same_rollback():
    r = _run(VeraxMemoryHeadOutsideAdapter)["snapshot_rollback"]
    assert r.guard is None and r.error is None
    assert r.detected is True
    assert "memory-integrity-history-unavailable" in (r.detail or "")


@pytest.mark.parametrize("cls", ROWS, ids=[c.name for c in ROWS])
def test_erasure_is_not_evaluable_and_says_why(cls):
    r = _run(cls)["erase_resurrect"]
    assert r.status == "n/a"
    assert (r.error or "").startswith("Verax's memory has no erase operation")


def test_the_two_rows_differ_on_t9_and_nothing_else():
    default, outside = _run(VeraxMemoryAdapter), _run(VeraxMemoryHeadOutsideAdapter)
    assert len(default) == len(outside) == 10
    differ = sorted(n for n in default if default[n].status != outside[n].status)
    assert differ == ["snapshot_rollback"]
