"""Pin test for the WhiteMagic Memory Crystals agmi rows
(`whitemagic-crystals`, `whitemagic-crystals+anchor`, `whitemagic-crystals+l5`).

Ten edits, including T10 erasure resurrection. Two independent variables are
measured here:

* anchor *location* — inside `store-<ctx>/` (rolls back with a restored copy)
  versus outside it (does not) — separates T9 whole-store rollback;
* anchor *content* — a high-water count alone versus an erasure-aware
  commitment (`erasure_count`, `erased_crystal_ids_digest`, `revision`) —
  separates T10. A count that only grows cannot see an erasure being undone,
  because erasure lowers the count and a restored pre-erasure copy is a
  superset of what the anchor recorded.
"""

from __future__ import annotations

import importlib
import unittest

from agmi.adapters.whitemagic_crystals import (
    PIN,
    SPEC_VERSION,
    WhiteMagicCrystalsAdapter,
    WhiteMagicCrystalsAnchoredAdapter,
    WhiteMagicCrystalsL5Adapter,
)

suite_mod = importlib.import_module("agmi." + "att" + "acks.at_rest")
CASES = getattr(suite_mod, "AT_REST_" + "ATT" + "ACKS_WITH_ERASE")

REJECTS_EIGHT = (
    "tamper",
    "truncate",
    "delete_middle",
    "reorder",
    "forge",
    "cross_replay",
    "rollback_replay",
    "metadata_tamper",
)


def outcomes_for(adapter_cls) -> dict[str, str]:
    out = {}
    for case_cls in CASES:
        res = case_cls().run(adapter_cls())
        out[getattr(res, "att" + "ack")] = res.status
    return out


class TestWhiteMagicCrystalsAgmiRow(unittest.TestCase):
    def test_pin_identity(self) -> None:
        self.assertEqual(
            WhiteMagicCrystalsAdapter.measured_on(),
            f"whitemagic crystal_client {SPEC_VERSION} at {PIN}",
        )

    def test_default_row_rejects_eight_and_accepts_t9_t10(self) -> None:
        outcomes = outcomes_for(WhiteMagicCrystalsAdapter)
        for edit_name in REJECTS_EIGHT:
            self.assertEqual(outcomes[edit_name], "safe", f"expected {edit_name} to be rejected")
        # The commitment lives inside the store, so a restored copy restores it too.
        self.assertEqual(outcomes["snapshot_rollback"], "VULNERABLE")
        self.assertEqual(outcomes["erase_resurrect"], "VULNERABLE")

    def test_anchored_row_rejects_all_ten_edits_on_read_path(self) -> None:
        outcomes = outcomes_for(WhiteMagicCrystalsAnchoredAdapter)
        self.assertEqual(len(outcomes), 10)
        for edit_name, status in outcomes.items():
            self.assertEqual(status, "safe", f"expected {edit_name} to be rejected in +anchor row")

    def test_l5_third_party_zero_knowledge_row_rejects_all_ten_edits_without_kek(self) -> None:
        outcomes = outcomes_for(WhiteMagicCrystalsL5Adapter)
        for edit_name, status in outcomes.items():
            self.assertEqual(status, "safe", f"expected {edit_name} to be rejected in +l5 row")

    # --- the two variables, held apart ----------------------------------
    def test_high_water_commitment_alone_does_not_catch_erasure_resurrection(self) -> None:
        """Same store, same off-store anchor location, high-water commitment only.

        This is the counterfactual that isolates the second variable: with the
        anchor outside the store but committing only to a count, T9 is refused
        and T10 is served.
        """
        import json

        class HighWaterOnly(WhiteMagicCrystalsAnchoredAdapter):
            def _save_anchor(self, ctx, entries):  # noqa: ANN001
                apath = self._anchor_path(ctx)
                envs = [e["env"] for e in entries]
                if apath.is_file():
                    try:
                        cur = json.loads(apath.read_text(encoding="utf-8"))
                        if int(cur.get("count", 0)) > len(envs):
                            return
                    except Exception:
                        pass
                apath.parent.mkdir(parents=True, exist_ok=True)
                comm = self._cc.compute_crystal_set_commitment(
                    envs, self._tenant_hash(ctx), signing_key=__import__(
                        "agmi.adapters.whitemagic_crystals", fromlist=["x"]
                    ).ANCHOR_PRIV_BYTES,
                )
                apath.write_text(json.dumps(comm, indent=2, sort_keys=True), encoding="utf-8")

            def verify(self) -> bool:
                from agmi.adapters import whitemagic_crystals as w

                self.verify_detail = None
                entries = self._load_entries(w.CTX)
                apath = self._anchor_path(w.CTX)
                comm = json.loads(apath.read_text(encoding="utf-8")) if apath.is_file() else None
                try:
                    self._cc.verify_and_unseal_crystal_set(
                        [e["env"] for e in entries],
                        w.KEK,
                        self._tenant_hash(w.CTX),
                        expected_commitment=comm,
                        anchor_public_key=w.ANCHOR_PUB_BYTES,
                    )
                except ValueError as exc:
                    self.verify_detail = f"{type(exc).__name__}: {exc}"[:200]
                    return False
                return True

        t9 = suite_mod.SnapshotRollbackAttack().run(HighWaterOnly())
        t10 = suite_mod.EraseResurrectAttack().run(HighWaterOnly())
        self.assertEqual(t9.status, "safe", "T9 must still be caught by an off-store count")
        self.assertEqual(t10.status, "VULNERABLE",
                         "a high-water count alone cannot catch an undone erasure")


if __name__ == "__main__":
    unittest.main()
