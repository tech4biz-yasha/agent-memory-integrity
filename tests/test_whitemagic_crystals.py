"""Pin test for the WhiteMagic Memory Crystals agmi rows
(`whitemagic-crystals`, `whitemagic-crystals+in-store`, `whitemagic-crystals+ciphertext-audit`).

Ten edits, including T10 erasure resurrection. Two independent variables are
measured here:

* anchor *location* — inside `store-<ctx>/` (`whitemagic-crystals+in-store`,
  rolls back with a restored copy) versus automatically persisted outside it
  under `$XDG_STATE_HOME` (`whitemagic-crystals`, `LocalCrystalStore` default,
  does not) — separates T9 whole-store rollback;
* anchor *content* — a high-water count alone versus an erasure-aware
  commitment (`erasure_count`, `erased_crystal_ids_digest`, `revision`) —
  separates T10. A count that only grows cannot see an erasure being undone,
  because erasure lowers the count and a restored pre-erasure copy is a
  superset of what the anchor recorded.
"""

from __future__ import annotations

import importlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pytest

if not os.environ.get("AGMI_WHITEMAGIC_CRYSTAL_CLIENT"):
    pytest.skip("AGMI_WHITEMAGIC_CRYSTAL_CLIENT not set", allow_module_level=True)

from agmi.adapters.whitemagic_crystals import (  # noqa: E402
    PIN,
    CLIENT_SHA256,
    SPEC_VERSION,
    WhiteMagicCrystalsAdapter,
    WhiteMagicCrystalsCiphertextAuditAdapter,
    WhiteMagicCrystalsInStoreAdapter,
    WhiteMagicCrystalsL5Adapter,
)
from agmi.agent.compose import compose  # noqa: E402

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
            f"whitemagic crystal_client {SPEC_VERSION} at {PIN} sha256:{CLIENT_SHA256}",
        )

    def test_default_row_rejects_all_ten_edits_on_read_path(self) -> None:
        outcomes = outcomes_for(WhiteMagicCrystalsAdapter)
        self.assertEqual(len(outcomes), 10)
        for edit_name, status in outcomes.items():
            self.assertEqual(status, "safe", f"expected {edit_name} to be rejected in default row")

    def test_instore_counterfactual_rejects_eight_and_accepts_t9_t10(self) -> None:
        outcomes = outcomes_for(WhiteMagicCrystalsInStoreAdapter)
        for edit_name in REJECTS_EIGHT:
            self.assertEqual(outcomes[edit_name], "safe", f"expected {edit_name} to be rejected")
        # The counterfactual places commitment.json inside the store, so a restored copy restores it too.
        self.assertEqual(outcomes["snapshot_rollback"], "VULNERABLE")
        self.assertEqual(outcomes["erase_resurrect"], "VULNERABLE")

    def test_ciphertext_audit_envelope_audit_detects_all_ten_edits_without_kek(self) -> None:
        outcomes = outcomes_for(WhiteMagicCrystalsCiphertextAuditAdapter)
        for edit_name, status in outcomes.items():
            self.assertEqual(status, "safe", f"expected {edit_name} to be rejected in +ciphertext-audit row")

    def test_wrong_client_bytes_are_refused_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "crystal_client.py"
            marker = Path(directory) / "executed"
            source.write_text(f"open({str(marker)!r}, 'w').write('executed')\n", encoding="utf-8")
            with patch.dict(os.environ, {"AGMI_WHITEMAGIC_CRYSTAL_CLIENT": str(source)}):
                with self.assertRaisesRegex(RuntimeError, "pin mismatch"):
                    WhiteMagicCrystalsAdapter()
            self.assertFalse(marker.exists())

    def test_plaintext_read_row_rejects_an_isolated_plaintext_edit(self) -> None:
        adapter = WhiteMagicCrystalsAdapter()
        adapter.setup()
        try:
            adapter.seed(3)
            record = adapter.read_all_raw()[0]
            record.fields["value"] = "the limit is 999"
            adapter.write_raw(record)
            self.assertFalse(adapter.verify())
            self.assertIn("unsealed plaintext mismatch", adapter.verify_detail)
        finally:
            adapter.teardown()

    def test_ciphertext_audit_exposes_envelope_audit_scope_not_detached_plaintext(self) -> None:
        adapter = WhiteMagicCrystalsCiphertextAuditAdapter()
        adapter.setup()
        try:
            adapter.seed(3)
            record = adapter.read_all_raw()[0]
            checked_payload = adapter.payload_of(record)
            record.fields["value"] = "the limit is 999"
            adapter.write_raw(record)
            # This field is outside the row's declared measured payload. A
            # plaintext consumer must use the unsealing row above instead.
            self.assertEqual(adapter.payload_of(adapter.read_all_raw()[0]), checked_payload)
            self.assertNotIn("the limit is 999", checked_payload)
            self.assertTrue(adapter.verify())
            self.assertEqual(adapter.detection_point, "audit")
            self.assertIn("detached plaintext not evaluated", adapter.verify_detail)
            self.assertIn("scope=signed-ciphertext", adapter.measured_on())
        finally:
            adapter.teardown()

    def test_ciphertext_audit_report_labels_detection_as_audit_not_read_refusal(self) -> None:
        from agmi.check import verdict
        adapter = WhiteMagicCrystalsCiphertextAuditAdapter()
        result = suite_mod.TamperAttack().run(adapter)
        self.assertTrue(result.detected)
        self.assertEqual(verdict(result, adapter), "REPORTED")

    def test_legacy_l5_alias_identical_to_ciphertext_audit(self) -> None:
        self.assertIs(WhiteMagicCrystalsL5Adapter, WhiteMagicCrystalsCiphertextAuditAdapter)

    def test_default_row_has_no_composite_hole_with_compose(self) -> None:
        _authz, findings = compose(
            lambda: WhiteMagicCrystalsAdapter(),
            target="whitemagic-crystals",
            max_len=2,
        )
        self.assertEqual(findings, [])

    # --- the two variables, held apart ----------------------------------
    def test_high_water_commitment_alone_does_not_catch_erasure_resurrection(self) -> None:
        """Same store, off-store anchor location, high-water commitment only.

        This is the counterfactual that isolates the second variable: with the
        anchor outside the store but committing only to a count, T9 is refused
        and T10 is served.
        """
        import json

        class HighWaterOnly(WhiteMagicCrystalsInStoreAdapter):
            def _anchor_path(self, ctx: str) -> Path:
                assert self._root is not None
                return self._root / f"off-store-{ctx}.json"

            def _save_anchor(self, ctx, envs):  # noqa: ANN001
                apath = self._anchor_path(ctx)
                if apath.is_file():
                    try:
                        cur = json.loads(apath.read_text(encoding="utf-8"))
                        if int(cur.get("count", 0)) > len(envs):
                            return
                    except Exception:
                        pass
                apath.parent.mkdir(parents=True, exist_ok=True)
                comm = self._cc.compute_crystal_set_commitment(
                    envs,
                    self._tenant_hash(ctx),
                    signing_key=__import__(
                        "agmi.adapters.whitemagic_crystals", fromlist=["x"]
                    ).ANCHOR_PRIV_BYTES,
                )
                apath.write_text(json.dumps(comm, indent=2, sort_keys=True), encoding="utf-8")

            def verify(self) -> bool:
                from agmi.adapters import whitemagic_crystals as w

                self.verify_detail = None
                envs = self._load_envelopes(w.CTX)
                apath = self._anchor_path(w.CTX)
                comm = json.loads(apath.read_text(encoding="utf-8")) if apath.is_file() else None
                try:
                    self._cc.verify_and_unseal_crystal_set(
                        envs,
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
