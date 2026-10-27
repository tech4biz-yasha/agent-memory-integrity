# agmi: Agent Memory Integrity conformance adapter for WhiteMagic Memory Crystals
# SPDX-License-Identifier: MIT
"""WhiteMagic Memory Crystals (`wm-crystal/1.0`), a client-encrypted,
content-addressed, lineage-chained memory store for agents.

1. What is the store?
   A per-tenant directory (`store-<ctx>/`) holding `crystals.json` (an ordered
   list of slot entries, each containing a `wm-crystal/1.0` AEAD-sealed crystal
   envelope) and a signed `wm.crystal-set-commitment` high-water head
   commitment (`commitment.json`).

2. What is one record?
   One slot entry containing a `wm-crystal/1.0` envelope (`crystal_id`,
   `parent_crystal_id`, `tenant_hash`, `cipher`, `nonce`, `ciphertext`,
   `created_at`, `kek_version=1`, `id_kek_version=1`, `wrapped_dek`,
   `metadata_public`).

3. What is the threat / edit scope?
   Direct read/write access to the store directory (`store-<ctx>/`) on disk,
   without access to the client's 32-byte Key Encryption Key (`KEK`) or the
   Ed25519 commitment signing key.

4. What is the read path?
   `crystal_client.verify_and_unseal_crystal_set(crystals, key, tenant_hash,
   expected_commitment=..., anchor_public_key=...)`, which verifies the high-water
   commitment, checks `tenant_hash` context binding and `parent_crystal_id`
   lineage links, recomputes `crystal_id = sha256(id_kek_version_be32 || nonce || ciphertext)`,
   unwraps the per-crystal DEK, and AEAD-decrypts each crystal over its bound
   AAD (`cipher|tenant_hash|parent_crystal_id|created_at|metadata_public`).

5. What is pinned?
   `crystal_client.py` from `lbailey94/whitemagic` (`scripts/crystal_client.py` @ `586ed21` / `0fe89e3`),
   Python 3.12 + `cryptography`. Two configurations:
     - `whitemagic-crystals`: commitment stored inside `store-<ctx>/` on the
       same disk.
     - `whitemagic-crystals+anchor`: commitment stored outside the store
       directory (`offstore-anchors/`), detecting whole-store snapshot rollback (T9).
"""

from __future__ import annotations

import base64
import copy
import datetime as dt
import importlib.util
import json
import os
import secrets
import shutil
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agmi.adapters.base import MemoryAdapter, Record

PIN = "0fe89e3"
SPEC_VERSION = "wm-crystal/1.0"
CTX, OTHER = "a", "b"
STORE_FILE = "crystals.json"
ERASURES_FILE = "erasures.json"
ANCHOR_FILE = "commitment.json"
SEED_TOKEN = "agmi-seed-"
OTHER_TOKEN = "agmi-other-"

KEK = b"agmi-whitemagic-kek-32-bytes-001"
ANCHOR_PRIV_BYTES = b"agmi-whitemagic-anchor-ed25519-1"
ANCHOR_PUB_BYTES = (
    Ed25519PrivateKey.from_private_bytes(ANCHOR_PRIV_BYTES)
    .public_key()
    .public_bytes(Encoding.Raw, PublicFormat.Raw)
)


CRYSTAL_CLIENT_ENV = "AGMI_WHITEMAGIC_CRYSTAL_CLIENT"


def _crystal_client_path() -> Path | None:
    """Locate the pinned crystal_client.py.

    The row needs a checkout of lbailey94/whitemagic (scripts/crystal_client.py). It is not
    on a package index, so, as the Recallspection and HDP rows do, the suite
    skips the row unless the checkout is named in the environment.
    """
    named = os.environ.get(CRYSTAL_CLIENT_ENV)
    if not named:
        return None
    p = Path(named).expanduser().resolve()
    return p if p.is_file() else None


def _load_crystal_client():
    p = _crystal_client_path()
    if p is None:
        raise RuntimeError(
            "crystal_client.py not found: set "
            f"{CRYSTAL_CLIENT_ENV} to scripts/crystal_client.py from "
            "github.com/lbailey94/whitemagic at the pinned commit"
        )
    spec = importlib.util.spec_from_file_location("wm_crystal_client", p)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


class WhiteMagicCrystalsAdapter(MemoryAdapter):
    """WhiteMagic Memory Crystals with the head commitment stored beside the store on the same disk."""

    name = "whitemagic-crystals"
    supports_replay = True
    supports_metadata = True
    supports_snapshot = True
    supports_erase = True
    detection_point = "read"

    anchor_off_store = False

    def __init__(self):
        self._cc = _load_crystal_client()
        self._root: Path | None = None

    @staticmethod
    def measured_on() -> str:
        return f"whitemagic crystal_client {SPEC_VERSION} at {PIN}"

    def _dir(self, ctx: str) -> Path:
        assert self._root is not None
        return self._root / f"store-{ctx}"

    def _store_path(self, ctx: str) -> Path:
        return self._dir(ctx) / STORE_FILE

    def _anchor_path(self, ctx: str) -> Path:
        assert self._root is not None
        if self.anchor_off_store:
            return self._root / "offstore-anchors" / f"{ctx}-{ANCHOR_FILE}"
        return self._dir(ctx) / ANCHOR_FILE

    def _erasures_path(self, ctx: str) -> Path:
        # The erasure list is part of the store: it rolls back with the store,
        # which is exactly why the *anchor* has to commit to it.
        return self._dir(ctx) / ERASURES_FILE

    def _tenant_hash(self, ctx: str) -> str:
        return self._cc.compute_tenant_hash(f"tenant-{ctx}")

    def setup(self) -> None:
        self._root = Path(tempfile.mkdtemp(prefix="agmi-wm-crystals-"))
        for ctx in (CTX, OTHER):
            self._dir(ctx).mkdir(parents=True, exist_ok=True)
            self._store_path(ctx).write_text("[]", encoding="utf-8")

    def teardown(self) -> None:
        if self._root:
            shutil.rmtree(self._root, ignore_errors=True)
        self._root = None

    def _value(self, token: str, i: int) -> str:
        return f"the limit is {50 + i}" if token == SEED_TOKEN else f"the quota is {90 + i}"

    def _load_entries(self, ctx: str) -> list[dict]:
        p = self._store_path(ctx)
        if not p.is_file():
            return []
        return json.loads(p.read_text(encoding="utf-8"))

    def _save_entries(self, ctx: str, entries: list[dict]) -> None:
        self._store_path(ctx).write_text(
            json.dumps(entries, indent=2, sort_keys=True), encoding="utf-8"
        )

    def _load_erasures(self, ctx: str) -> list[dict]:
        p = self._erasures_path(ctx)
        if not p.is_file():
            return []
        return json.loads(p.read_text(encoding="utf-8"))

    def _save_erasures(self, ctx: str, erasures: list[dict]) -> None:
        self._erasures_path(ctx).write_text(
            json.dumps(erasures, indent=2, sort_keys=True), encoding="utf-8"
        )

    def _save_anchor(self, ctx: str, entries: list[dict]) -> None:
        """Rewrite the set commitment over the store *and* its erasure list.

        Deliberately not a high-water mark. A count that only grows catches T9
        (append then roll back) but not T10: erasure lowers the count, so a
        restored pre-erasure copy is a superset of the anchor and passes. The
        commitment therefore carries ``erasure_count``, an
        ``erased_crystal_ids_digest`` and a ``revision`` that increases on every
        add and every erase. Where the anchor lives then decides the outcome:
        inside the store it rolls back with the copy (T10 served), outside it it
        does not (T10 refused).
        """
        apath = self._anchor_path(ctx)
        envelopes = [e["env"] for e in entries]
        apath.parent.mkdir(parents=True, exist_ok=True)
        comm = self._cc.compute_crystal_set_commitment(
            envelopes,
            self._tenant_hash(ctx),
            signing_key=ANCHOR_PRIV_BYTES,
            erasures=self._load_erasures(ctx),
        )
        apath.write_text(json.dumps(comm, indent=2, sort_keys=True), encoding="utf-8")

    def _append_one(self, ctx: str, token: str, idx: int) -> None:
        entries = self._load_entries(ctx)
        parent_id = entries[-1]["env"]["crystal_id"] if entries else None
        slot_key = f"{token}{idx}"
        val = self._value(token, idx)
        env = self._cc.seal_crystal(
            content=val,
            key=KEK,
            tenant_id=f"tenant-{ctx}",
            parent_crystal_id=parent_id,
            metadata_public={"source": "system", "slot": slot_key, "role": "policy"},
            cipher="chacha20-poly1305",
            kek_version=1,
        )
        env = self._cc.sign_crystal_envelope(env, ANCHOR_PRIV_BYTES)
        entries.append({"key": slot_key, "value": val, "env": env})
        self._save_entries(ctx, entries)
        self._save_anchor(ctx, entries)

    def seed(self, n: int) -> None:
        for i in range(n):
            self._append_one(CTX, SEED_TOKEN, i)

    def seed_other(self, n: int) -> None:
        for i in range(n):
            self._append_one(OTHER, OTHER_TOKEN, i)

    def append_genuine(self) -> None:
        n = len(self._load_entries(CTX))
        self._append_one(CTX, SEED_TOKEN, n)

    def erase_genuine(self) -> list[str]:
        """Erase the newest crystal through the tool's own erasure path.

        The tail is erased so the remaining lineage DAG stays valid without
        rewriting any untouched record (the attack checks exactly that). The
        erasure writes a tombstone to the erasure list and rewrites the set
        commitment — the state T10 then tries to undo.
        """
        entries = self._load_entries(CTX)
        if not entries:
            raise RuntimeError("no crystal to erase")
        victim = entries.pop()
        cid = str(victim["env"]["crystal_id"]).lower()
        erasures = self._load_erasures(CTX)
        erasures.append({
            "crystal_id": cid,
            "slot": victim["key"],
            "erased_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "class": "access_control_and_ciphertext_purge",
        })
        self._save_entries(CTX, entries)
        self._save_erasures(CTX, erasures)
        self._save_anchor(CTX, entries)
        return [victim["key"]]

    def _records(self, ctx: str) -> list[Record]:
        entries = self._load_entries(ctx)
        return [
            Record(
                seq=i,
                fields={
                    "ctx": ctx,
                    "key": item["key"],
                    "value": item["value"],
                    "env": copy.deepcopy(item["env"]),
                },
            )
            for i, item in enumerate(entries)
        ]

    def read_all_raw(self) -> list[Record]:
        return self._records(CTX)

    def read_other_raw(self) -> list[Record]:
        return self._records(OTHER)

    def _entry_of(self, record: Record) -> dict:
        return {
            "key": record.fields["key"],
            "value": record.fields["value"],
            "env": copy.deepcopy(record.fields["env"]),
        }

    def write_raw(self, record: Record) -> None:
        entries = self._load_entries(CTX)
        if record.seq < len(entries):
            entries[record.seq] = self._entry_of(record)
        else:
            entries.append(self._entry_of(record))
        self._save_entries(CTX, entries)

    def delete_raw(self, seq: int) -> None:
        entries = self._load_entries(CTX)
        if seq < 0 or seq >= len(entries):
            raise IndexError(f"no crystal at position {seq}")
        del entries[seq]
        self._save_entries(CTX, entries)

    def mutate_payload(self, record: Record) -> Record:
        fields = copy.deepcopy(record.fields)
        env = fields["env"]
        ct = bytearray(base64.urlsafe_b64decode(env["ciphertext"]))
        ct[0] ^= 0x01
        env["ciphertext"] = base64.urlsafe_b64encode(bytes(ct)).decode("ascii")
        fields["value"] = f"{fields['value']} [modified]"
        return Record(seq=record.seq, fields=fields)

    def forge_record(self, template: Record) -> Record:
        env = copy.deepcopy(template.fields["env"])
        forged_ct = b"forged-ciphertext-without-key-123456"
        nonce = secrets.token_bytes(12)
        env["nonce"] = base64.urlsafe_b64encode(nonce).decode("ascii")
        env["ciphertext"] = base64.urlsafe_b64encode(forged_ct).decode("ascii")
        env["size_bytes"] = len(forged_ct)
        env["crystal_id"] = self._cc.compute_crystal_id(
            forged_ct, nonce=nonce, id_kek_version=env.get("id_kek_version", 1)
        )
        forged_key = f"{SEED_TOKEN}forged"
        env["metadata_public"] = {"source": "forged", "slot": forged_key, "role": "admin"}
        return Record(
            seq=template.seq + 1,
            fields={
                "ctx": CTX,
                "key": forged_key,
                "value": "the limit is 999",
                "env": env,
            },
        )

    def replay_onto(self, target_seq: int, donor: Record) -> None:
        entries = self._load_entries(CTX)
        slot_key = entries[target_seq]["key"]
        donor_env = copy.deepcopy(donor.fields["env"])
        entries[target_seq] = {
            "key": slot_key,
            "value": donor.fields["value"],
            "env": donor_env,
        }
        self._save_entries(CTX, entries)

    def read_meta(self, seq: int) -> dict:
        return copy.deepcopy(self._records(CTX)[seq].fields["env"].get("metadata_public", {}))

    def write_meta(self, seq: int, meta: dict) -> None:
        rec = self._records(CTX)[seq]
        rec.fields["env"]["metadata_public"] = copy.deepcopy(meta)
        self.write_raw(rec)

    def identity_of(self, record: Record) -> str:
        return str(record.fields["key"])

    def payload_of(self, record: Record) -> str:
        return str(record.fields["value"])

    def owner_of(self, record: Record) -> str | None:
        return str(self._dir(record.fields["ctx"]).resolve())

    def snapshot_store(self):
        return self._copy_store(self._dir(CTX))

    def restore_store(self, token) -> None:
        self._restore_store(token, self._dir(CTX))
        shutil.rmtree(Path(token).parent, ignore_errors=True)

    def reload(self) -> None:
        return None

    def verify(self) -> bool:
        self.verify_detail = None
        entries = self._load_entries(CTX)
        envelopes = [e["env"] for e in entries]
        apath = self._anchor_path(CTX)
        comm = json.loads(apath.read_text(encoding="utf-8")) if apath.is_file() else None
        try:
            plaintexts = self._cc.verify_and_unseal_crystal_set(
                envelopes,
                KEK,
                self._tenant_hash(CTX),
                expected_commitment=comm,
                anchor_public_key=ANCHOR_PUB_BYTES,
                erasures=self._load_erasures(CTX),
            )
            for idx, (entry, pt_bytes) in enumerate(zip(entries, plaintexts)):
                slot_claim = (entry["env"].get("metadata_public") or {}).get("slot")
                if slot_claim != entry["key"]:
                    raise ValueError(f"slot binding mismatch at index {idx}: {slot_claim!r} != {entry['key']!r}")
                if pt_bytes.decode("utf-8") != entry["value"]:
                    raise ValueError(f"unsealed plaintext mismatch at index {idx}")
        except (ValueError, InvalidTag) as exc:
            self.verify_detail = f"{type(exc).__name__}: {exc}"[:200]
            return False
        self.verify_detail = f"verified and unsealed {len(plaintexts)} crystals ok"
        return True


class WhiteMagicCrystalsAnchoredAdapter(WhiteMagicCrystalsAdapter):
    """WhiteMagic Memory Crystals with the signed set commitment anchored off the store directory."""

    name = "whitemagic-crystals+anchor"
    anchor_off_store = True


class WhiteMagicCrystalsL5Adapter(WhiteMagicCrystalsAnchoredAdapter):
    """Level L5 third-party zero-knowledge verifier: verifies the crystal chain and off-store commitment without the client KEK."""

    name = "whitemagic-crystals+l5"
    anchor_off_store = True

    def verify(self) -> bool:
        self.verify_detail = None
        entries = self._load_entries(CTX)
        envelopes = [e["env"] for e in entries]
        apath = self._anchor_path(CTX)
        comm = json.loads(apath.read_text(encoding="utf-8")) if apath.is_file() else None
        try:
            if comm is None:
                raise ValueError("missing off-store commitment")
            self._cc.verify_crystal_set_third_party(
                envelopes,
                self._tenant_hash(CTX),
                expected_commitment=comm,
                signer_public_key=ANCHOR_PUB_BYTES,
                erasures=self._load_erasures(CTX),
            )
            for idx, entry in enumerate(entries):
                slot_claim = (entry["env"].get("metadata_public") or {}).get("slot")
                if slot_claim != entry["key"]:
                    raise ValueError(f"slot binding mismatch at index {idx}: {slot_claim!r} != {entry['key']!r}")
        except (ValueError, InvalidTag) as exc:
            self.verify_detail = f"{type(exc).__name__}: {exc}"[:200]
            return False
        self.verify_detail = f"verified {len(envelopes)} crystals third-party zero-knowledge (no KEK) ok"
        return True
