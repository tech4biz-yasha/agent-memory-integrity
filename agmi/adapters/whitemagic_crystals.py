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
   - Default `whitemagic-crystals`: `crystal_client.LocalCrystalStore.read_all()`,
     which verifies the off-store signed erasure-aware commitment (persisted by
     default under `$XDG_STATE_HOME/whitemagic/anchors/` outside `store-<ctx>/`),
     checks `tenant_hash` context binding and `parent_crystal_id` lineage links,
     verifies optional `client_sig` and `crystal_id`, unwraps the per-crystal DEK,
     and AEAD-decrypts each crystal over its bound AAD.
   - Counterfactual `whitemagic-crystals+in-store`: stateless
     `verify_and_unseal_crystal_set(...)` reading `commitment.json` kept inside
     `store-<ctx>/`, isolating the store-boundary rollback risk (T9/T10).

5. What is pinned?
   `crystal_client.py` from `lbailey94/whitemagic`, full commit and file SHA-256
   below. The selected source bytes are checked before importing. Python 3.12
   + `cryptography`. Three measured configurations:
     - `whitemagic-crystals`: shipped `LocalCrystalStore` default, auto-persisting
       its signed commitment outside `store-<ctx>/` (`$XDG_STATE_HOME`),
       defeating store-directory snapshot rollback (T9) and erasure resurrection (T10).
     - `whitemagic-crystals+in-store`: counterfactual baseline placing `commitment.json`
       inside `store-<ctx>/` via stateless functions (`T9`/`T10` roll back with store).
     - `whitemagic-crystals+ciphertext-audit` (formerly `whitemagic-crystals+l5`):
       encrypted-envelope audit without the KEK; payload is signed ciphertext,
       not detached plaintext fields.
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
import copy
import datetime as dt
import hashlib
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

PIN = "273b177b5c59eb3148b721a85683ab929041d246"
CLIENT_SHA256 = "e44b13f2103fb3191d43bfe7cb5bbbde6393b6756af2c5fd4c2c28a52bd89fe9"
SPEC_VERSION = "wm-crystal/1.0"
CTX, OTHER = "a", "b"
STORE_FILE = "crystals.json"
ERASURES_FILE = "erasures.json"
SLOTS_FILE = "slots.json"
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


@contextmanager
def _xdg_state_env(path: Path):
    prev = os.environ.get("XDG_STATE_HOME")
    os.environ["XDG_STATE_HOME"] = str(path)
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop("XDG_STATE_HOME", None)
        else:
            os.environ["XDG_STATE_HOME"] = prev


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
    source = p.read_bytes()
    observed = hashlib.sha256(source).hexdigest()
    if observed != CLIENT_SHA256:
        raise RuntimeError(
            f"crystal_client.py pin mismatch: expected SHA-256 {CLIENT_SHA256} "
            f"from {PIN}, observed {observed}"
        )
    spec = importlib.util.spec_from_file_location("wm_crystal_client", p)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    # Execute exactly the checked bytes, rather than reopening the path after
    # the check (which would leave a file-swap race).
    exec(compile(source, str(p), "exec"), mod.__dict__)
    return mod


class WhiteMagicCrystalsAdapter(MemoryAdapter):
    """WhiteMagic Memory Crystals (`LocalCrystalStore`) with automatic off-store anchor persistence."""

    name = "whitemagic-crystals"
    supports_replay = True
    supports_metadata = True
    supports_snapshot = True
    supports_erase = True
    detection_point = "read"

    def __init__(self):
        self._cc = _load_crystal_client()
        self._root: Path | None = None

    @staticmethod
    def measured_on() -> str:
        return f"whitemagic crystal_client {SPEC_VERSION} at {PIN} sha256:{CLIENT_SHA256}"

    def _dir(self, ctx: str) -> Path:
        assert self._root is not None
        return self._root / f"store-{ctx}"

    def _xdg_dir(self) -> Path:
        assert self._root is not None
        return self._root / "xdg-state"

    def _store_path(self, ctx: str) -> Path:
        return self._dir(ctx) / STORE_FILE

    def _slots_path(self, ctx: str) -> Path:
        return self._dir(ctx) / SLOTS_FILE

    def _erasures_path(self, ctx: str) -> Path:
        return self._dir(ctx) / ERASURES_FILE

    def _tenant_hash(self, ctx: str) -> str:
        return self._cc.compute_tenant_hash(f"tenant-{ctx}")

    def _open_store(self, ctx: str, *, create: bool = True):
        with _xdg_state_env(self._xdg_dir()):
            return self._cc.LocalCrystalStore(
                self._dir(ctx),
                key=KEK,
                tenant_id=f"tenant-{ctx}",
                anchor_signing_key=ANCHOR_PRIV_BYTES,
                anchor_public_key=ANCHOR_PUB_BYTES,
                cipher="chacha20-poly1305",
                kek_version=1,
                create=create,
            )

    def setup(self) -> None:
        self._root = Path(tempfile.mkdtemp(prefix="agmi-wm-crystals-"))
        self._xdg_dir().mkdir(parents=True, exist_ok=True)
        for ctx in (CTX, OTHER):
            self._open_store(ctx, create=True)
            self._save_slots(ctx, [])

    def teardown(self) -> None:
        if self._root:
            shutil.rmtree(self._root, ignore_errors=True)
        self._root = None

    def _value(self, token: str, i: int) -> str:
        return f"the limit is {50 + i}" if token == SEED_TOKEN else f"the quota is {90 + i}"

    def _load_envelopes(self, ctx: str) -> list[dict]:
        p = self._store_path(ctx)
        if not p.is_file():
            return []
        return json.loads(p.read_text(encoding="utf-8"))

    def _save_envelopes(self, ctx: str, envs: list[dict]) -> None:
        self._store_path(ctx).write_text(
            json.dumps(envs, indent=2, sort_keys=True), encoding="utf-8"
        )

    def _load_slots(self, ctx: str) -> list[dict]:
        p = self._slots_path(ctx)
        if not p.is_file():
            return []
        return json.loads(p.read_text(encoding="utf-8"))

    def _save_slots(self, ctx: str, slots: list[dict]) -> None:
        self._slots_path(ctx).write_text(
            json.dumps(slots, indent=2, sort_keys=True), encoding="utf-8"
        )

    def _load_erasures(self, ctx: str) -> list[dict]:
        p = self._erasures_path(ctx)
        if not p.is_file():
            return []
        return json.loads(p.read_text(encoding="utf-8"))

    def _append_one(self, ctx: str, token: str, idx: int) -> None:
        slot_key = f"{token}{idx}"
        val = self._value(token, idx)
        with _xdg_state_env(self._xdg_dir()):
            store = self._open_store(ctx, create=False)
            store.append(
                val,
                metadata_public={"source": "system", "slot": slot_key, "role": "policy"},
                sign_envelope=True,
            )
        slots = self._load_slots(ctx)
        slots.append({"key": slot_key, "value": val})
        self._save_slots(ctx, slots)

    def seed(self, n: int) -> None:
        for i in range(n):
            self._append_one(CTX, SEED_TOKEN, i)

    def seed_other(self, n: int) -> None:
        for i in range(n):
            self._append_one(OTHER, OTHER_TOKEN, i)

    def append_genuine(self) -> None:
        n = len(self._load_slots(CTX))
        self._append_one(CTX, SEED_TOKEN, n)

    def erase_genuine(self) -> list[str]:
        """Erase the newest crystal through LocalCrystalStore.erase()."""
        with _xdg_state_env(self._xdg_dir()):
            store = self._open_store(CTX, create=False)
            tombstones = store.erase()
        slots = self._load_slots(CTX)
        victim_slot = slots.pop()
        self._save_slots(CTX, slots)
        erased_key = tombstones[0].get("slot", victim_slot["key"])
        return [str(erased_key)]

    def _records(self, ctx: str) -> list[Record]:
        envs = self._load_envelopes(ctx)
        slots = self._load_slots(ctx)
        return [
            Record(
                seq=i,
                fields={
                    "ctx": ctx,
                    "key": slots[i]["key"] if i < len(slots) else f"orphan-{i}",
                    "value": slots[i]["value"] if i < len(slots) else "",
                    "env": copy.deepcopy(env),
                },
            )
            for i, env in enumerate(envs)
        ]

    def read_all_raw(self) -> list[Record]:
        return self._records(CTX)

    def read_other_raw(self) -> list[Record]:
        return self._records(OTHER)

    def write_raw(self, record: Record) -> None:
        envs = self._load_envelopes(CTX)
        slots = self._load_slots(CTX)
        slot_obj = {"key": record.fields["key"], "value": record.fields["value"]}
        env_obj = copy.deepcopy(record.fields["env"])
        if record.seq < len(envs):
            envs[record.seq] = env_obj
        else:
            envs.append(env_obj)
        if record.seq < len(slots):
            slots[record.seq] = slot_obj
        else:
            slots.append(slot_obj)
        self._save_envelopes(CTX, envs)
        self._save_slots(CTX, slots)

    def delete_raw(self, seq: int) -> None:
        envs = self._load_envelopes(CTX)
        slots = self._load_slots(CTX)
        if seq < 0 or seq >= len(envs):
            raise IndexError(f"no crystal at position {seq}")
        del envs[seq]
        if seq < len(slots):
            del slots[seq]
        self._save_envelopes(CTX, envs)
        self._save_slots(CTX, slots)

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
        envs = self._load_envelopes(CTX)
        slots = self._load_slots(CTX)
        slot_key = slots[target_seq]["key"]
        envs[target_seq] = copy.deepcopy(donor.fields["env"])
        slots[target_seq] = {
            "key": slot_key,
            "value": donor.fields["value"],
        }
        self._save_envelopes(CTX, envs)
        self._save_slots(CTX, slots)

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
        try:
            with _xdg_state_env(self._xdg_dir()):
                store = self._open_store(CTX, create=False)
                records = store.read_all()
            slots = self._load_slots(CTX)
            if len(slots) != len(records):
                raise ValueError(
                    f"slot count mismatch: {len(slots)} != {len(records)}"
                )
            for idx, (slot, rec) in enumerate(zip(slots, records)):
                slot_claim = (rec.get("metadata_public") or {}).get("slot")
                if slot_claim != slot["key"]:
                    raise ValueError(
                        f"slot binding mismatch at index {idx}: {slot_claim!r} != {slot['key']!r}"
                    )
                if rec["plaintext"].decode("utf-8") != slot["value"]:
                    raise ValueError(f"unsealed plaintext mismatch at index {idx}")
        except (ValueError, InvalidTag, FileNotFoundError, OSError, KeyError) as exc:
            self.verify_detail = f"{type(exc).__name__}: {exc}"[:200]
            return False
        self.verify_detail = f"verified and unsealed {len(records)} crystals ok"
        return True


class WhiteMagicCrystalsInStoreAdapter(WhiteMagicCrystalsAdapter):
    """Counterfactual storing the signed commitment inside `store-<ctx>/` via stateless calls."""

    name = "whitemagic-crystals+in-store"

    def _anchor_path(self, ctx: str) -> Path:
        return self._dir(ctx) / ANCHOR_FILE

    def _save_erasures(self, ctx: str, erasures: list[dict]) -> None:
        self._erasures_path(ctx).write_text(
            json.dumps(erasures, indent=2, sort_keys=True), encoding="utf-8"
        )

    def _save_anchor(self, ctx: str, envs: list[dict]) -> None:
        """Rewrite the set commitment inside `store-<ctx>/`, rolling back with it."""
        apath = self._anchor_path(ctx)
        apath.parent.mkdir(parents=True, exist_ok=True)
        comm = self._cc.compute_crystal_set_commitment(
            envs,
            self._tenant_hash(ctx),
            signing_key=ANCHOR_PRIV_BYTES,
            erasures=self._load_erasures(ctx),
        )
        apath.write_text(json.dumps(comm, indent=2, sort_keys=True), encoding="utf-8")

    def setup(self) -> None:
        self._root = Path(tempfile.mkdtemp(prefix="agmi-wm-crystals-"))
        for ctx in (CTX, OTHER):
            self._dir(ctx).mkdir(parents=True, exist_ok=True)
            self._save_envelopes(ctx, [])
            self._save_erasures(ctx, [])
            self._save_slots(ctx, [])
            self._save_anchor(ctx, [])

    def _append_one(self, ctx: str, token: str, idx: int) -> None:
        envs = self._load_envelopes(ctx)
        slots = self._load_slots(ctx)
        parent_id = envs[-1]["crystal_id"] if envs else None
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
        envs.append(env)
        slots.append({"key": slot_key, "value": val})
        self._save_envelopes(ctx, envs)
        self._save_slots(ctx, slots)
        self._save_anchor(ctx, envs)

    def erase_genuine(self) -> list[str]:
        """Erase the newest crystal and update the in-store erasure list and commitment."""
        envs = self._load_envelopes(CTX)
        slots = self._load_slots(CTX)
        if not envs:
            raise RuntimeError("no crystal to erase")
        victim_env = envs.pop()
        victim_slot = slots.pop()
        cid = str(victim_env["crystal_id"]).lower()
        erasures = self._load_erasures(CTX)
        erasures.append(
            {
                "crystal_id": cid,
                "slot": victim_slot["key"],
                "erased_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "class": "access_control_and_ciphertext_purge",
            }
        )
        self._save_envelopes(CTX, envs)
        self._save_slots(CTX, slots)
        self._save_erasures(CTX, erasures)
        self._save_anchor(CTX, envs)
        return [victim_slot["key"]]

    def verify(self) -> bool:
        self.verify_detail = None
        envs = self._load_envelopes(CTX)
        slots = self._load_slots(CTX)
        apath = self._anchor_path(CTX)
        try:
            if not apath.is_file():
                raise ValueError("missing commitment anchor")
            comm = json.loads(apath.read_text(encoding="utf-8"))
            plaintexts = self._cc.verify_and_unseal_crystal_set(
                envs,
                KEK,
                self._tenant_hash(CTX),
                expected_commitment=comm,
                anchor_public_key=ANCHOR_PUB_BYTES,
                erasures=self._load_erasures(CTX),
            )
            if len(slots) != len(plaintexts):
                raise ValueError(
                    f"slot count mismatch: {len(slots)} != {len(plaintexts)}"
                )
            for idx, (env, slot, pt_bytes) in enumerate(zip(envs, slots, plaintexts)):
                slot_claim = (env.get("metadata_public") or {}).get("slot")
                if slot_claim != slot["key"]:
                    raise ValueError(
                        f"slot binding mismatch at index {idx}: {slot_claim!r} != {slot['key']!r}"
                    )
                if pt_bytes.decode("utf-8") != slot["value"]:
                    raise ValueError(f"unsealed plaintext mismatch at index {idx}")
        except (ValueError, InvalidTag, FileNotFoundError, OSError, KeyError) as exc:
            self.verify_detail = f"{type(exc).__name__}: {exc}"[:200]
            return False
        self.verify_detail = f"verified and unsealed {len(plaintexts)} crystals ok"
        return True


class WhiteMagicCrystalsCiphertextAuditAdapter(WhiteMagicCrystalsAdapter):
    """Signed encrypted-envelope audit without a decryption key (`LocalCrystalStore.verify_third_party`).

    Formerly known as whitemagic-crystals+l5. This row measures envelope integrity
    at audit time using the shipped off-store anchor. Its ciphertext payload deliberately
    excludes the detached plaintext field, which cannot be bound to ciphertext without
    unsealing or an additional proof construction.
    """

    name = "whitemagic-crystals+ciphertext-audit"
    detection_point = "audit"

    @staticmethod
    def measured_on() -> str:
        return (
            WhiteMagicCrystalsAdapter.measured_on()
            + " scope=signed-ciphertext audit-only no-KEK"
        )

    def payload_of(self, record: Record) -> str:
        # Metadata has its own T8 edit/control. Exposing ciphertext as content
        # keeps that independent variable separate while binding this payload
        # to what the no-KEK verifier actually checks.
        return str(record.fields["env"]["ciphertext"])

    def verify(self) -> bool:
        self.verify_detail = None
        try:
            with _xdg_state_env(self._xdg_dir()):
                store = self._open_store(CTX, create=False)
                result = store.verify_third_party(signer_public_key=ANCHOR_PUB_BYTES)
            envs = self._load_envelopes(CTX)
            slots = self._load_slots(CTX)
            if len(slots) != len(envs):
                raise ValueError(
                    f"slot count mismatch: {len(slots)} != {len(envs)}"
                )
            for idx, (env, slot) in enumerate(zip(envs, slots)):
                slot_claim = (env.get("metadata_public") or {}).get("slot")
                if slot_claim != slot["key"]:
                    raise ValueError(
                        f"slot binding mismatch at index {idx}: {slot_claim!r} != {slot['key']!r}"
                    )
        except (ValueError, InvalidTag, FileNotFoundError, OSError, KeyError) as exc:
            self.verify_detail = f"{type(exc).__name__}: {exc}"[:200]
            return False
        self.verify_detail = (
            f"audited {result.get('count', len(envs))} signed encrypted envelopes without KEK; "
            "detached plaintext not evaluated"
        )
        return True


# Backward-compatible aliases for legacy working names
WhiteMagicCrystalsAnchoredAdapter = WhiteMagicCrystalsAdapter
WhiteMagicCrystalsL5Adapter = WhiteMagicCrystalsCiphertextAuditAdapter

