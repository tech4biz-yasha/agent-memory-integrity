# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""NetOps Copilot: the hash-chained change journal of a network change agent.

NetOps Copilot (gokunguru/netops-copilot) is an AI agent that turns a
network change request into a reviewed, applied and reversible change.
Every apply and every rollback is appended through `Store.append()` to
`journal.jsonl` in the state directory (`NETOPS_STATE_DIR`, `.netops` by
default). Each line carries `seq`, `time`, the change fields (`type`,
`change`, `operator`, `request`, `devices`, `live`), `prev` (the previous
entry's hash) and `hash`: plain SHA-256 over the entry's canonical JSON,
with no key.

1. The store: `journal.jsonl` in one state directory.
2. One record: one journal line.
3. The attacker reads and writes the state directory. There is no key to
   hold: the chain is an unkeyed digest, so the attacker can compute a
   valid hash for anything they write.
4. The read path: `rollback()` reads `Store.journal()` to decide whether a
   change was already rolled back, and the history view and the web UI
   list the entries, all without checking the chain. The check is
   `Store.verify_journal()`, which the `history` command prints as
   "Journal integrity (hash chain): OK / BROKEN" (exit code 5 when broken)
   and the web UI shows as a badge. Detection point is therefore the audit.
5. Pinned: netops-copilot 0.1.0 at d7e4ec0. Not on PyPI; install with
   pip install "netops-copilot @ git+https://github.com/gokunguru/netops-copilot@d7e4ec0".
   Without it the row and its tests are skipped.

A second state directory stands in for the second context (the public
demo gives each visitor a private lab directory). Erasure (T10) is the
tool's own `Store.reset()`, which removes the whole state directory: the
only erasure the store offers, so it is whole-context.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record

CTX = "lab-A"
OTHER = "lab-B"


class NetopsCopilotJournalAdapter(MemoryAdapter):
    """journal.jsonl as the store, Store.verify_journal() as the audit."""

    name = "netops-copilot-journal"
    supports_replay = True
    supports_metadata = True
    supports_snapshot = True
    supports_erase = True
    detection_point = "audit"

    def __init__(self):
        self._dir: str | None = None

    @staticmethod
    def measured_on() -> str:
        return "netops-copilot 0.1.0 at d7e4ec0"

    # --- lifecycle ---------------------------------------------------------

    def setup(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="agmi-netops-")

    def teardown(self) -> None:
        if self._dir:
            shutil.rmtree(self._dir, ignore_errors=True)
        self._dir = None

    def _root(self, ctx: str) -> Path:
        return Path(self._dir) / ctx

    def _store(self, ctx: str):
        from netops_copilot.changes import Store
        return Store(self._root(ctx))

    def _path(self, ctx: str) -> Path:
        return self._root(ctx) / "journal.jsonl"

    def _read(self, ctx: str) -> list[dict]:
        p = self._path(ctx)
        if not p.exists():
            return []
        return [json.loads(ln) for ln in p.read_text().splitlines() if ln.strip()]

    def _write(self, ctx: str, entries: list[dict]) -> None:
        self._root(ctx).mkdir(parents=True, exist_ok=True)
        self._path(ctx).write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in entries))

    # --- the tool's own write path ----------------------------------------

    def _entry(self, ctx: str, i: int) -> dict:
        value = (f"the ACL limit is {40 + i}" if ctx == CTX else f"the VLAN quota is {70 + i}")
        return {"type": "apply", "change": f"{(i + 1) if ctx == CTX else (i + 501):010x}",
                "operator": "agmi", "request": f"agmi-{ctx}-{i}: {value}",
                "devices": [f"r{i}"], "live": []}

    def seed(self, n: int) -> None:
        store = self._store(CTX)
        for i in range(n):
            store.append(self._entry(CTX, i))

    def seed_other(self, n: int) -> None:
        store = self._store(OTHER)
        for i in range(n):
            store.append(self._entry(OTHER, i))

    def append_genuine(self) -> None:
        store = self._store(CTX)
        store.append(self._entry(CTX, len(store.journal())))

    # --- raw access, bypassing the tool -----------------------------------

    def _read_ctx(self, ctx: str) -> list[Record]:
        return [Record(seq=i, fields={"ctx": ctx, "entry": e}) for i, e in enumerate(self._read(ctx))]

    def read_all_raw(self) -> list[Record]:
        return self._read_ctx(CTX)

    def read_other_raw(self) -> list[Record]:
        return self._read_ctx(OTHER)

    def write_raw(self, record: Record) -> None:
        entries = self._read(CTX)
        if record.seq < len(entries):
            entries[record.seq] = record.fields["entry"]
        else:
            entries.append(record.fields["entry"])
        self._write(CTX, entries)

    def delete_raw(self, seq: int) -> None:
        entries = self._read(CTX)
        if seq >= len(entries):
            raise IndexError(seq)
        del entries[seq]
        self._write(CTX, entries)

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        entries = self._read(CTX)
        entries[victim_seq] = json.loads(json.dumps(donor.fields["entry"]))
        self._write(CTX, entries)

    def read_meta(self, seq: int) -> dict:
        return {"time": self._read(CTX)[seq]["time"]}

    def write_meta(self, seq: int, meta: dict) -> None:
        # The entry's timestamp is its metadata; the hash is left as it was.
        entries = self._read(CTX)
        if meta.get("agmi_meta_tampered"):
            entries[seq]["time"] = "2030-01-01T00:00:00+00:00"
        elif "time" in meta:
            entries[seq]["time"] = meta["time"]
        self._write(CTX, entries)

    def mutate_payload(self, record: Record) -> Record:
        record = Record(seq=record.seq, fields=json.loads(json.dumps(record.fields)))
        record.fields["entry"]["request"] += "  [TAMPERED]"
        return record

    def forge_record(self, template: Record) -> Record:
        """An entry the tool never wrote, chained after the template.

        The chain has no key, so the attacker computes `prev` and `hash`
        exactly as Store.append() would."""
        forged = json.loads(json.dumps(template.fields["entry"]))
        forged.pop("hash", None)
        forged.update({"seq": forged["seq"] + 1, "change": "f0f0f0f0f0",
                       "request": "agmi-forged: the ACL limit is 999",
                       "prev": template.fields["entry"]["hash"]})
        forged["hash"] = hashlib.sha256(json.dumps(forged, sort_keys=True).encode()).hexdigest()
        return Record(seq=template.seq + 1, fields={"ctx": CTX, "entry": forged})

    # --- guard hooks (control C3) -----------------------------------------

    def identity_of(self, record):
        # The slot is the identity: a journal line is addressed by its
        # position in the file, which a replayed line takes over.
        return f"{record.fields['ctx']}:{record.seq}"

    def payload_of(self, record):
        return str(record.fields["entry"]["request"])

    def owner_of(self, record):
        return record.fields["ctx"]

    # --- T9 whole-store rollback, T10 erasure -----------------------------

    def snapshot_store(self):
        return self._copy_store(self._root(CTX))

    def restore_store(self, token) -> None:
        self._restore_store(token, self._root(CTX))
        shutil.rmtree(Path(token).parent, ignore_errors=True)

    def erase_genuine(self) -> list[str]:
        ids = [self.identity_of(r) for r in self.read_all_raw()]
        self._store(CTX).reset()
        return ids

    # --- the audit ----------------------------------------------------------

    def reload(self) -> None:
        return  # Store reads journal.jsonl on every call; nothing is cached

    def verify(self) -> bool:
        self.verify_detail = None
        if not self._store(CTX).verify_journal():
            self.verify_detail = "verify_journal: False (history prints 'Journal integrity (hash chain): BROKEN')"
            return False
        return True
