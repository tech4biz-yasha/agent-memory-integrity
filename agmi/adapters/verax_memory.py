# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Verax: an agent's memory in the gateway's state directory, read through memory.get.

Verax (npm `@verax-ai/body`, Apache-2.0) is an MCP server that sits between an
agent and its tools. Its memory tools are `memory.put` and `memory.get`; each
call passes Verax's policy gate and leaves a signed decision record.

The store is the state directory. One record is one memory item under its id:
the object file `tenants/<tenantKey>/memory/<id>/<revision>.json`, which holds
the content, its source and validity window, and `versionHash`, an unkeyed
SHA-256 over the tenant key, id, revision, content, source and validity window.
Beside the objects the store keeps `memory-commits.jsonl`, one
Ed25519-signed line per write chained by hash, and a signed memory head that
names the chain's last line. The tenant key is the SHA-256 of the token's issuer
and subject, so the two contexts here are two agents with two subjects.

The attacker reads and writes the state directory and signs nothing. Every edit
is made with the body stopped, as Section 6 requires. In the default layout the
key files sit inside that directory; these edits do not sign with them, and an
attacker who does is a different row.

Read path: `memory.get` over MCP. `verify()` starts one fresh Node process per
context; it starts the body with `listen` from the published package, reads the
ids of that context, and stops, so nothing in memory survives from before the
edit. `verify()` reads every id the
agent wrote through `memory.put` and every id present in the raw store. A
JSON-RPC error, or an error answer from `memory.get` other than not found, is a
refusal; the adapter does not check which error it is. The ones expected are a
`memory-integrity-*` code and a deny because the body halted after one. An id
that is on disk and that Verax answers as not found also counts as a refusal:
that is the adapter's reading, a record the store holds and will not serve. In
0.8.2 no measured cell rests on that rule; the forged object of T5, for one, is
answered `memory-integrity-unattested`. An id the agent wrote that is no longer
on disk, and that the store answers as never written, is not a refusal: that is
the store opening an older state as current.

The raw records are listed in the order of the signed commit chain, which the
adapter reads from `memory-commits.jsonl`. The record-level edits leave that
file untouched; T9 restores an older copy of the whole state directory, and the
chain file goes back with it. So T4 as this adapter runs it swaps the contents
of two object files and leaves the chain alone: the `reorder` cell is a content
swap, refused by the id and `versionHash` check, not a reorder of the signed
commit chain. T8 as agmi runs it adds a field to the object file; Verax accepts
an object file with its closed set of keys and nothing else, so the read
answers mismatch. That run does not change `source` or the validity window.

Two rows, because one deployment choice changes T9. By default the signing keys
and the memory head live in `keys/` inside the state directory, so a restored
copy of the directory brings its own older head. With `keysDir` outside it
(`verax-memory+head-outside`), the head is held off the store.

T10 is not evaluable: Verax's memory has no erase operation. Its memory tools
are memory.get and memory.put, and a record is replaced only by a newer revision.

The package is installed with npm into a directory named by AGMI_VERAX_DIR
(`npm install @verax-ai/body@0.8.2`); the adapter refuses any other version.
Node 22.6 or later, found on PATH or named by AGMI_NODE.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record

PIN = "0.8.2"
NODE_ENGINE = (22, 6, 0)
MEASURED_ON = f"@verax-ai/body {PIN} (npm)"
ISSUER = "https://agmi.invalid/verax"
AUDIENCE = "http://127.0.0.1/agmi-verax"
SUBJECTS = {"a": "agmi-agent-a", "b": "agmi-agent-b"}
UNTIL_MS = 4102444800000  # 2100-01-01, so no record expires during a run
CONTENT_KEYS = ("id", "revision", "tenantKey", "body", "versionHash")

HELPER = r"""
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { createRequire } from 'node:module';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const [, , veraxDir] = process.argv;
const req = createRequire(path.join(veraxDir, 'package.json'));
const { listen } = await import(pathToFileURL(req.resolve('@verax-ai/body')).href);
const input = JSON.parse(fs.readFileSync(0, 'utf8'));

const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwk = { ...publicKey.export({ format: 'jwk' }), alg: 'ES256', use: 'sig', kid: 'agmi' };
const jwks = http.createServer((q, s) => {
  if (q.url === '/jwks') {
    s.writeHead(200, { 'content-type': 'application/json' });
    s.end(JSON.stringify({ keys: [jwk] }));
    return;
  }
  s.writeHead(404);
  s.end();
});
await new Promise((resolve) => jwks.listen(0, '127.0.0.1', resolve));
const b64u = (b) => Buffer.from(b).toString('base64url');
function token(sub) {
  const now = Math.floor(Date.now() / 1000);
  const h = b64u(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid: 'agmi' }));
  const p = b64u(JSON.stringify({
    iss: input.issuer, aud: input.audience, sub, scope: 'verax:read verax:memory',
    iat: now, exp: now + 600, jti: randomUUID(),
  }));
  const sig = sign('sha256', Buffer.from(`${h}.${p}`), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${h}.${p}.${b64u(sig)}`;
}

const out = [];
let server = null;
try {
  server = await listen({
    issuer: input.issuer,
    jwksUrl: `http://127.0.0.1:${jwks.address().port}/jwks`,
    audience: input.audience,
    stateDir: input.stateDir,
    ...(input.keysDir ? { keysDir: input.keysDir } : {}),
    bindHost: '127.0.0.1',
    bindPort: 0,
    policyFile: input.policyFile,
    tlsTerminated: false,
  });
  const port = server.address().port;
  let rpc = 0;
  for (const op of input.ops) {
    const name = op.op === 'put' ? 'memory.put' : 'memory.get';
    const args = op.op === 'put'
      ? { id: op.id, body: { fact: op.fact }, source: { uri: op.src, retrievedAtMs: 1 }, validUntilMs: op.until }
      : { id: op.id };
    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token(op.sub)}`,
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++rpc, method: 'tools/call', params: { name, arguments: args } }),
    });
    const body = await res.json().catch(() => ({}));
    out.push({
      id: op.id,
      http: res.status,
      isError: body?.result?.isError === true,
      text: body?.result?.content?.[0]?.text ?? '',
      rpcError: body?.error ?? null,
    });
  }
} catch (e) {
  out.push({ fatal: String((e && e.stack) || e) });
} finally {
  if (server) {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(() => resolve()));
  }
  jwks.close();
}
process.stdout.write(JSON.stringify(out));
process.exit(0);
"""


def verax_dir() -> str | None:
    path = os.environ.get("AGMI_VERAX_DIR")
    return os.path.realpath(os.path.expanduser(path)) if path else None


def package_dir() -> Path:
    root = verax_dir()
    if not root:
        raise RuntimeError("AGMI_VERAX_DIR is not set (a directory with @verax-ai/body installed by npm)")
    pkg = Path(root) / "node_modules" / "@verax-ai" / "body"
    meta = json.loads((pkg / "package.json").read_text(encoding="utf-8"))
    if meta.get("version") != PIN:
        raise RuntimeError(f"@verax-ai/body {meta.get('version')} installed, pinned {PIN}; re-measure before re-pinning")
    return pkg


def node_binary() -> str:
    node = os.environ.get("AGMI_NODE") or shutil.which("node")
    if not node:
        raise RuntimeError("node not found; set AGMI_NODE")
    v = subprocess.run([node, "--version"], capture_output=True, text=True, check=True).stdout.strip().lstrip("v")
    if tuple(int(x) for x in v.split(".")[:3]) < NODE_ENGINE:
        raise RuntimeError(f"node {v} is below the engine @verax-ai/body declares (>=22.6.0)")
    return node


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256c(value) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def tenant_key(ctx: str) -> str:
    """Verax's tenant key: SHA-256 of the canonical {iss, sub}."""
    return _sha256c({"iss": ISSUER, "sub": SUBJECTS[ctx]})


def version_hash(obj: dict) -> str:
    """The unkeyed digest Verax stores in each object; anyone can compute it."""
    return _sha256c({
        "purpose": "verax.memory.v2",
        "hashSchema": 2,
        "tenantKey": obj["tenantKey"],
        "id": obj["id"],
        "revision": obj["revision"],
        "body": obj["body"],
        "source": obj["source"],
        "validFromMs": obj["validFromMs"],
        "validUntilMs": obj["validUntilMs"],
    })


class VeraxMemoryAdapter(MemoryAdapter):
    """Verax memory, keys and head in the state directory, read through memory.get."""

    name = "verax-memory"
    supports_replay = True
    supports_metadata = True
    supports_snapshot = True
    supports_erase = False
    erase_na_reason = ("Verax's memory has no erase operation: its memory tools are memory.get "
                       "and memory.put, and a record is replaced only by a newer revision")
    detection_point = "read"

    #: True holds the signing keys and the memory head outside the state directory.
    keys_outside = False

    def __init__(self):
        self._pkg = package_dir()
        self._node = node_binary()
        self._root: Path | None = None
        self._written: dict[str, list[str]] = {"a": [], "b": []}
        self._paths: list[Path] = []
        self._other_paths: list[Path] = []

    @staticmethod
    def measured_on() -> str:
        return MEASURED_ON

    # --- lifecycle ---------------------------------------------------------

    def setup(self) -> None:
        self._root = Path(tempfile.mkdtemp(prefix="agmi-verax-"))
        # Verax refuses a state or keys directory others can read (POSIX 0700).
        self._state().mkdir(mode=0o700)
        if self.keys_outside:
            self._keys().mkdir(mode=0o700)
        (self._root / "helper.mjs").write_text(HELPER, encoding="utf-8")
        self._written = {"a": [], "b": []}
        self._paths, self._other_paths = [], []

    def teardown(self) -> None:
        if self._root is not None:
            shutil.rmtree(self._root, ignore_errors=True)
            self._root = None

    def reload(self) -> None:
        """Every read already starts the body in a fresh process."""

    def _state(self) -> Path:
        assert self._root is not None
        return self._root / "state"

    def _keys(self) -> Path:
        assert self._root is not None
        return self._root / "keys"

    # --- the body, through the published package ----------------------------

    def _run(self, ops: list[dict]) -> list[dict]:
        policy = self._pkg.parent / "proxy" / "policy" / "default.json"
        payload = {
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "stateDir": str(self._state()),
            "keysDir": str(self._keys()) if self.keys_outside else None,
            "policyFile": str(policy),
            "ops": ops,
        }
        proc = subprocess.run([self._node, str(self._root / "helper.mjs"), verax_dir()],
                              input=json.dumps(payload), capture_output=True, text=True,
                              encoding="utf-8", timeout=180)
        try:
            out = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"helper printed no result: {proc.stderr.strip()[-300:]}") from exc
        for row in out:
            if "fatal" in row:
                raise RuntimeError(f"body did not start: {row['fatal'][:300]}")
        return out

    @staticmethod
    def _fact(ctx: str, i: int) -> str:
        return f"agmi-{ctx}-{i}: the limit is {40 + i}" if ctx == "a" else f"agmi-{ctx}-{i}: the quota is {70 + i}"

    def _put(self, ctx: str, indices: list[int]) -> None:
        ops = [{"op": "put", "sub": SUBJECTS[ctx], "id": f"{ctx}{i}", "fact": self._fact(ctx, i),
                "src": f"file://agmi/{ctx}/{i}", "until": UNTIL_MS} for i in indices]
        for row in self._run(ops):
            if row["isError"] or row["rpcError"]:
                raise RuntimeError(f"memory.put {row['id']} refused: {(row['text'] or row['rpcError'])!s:.200}")
        self._written[ctx].extend(f"{ctx}{i}" for i in indices)
        if not self._tenant_dir(ctx).is_dir():
            raise RuntimeError(f"no tenant directory for context {ctx}: tenant key derivation disagrees with Verax")

    # --- the agent's write path ---------------------------------------------

    def seed(self, n: int) -> None:
        self._put("a", list(range(1, n + 1)))

    def seed_other(self, n: int) -> None:
        self._put("b", list(range(1, n + 1)))

    def append_genuine(self) -> None:
        self._put("a", [len(self._written["a"]) + 1])

    # --- reading the raw store ----------------------------------------------

    def _tenant_dir(self, ctx: str) -> Path:
        return self._state() / "tenants" / tenant_key(ctx) / "memory"

    def _commit_order(self) -> dict[str, int]:
        """objectPath -> seq, from the signed commit chain the read path follows."""
        order: dict[str, int] = {}
        path = self._state() / "memory-commits.jsonl"
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    payload = json.loads(line)["payload"]
                    order[payload["objectPath"]] = int(payload["seq"])
                except (ValueError, KeyError, TypeError):
                    continue
        return order

    def _records(self, ctx: str) -> tuple[list[Record], list[Path]]:
        base = self._tenant_dir(ctx)
        files = sorted(base.glob("*/*.json")) if base.is_dir() else []
        order = self._commit_order()
        rel = lambda p: p.relative_to(self._state()).as_posix()  # noqa: E731
        files.sort(key=lambda p: (order.get(rel(p), float("inf")), rel(p)))
        records = []
        for seq, p in enumerate(files):
            rec = Record(seq=seq, fields=json.loads(p.read_text(encoding="utf-8")))
            rec._where = (ctx, p.parent.name, p.name)  # location, kept out of fields
            records.append(rec)
        return records, files

    def read_all_raw(self) -> list[Record]:
        records, self._paths = self._records("a")
        return records

    def read_other_raw(self) -> list[Record]:
        records, self._other_paths = self._records("b")
        return records

    # --- the attacker's edits -----------------------------------------------

    @staticmethod
    def _write(path: Path, fields: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(fields, separators=(",", ":"), ensure_ascii=False) + "\n", encoding="utf-8")

    def write_raw(self, record: Record) -> None:
        if record.seq < len(self._paths):
            path = self._paths[record.seq]
        else:
            path = self._tenant_dir("a") / str(record.fields["id"]) / f"{record.fields['revision']}.json"
        self._write(path, record.fields)

    def delete_raw(self, seq: int) -> None:
        if seq >= len(self._paths) or not self._paths[seq].exists():
            raise IndexError(f"no record at position {seq}")
        self._paths[seq].unlink()

    def mutate_payload(self, record: Record) -> Record:
        out = Record(seq=record.seq, fields=copy.deepcopy(record.fields))
        out._where = getattr(record, "_where", None)
        out.fields["body"]["fact"] = out.fields["body"]["fact"].replace("the limit is", "the limit is 9")
        return out

    def forge_record(self, template: Record) -> Record:
        """A new id in the store's format with the digest an attacker can compute; no signed commit."""
        t = template.fields
        obj = {
            "id": "a99",
            "revision": 1,
            "tenantKey": t["tenantKey"],
            "body": {"fact": "agmi-a-99: the limit is 1"},
            "source": copy.deepcopy(t["source"]),
            "validFromMs": t["validFromMs"],
            "validUntilMs": t["validUntilMs"],
        }
        obj["versionHash"] = version_hash(obj)
        ordered = {k: obj[k] for k in t if k in obj}
        ordered.update({k: v for k, v in obj.items() if k not in ordered})
        return Record(seq=len(self._paths), fields=ordered)

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        if victim_seq >= len(self._paths):
            raise IndexError(f"no record at position {victim_seq}")
        self._write(self._paths[victim_seq], copy.deepcopy(donor.fields))

    # --- metadata (T8) -------------------------------------------------------

    def read_meta(self, seq: int) -> dict:
        fields = json.loads(self._paths[seq].read_text(encoding="utf-8"))
        return {k: v for k, v in fields.items() if k not in CONTENT_KEYS}

    def write_meta(self, seq: int, meta: dict) -> None:
        fields = json.loads(self._paths[seq].read_text(encoding="utf-8"))
        fields.update(meta)
        self._write(self._paths[seq], fields)

    # --- identity, payload, owner -------------------------------------------

    def identity_of(self, record: Record) -> str:
        where = getattr(record, "_where", None)
        if where:
            return f"{where[1]}/{where[2]}"
        return f"{record.fields.get('id')}/{record.fields.get('revision')}.json"

    def payload_of(self, record: Record) -> str:
        return _canonical(record.fields.get("body"))

    def owner_of(self, record: Record) -> str | None:
        where = getattr(record, "_where", None)
        return where[0] if where else None

    # --- whole-store rollback (T9) ------------------------------------------

    def snapshot_store(self):
        return self._copy_store(self._state())

    def restore_store(self, token) -> None:
        self._restore_store(token, self._state())

    # --- the tool's answer ---------------------------------------------------

    @staticmethod
    def _answer(row: dict) -> tuple[str, str]:
        """(kind, text): kind is served, refused, absent."""
        text = row.get("text") or ""
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            data = {"raw": text}
        code = str(data.get("error") or data.get("raw") or "") if isinstance(data, dict) else ""
        if row.get("rpcError"):
            return "refused", f"rpc error {row['rpcError']}"[:200]
        if row.get("isError"):
            if "not-found" in code or "not found" in code.lower():
                return "absent", code
            return "refused", code[:200]
        if isinstance(data, dict) and data.get("found") is False:
            return "absent", "found: false"
        return "served", ""

    def verify(self) -> bool:
        """Read every id the agent wrote and every id in the raw store through memory.get."""
        self.verify_detail = None
        bad: list[str] = []
        for ctx in ("a", "b"):
            on_disk = sorted(p.name for p in self._tenant_dir(ctx).glob("*") if p.is_dir()) \
                if self._tenant_dir(ctx).is_dir() else []
            ids = list(dict.fromkeys(self._written[ctx] + on_disk))
            if not ids:
                continue
            rows = self._run([{"op": "get", "sub": SUBJECTS[ctx], "id": i} for i in ids])
            for row in rows:
                kind, text = self._answer(row)
                if kind == "refused":
                    bad.append(f"memory.get {row['id']}: {text}")
                elif kind == "absent" and row["id"] in on_disk:
                    bad.append(f"memory.get {row['id']}: not served ({text}) though the object is on disk")
        if bad:
            self.verify_detail = bad[0][:200]
            return False
        return True


class VeraxMemoryHeadOutsideAdapter(VeraxMemoryAdapter):
    """Verax memory with the signing keys and the memory head outside the state directory."""

    name = "verax-memory+head-outside"
    keys_outside = True

    @staticmethod
    def measured_on() -> str:
        return f"{MEASURED_ON}, keysDir outside the state directory"
