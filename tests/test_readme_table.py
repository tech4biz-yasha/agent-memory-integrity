# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""The at-rest table in README.md is written by hand. This test holds it to
results/scorecard.json cell for cell, so a row can never say one thing in the
README and another on the board. A new README row needs an entry in ROWS."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EDITS = ["tamper", "truncate", "delete_middle", "reorder", "forge", "cross_replay",
         "rollback_replay", "metadata_tamper", "snapshot_rollback", "erase_resurrect"]

# README row name -> results-file label
ROWS = {
    "LangGraph `SqliteSaver`": "langgraph-sqlite",
    "LangGraph `PostgresSaver`": "langgraph-postgres",
    "LangGraph `RedisSaver`": "langgraph-redis",
    "OpenAI Agents SDK `SQLiteSession`": "openai-agents-sqlite-session",
    "LlamaIndex `Memory` over SQLite": "llamaindex-memory-sqlite",
    "CrewAI long-term memory, LanceDB dataset": "crewai-ltm-lancedb",
    "Vertex AI Agent Engine Memory Bank, managed store, edits through the data-plane API":
        "vertex-memory-bank",
    "OpenClaw agent memory, `MEMORY.md` read through `memory_get`": "openclaw-memory-md",
    "Hermes Agent memory, `MEMORY.md` read through the system-prompt snapshot": "hermes-memory-md",
    "Letta core memory checkpoint history": "letta-block-history",
    "Mem0 local Qdrant store": "mem0-qdrant-local",
    "inspeximus, receipts off (default), read path": "inspeximus-default",
    "inspeximus, receipts on with a key, attacker holds the store's directory":
        "inspeximus-rcpt+dir",
    "inspeximus, receipts on with a key, attacker also holds the user's config home":
        "inspeximus-rcpt+dir+home",
    "langgraph-ledger over `SqliteSaver`, hash-chained ledger, `verify_thread()` audit":
        "langgraph-ledger",
    "memory-blackbox memory.md watcher, agent process alive, scan audit": "memory-blackbox-md",
    "memory-blackbox memory.md watcher, agent restarted before the scan, scan audit":
        "memory-blackbox-md+restart",
    "Atelya Attest, keyed hash chain, `verify_chain()` audit": "atelya-attest-chain",
    "Atelya Attest, keyed hash chain plus anchored head, verify and consistency audit":
        "atelya-attest-chain+anchor",
    "CONTINUUM event log, hash chain, `verify_events()` audit": "continuum-events",
    "CONTINUUM event log, hash chain plus Ed25519-signed head, attest-verify audit":
        "continuum-events+attest",
    "AtMem 2.3.8, audit chain alone, `verify()` audit": "atmem-chain",
    "AtMem 2.3.8, audit chain with an external checkpoint outside the attacker-controlled "
    "store directory, `verify()` audit": "atmem-chain+checkpoint",
    "acrf-memory-guard, per-entry HMAC over a JSON store, read path": "acrf-memory-guard",
    "MythologIQ Agent Memory reference runtime, SQLite canonical substrate, read path":
        "agent-memory",
    "AWS Bedrock AgentCore Memory, event plane, edits through the data-plane API":
        "bedrock-agentcore-events",
    "Surgical DevOps G7, signed envelopes bound to their storage position with an "
    "independent witness, read path": "surgical-devops-g7",
    "Recallspection ExactMemory, anchor beside the store on the same disk, read path":
        "recallspection-exact",
    "Recallspection ExactMemory, anchor off the store, read path":
        "recallspection-exact+anchor",
    "HDP token store, content-addressed reference, read path":
        "hdp-token-content-ref",
    "HDP token store, UUID reference, read path": "hdp-token-uuid",
    "Verax memory, keys and memory head inside the state directory (the default), read path":
        "verax-memory",
    "Verax memory, keys and memory head outside the state directory, read path":
        "verax-memory+head-outside",
}


def _table():
    text = (ROOT / "README.md").read_text()
    start = text.index("| Target | Version")
    block = text[start:text.index("\n\n", start)]
    return [[c.strip() for c in line.strip("|").split("|")] for line in block.splitlines()[2:]]


def test_every_readme_cell_matches_the_results_file():
    rows = {r["label"]: r for r in json.loads((ROOT / "results/scorecard.json").read_text())["rows"]}
    wrong = []
    for cells in _table():
        name, verdicts = cells[0], cells[2:]
        assert name in ROWS, f"README row not mapped in tests/test_readme_table.py: {name}"
        row = rows[ROWS[name]]
        for edit, got in zip(EDITS, verdicts):
            want = row["cells"].get(edit, {}).get("verdict") or "n/a"
            if got != want:
                wrong.append(f"{name} {edit}: README {got}, results {want}")
    assert not wrong, "\n".join(wrong)
