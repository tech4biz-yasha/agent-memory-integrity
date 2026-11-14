# Scorecard

Generated from the results file by `agmi.render`; do not edit by hand. Run of 2026-10-19 on Darwin x86_64, Python 3.12. Attack versions: tamper@v1, truncate@v1, delete_middle@v1, reorder@v1, forge@v1, cross_replay@v1, rollback_replay@v1, metadata_tamper@v1, snapshot_rollback@v1, erase_resurrect@v1, memory_injection@v3, cross_session_bleed@v2, retrieval_hijack@v4, indirect_prompt_injection@v3, update_poisoning@v1, metadata_poisoning@v1. Attacker levels: at-rest attacks assume store access (level 3); front-door attacks assume write access to the memory API (level 2); content-only attacks (level 1) are not in this table.

## Behind the back (at rest)

| Target | Checked at | tamper | truncate | delete middle | reorder | forge |
|---|---|---|---|---|---|---|
| openfang(model,fixed) | read | rejected | rejected | rejected | rejected | rejected |
| langgraph-sqlite | read | accepted | accepted | accepted | accepted | accepted |
| openai-agents-sqlite-session | read | accepted | accepted | accepted | accepted | accepted |
| llamaindex-memory-sqlite | read | accepted | accepted | accepted | accepted | accepted |
| crewai-ltm-lancedb | read | accepted | accepted | accepted | accepted | accepted |
| bedrock-agentcore-events | read | n/a | accepted | accepted | n/a | accepted |
| hermes-memory-md | read | accepted | accepted | accepted | accepted | accepted |
| mem0-qdrant-local | read | accepted | accepted | accepted | accepted | accepted |
| inspeximus-default | read | accepted | accepted | accepted | accepted | accepted |
| inspeximus-rcpt+dir | audit | reported | reported | reported | reported | reported |
| inspeximus-rcpt+dir+home | audit | reported | accepted | reported | reported | reported |
| langgraph-ledger | audit | reported | reported | reported | reported | accepted |
| memory-blackbox-md | audit | reported | reported | reported | reported | reported |
| memory-blackbox-md+restart | audit | reported | reported | reported | reported | reported |
| atelya-attest-chain | audit | reported | accepted | reported | reported | reported |
| atelya-attest-chain+anchor | audit | reported | reported | reported | reported | reported |
| continuum-events | audit | reported | accepted | reported | reported | reported |
| continuum-events+attest | audit | reported | reported | reported | reported | reported |
| recallspection-exact | read | rejected | rejected | rejected | rejected | rejected |
| recallspection-exact+anchor | read | rejected | rejected | rejected | rejected | rejected |
| hdp-token-content-ref | read | rejected | accepted | accepted | rejected | rejected |
| hdp-token-uuid | read | rejected | accepted | accepted | rejected | rejected |
| acrf-memory-guard | read | rejected | accepted | accepted | accepted | rejected |
| langgraph-postgres | read | accepted | accepted | accepted | accepted | accepted |
| langgraph-redis | read | accepted | accepted | accepted | accepted | accepted |
| vertex-memory-bank | read | accepted | accepted | accepted | n/a | accepted |
| openclaw-memory-md | read | accepted | accepted | accepted | accepted | accepted |
| letta-block-history | read | accepted | accepted | accepted | accepted | accepted |
| atmem-chain | audit | reported | reported | reported | reported | reported |
| atmem-chain+checkpoint | audit | reported | reported | reported | reported | reported |
| agent-memory | read | rejected | rejected | rejected | rejected | rejected |
| surgical-devops-g7 | read | rejected | rejected | rejected | rejected | rejected |
| verax-memory | read | rejected | rejected | rejected | rejected | rejected |
| verax-memory+head-outside | read | rejected | rejected | rejected | rejected | rejected |

## Through the front door

| Target | planted fact | cross-user leak | retrieval hijack | hidden instruction | false correction | self-tagged trust |
|---|---|---|---|---|---|---|
| inspeximus-default | surfaced | kept out | surfaced | surfaced | surfaced | surfaced |
| inspeximus-defended | surfaced | kept out | surfaced | surfaced | surfaced | surfaced |
| inspeximus-defended-key | surfaced | kept out | surfaced | surfaced | surfaced | surfaced |
| naive-mem(scoped) | surfaced | kept out | surfaced | surfaced | surfaced | surfaced |
| naive-mem(unscoped) | surfaced | surfaced | surfaced | surfaced | surfaced | surfaced |
| reference-defended(model) | surfaced | kept out | kept out | kept out | surfaced | surfaced |
| langgraph-sqlite-store | surfaced | kept out | surfaced | surfaced | surfaced | surfaced |
| letta-archival | surfaced | kept out | surfaced | surfaced | surfaced | n/a |

## Detail per cell

### openfang(model,fixed)

- `tamper`: rejected. detected on reload (hash mismatch at seq 2).
- `truncate`: rejected. detected on reload (walked tip differs from persisted tip).
- `delete_middle`: rejected. detected on reload (chain break at seq 3).
- `reorder`: rejected. detected on reload (chain break at seq 1).
- `forge`: rejected. detected on reload (chain break at seq 5).
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### langgraph-sqlite

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.
- `erase_resurrect`: accepted. the restored copy opened as current; the record the store had erased is served again without an error.

### openai-agents-sqlite-session

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.
- `erase_resurrect`: accepted. the restored copy opened as current; the record the store had erased is served again without an error.

### llamaindex-memory-sqlite

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.
- `erase_resurrect`: accepted. the restored copy opened as current; the record the store had erased is served again without an error.

### crewai-ltm-lancedb

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### bedrock-agentcore-events

Measured on: AWS Bedrock AgentCore Memory (events), boto3

- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `forge`: accepted. accepted silently.

### hermes-memory-md

Measured on: hermes-agent 0.19.0 (PyPI)

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### mem0-qdrant-local

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.
- `erase_resurrect`: accepted. the restored copy opened as current; the record the store had erased is served again without an error.

### inspeximus-default

Measured on: inspeximus 3.0.0, receipts off, recall defaults (lexical token overlap; mode=auto stays lexical below 300 memories), Darwin x86_64, Python 3.12

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.
- `memory_injection`: surfaced. planted memory served as trusted fact (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `cross_session_bleed`: kept out. user boundary held (cross-user: kept out 5 of 5).
- `retrieval_hijack`: surfaced. attacker entry took a slot from a genuine memory (external: 5 of 5, ranks 1, 1, 1, 1, 1 of 3; laundered: 5 of 5, ranks 1, 1, 1, 1, 1 of 3; agent-laundered: 5 of 5, ranks 1, 1, 1, 1, 1 of 3).
- `indirect_prompt_injection`: surfaced. instruction-shaped content delivered into context (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `update_poisoning`: surfaced. attacker's correction served for the user's question (external: 5 of 5, alongside, alongside, alongside, alongside, alongside; laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside; agent-laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside).
- `metadata_poisoning`: surfaced. self-tagged memory passed the trust filter (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).

### inspeximus-rcpt+dir

- `tamper`: reported. detected on reload (verify_writes: ['memory d4839ef63e: its TEXT or KEY no longer matches its write receipt (edited after write)']).
- `truncate`: reported. detected on reload (verify_writes: ['write log shrank below the head kept outside the store: 3 < 5 (rolled back or truncated, receipts included); a deliberate restore is accep).
- `delete_middle`: reported. detected on reload (verify_writes: ['receipt 2: broken chain link (a prior receipt was altered/removed)', 'write log shrank below the head kept outside the store: 4 < 5 (rolle).
- `reorder`: reported. detected on reload (verify_writes: ['memory 8dcb4a250e: its TEXT or KEY; its VALUE (`object`); WHEN the fact became true (`valid_from`), or where that time came from no longer).
- `forge`: reported. detected on reload (verify_writes: ["1 record(s) are covered by NO write receipt, so nothing here vouches for them: ['f093dddc76']. They were inserted out of band, or written ).
- `cross_replay`: reported. detected on reload (verify_writes: ['memory 5a13b5ce63: its TEXT or KEY; its VALUE (`object`); WHEN the fact became true (`valid_from`), or where that time came from no longer).
- `rollback_replay`: reported. detected on reload (verify_writes: ['memory 7e2318a0a4: its TEXT or KEY; its VALUE (`object`); WHEN the fact became true (`valid_from`), or where that time came from no longer).
- `metadata_tamper`: reported. detected on reload (verify_writes: ['memory fa1d3b5095: a field its receipt commits to no longer matches its write receipt (edited after write)']).
- `snapshot_rollback`: reported. the store noticed it was older than its last committed state (verify_writes: ['write log shrank below the head kept outside the store: 5 < 6 (rolled back or truncated, receipts included); a deliberate restore is accep).

### inspeximus-rcpt+dir+home

- `tamper`: reported. detected on reload (verify_writes: ['memory 49f1bff888: its TEXT or KEY no longer matches its write receipt (edited after write)']).
- `truncate`: accepted. accepted silently.
- `delete_middle`: reported. detected on reload (verify_writes: ['receipt 2: broken chain link (a prior receipt was altered/removed)']).
- `reorder`: reported. detected on reload (verify_writes: ['memory d3819196a8: its TEXT or KEY; its VALUE (`object`); WHEN the fact became true (`valid_from`), or where that time came from no longer).
- `forge`: reported. detected on reload (verify_writes: ["1 record(s) are covered by NO write receipt, so nothing here vouches for them: ['f0c1fddcb1']. They were inserted out of band, or written ).
- `cross_replay`: reported. detected on reload (verify_writes: ['memory 2865f74a4d: its TEXT or KEY; its VALUE (`object`); WHEN the fact became true (`valid_from`), or where that time came from no longer).
- `rollback_replay`: reported. detected on reload (verify_writes: ['memory 25cf51333b: its TEXT or KEY; its VALUE (`object`); WHEN the fact became true (`valid_from`), or where that time came from no longer).
- `metadata_tamper`: reported. detected on reload (verify_writes: ['memory 43b650b94d: a field its receipt commits to no longer matches its write receipt (edited after write)']).
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### inspeximus-defended

Measured on: inspeximus 3.0.0, receipts off, recall defaults (lexical token overlap; mode=auto stays lexical below 300 memories), trusted_only=True, provenance recorded as the memory's source, trust_seeds=['user'], Darwin x86_64, Python 3.12

- `memory_injection`: surfaced. planted memory served as trusted fact (external: kept out 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `cross_session_bleed`: kept out. user boundary held (cross-user: kept out 5 of 5).
- `retrieval_hijack`: surfaced. attacker entry took a slot from a genuine memory (external: kept out 5 of 5; laundered: 5 of 5, ranks 1, 1, 1, 1, 1 of 3; agent-laundered: 5 of 5, ranks 1, 1, 1, 1, 1 of 3).
- `indirect_prompt_injection`: surfaced. instruction-shaped content delivered into context (external: kept out 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `update_poisoning`: surfaced. attacker's correction served for the user's question (external: kept out 5 of 5; laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside; agent-laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside).
- `metadata_poisoning`: surfaced. self-tagged memory passed the trust filter (external: kept out 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).

### inspeximus-defended-key

Measured on: inspeximus 3.0.0, receipts off, recall defaults (lexical token overlap; mode=auto stays lexical below 300 memories), trusted_only=True, provenance recorded as the memory's source, signed writes attested with a per-user Ed25519 key and those keys seeded, Darwin x86_64, Python 3.12

- `memory_injection`: surfaced. planted memory served as trusted fact (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: 5 of 5).
- `cross_session_bleed`: kept out. user boundary held (cross-user: kept out 5 of 5).
- `retrieval_hijack`: surfaced. attacker entry took a slot from a genuine memory (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: 5 of 5, ranks 1, 1, 1, 1, 1 of 3).
- `indirect_prompt_injection`: surfaced. instruction-shaped content delivered into context (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: 5 of 5).
- `update_poisoning`: surfaced. attacker's correction served for the user's question (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside).
- `metadata_poisoning`: surfaced. self-tagged memory passed the trust filter (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: 5 of 5).

### langgraph-ledger

- `tamper`: reported. detected on reload (verify_thread: checkpoint content drifted: 1f1cbd58-84a8-6f0e-8002-4b126a9744d8).
- `truncate`: reported. detected on reload (verify_thread: checkpoint missing from saver: 1f1cbd58-84df-6072-8003-42290ca54ac2; checkpoint missing from saver: 1f1cbd58-84e1-62aa-8004-3ed75c094f42).
- `delete_middle`: reported. detected on reload (verify_thread: checkpoint missing from saver: 1f1cbd58-8513-64c6-8002-c257404a3bbd).
- `reorder`: reported. detected on reload (verify_thread: checkpoint content drifted: 1f1cbd58-8544-63b4-8001-3c4334c632b6; checkpoint content drifted: 1f1cbd58-8546-654c-8002-1d6d8b0f08bb).
- `forge`: accepted. accepted silently.
- `cross_replay`: reported. detected on reload (verify_thread: checkpoint content drifted: 1f1cbd58-85b9-6524-8004-a2612c7ae9c1).
- `rollback_replay`: reported. detected on reload (verify_thread: checkpoint content drifted: 1f1cbd58-85fc-669e-8004-c68bbed74f00).
- `metadata_tamper`: accepted. accepted silently.
- `snapshot_rollback`: reported. the store noticed it was older than its last committed state (verify_thread: checkpoint missing from saver: 1f1cbd58-867b-6ea8-8063-5753641c4e4c).
- `erase_resurrect`: accepted. the restored copy opened as current; the record the store had erased is served again without an error.

### memory-blackbox-md

- `tamper`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a154e0)).
- `truncate`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a154e0)).
- `delete_middle`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a154e0)).
- `reorder`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a154e0)).
- `forge`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a154e0)).
- `cross_replay`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a154e0)).
- `rollback_replay`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a154e0)).
- `metadata_tamper`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a154e0)).
- `snapshot_rollback`: reported. the store noticed it was older than its last committed state (scan recorded an out-of-band write to MEMORY.md (record 01a154e0)).

### memory-blackbox-md+restart

- `tamper`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a154e0)).
- `truncate`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a154e0)).
- `delete_middle`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a154e0)).
- `reorder`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a154e0)).
- `forge`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a154e0)).
- `cross_replay`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a154e0)).
- `rollback_replay`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a154e0)).
- `metadata_tamper`: reported. detected on reload (scan recorded an out-of-band write to MEMORY.md (record 01a154e0)).
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### atelya-attest-chain

- `tamper`: reported. detected on reload (verify_chain: seq=2: curr_hash mismatch (payload modified after attestation)).
- `truncate`: accepted. accepted silently.
- `delete_middle`: reported. detected on reload (verify_chain: seq=2: sequence gap/reorder: entry has seq=3, expected 2).
- `reorder`: reported. detected on reload (verify_chain: seq=1: sequence gap/reorder: entry has seq=2, expected 1).
- `forge`: reported. detected on reload (verify_chain: seq=5: prev_hash does not match previous curr_hash (deletion/reorder)).
- `cross_replay`: reported. detected on reload (verify_chain: seq=4: prev_hash does not match previous curr_hash (deletion/reorder)).
- `rollback_replay`: reported. detected on reload (verify_chain: seq=4: sequence gap/reorder: entry has seq=0, expected 4).
- `metadata_tamper`: reported. detected on reload (verify_chain: seq=2: curr_hash mismatch (payload modified after attestation)).
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### atelya-attest-chain+anchor

- `tamper`: reported. detected on reload (verify_chain: seq=2: curr_hash mismatch (payload modified after attestation)).
- `truncate`: reported. detected on reload (anchor: chain has 3 entries but checkpoint anchors seq=4 — history truncated/vanished below an anchored checkpoint).
- `delete_middle`: reported. detected on reload (verify_chain: seq=2: sequence gap/reorder: entry has seq=3, expected 2).
- `reorder`: reported. detected on reload (verify_chain: seq=1: sequence gap/reorder: entry has seq=2, expected 1).
- `forge`: reported. detected on reload (verify_chain: seq=5: prev_hash does not match previous curr_hash (deletion/reorder)).
- `cross_replay`: reported. detected on reload (verify_chain: seq=4: prev_hash does not match previous curr_hash (deletion/reorder)).
- `rollback_replay`: reported. detected on reload (verify_chain: seq=4: sequence gap/reorder: entry has seq=0, expected 4).
- `metadata_tamper`: reported. detected on reload (verify_chain: seq=2: curr_hash mismatch (payload modified after attestation)).
- `snapshot_rollback`: reported. the store noticed it was older than its last committed state (anchor: chain has 5 entries but checkpoint anchors seq=5 — history truncated/vanished below an anchored checkpoint).

### continuum-events

- `tamper`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=3 event_id='event_25d2992fcf35d0ddacad7e5c123c8663' detail='stored hash does not match recomputed digest').
- `truncate`: accepted. accepted silently.
- `delete_middle`: reported. detected on reload (verify_events: kind='SEQUENCE_GAP' run_id='agmi-run-A' sequence=4 event_id='event_0763e7119ceccee45cf7e8d647f6a06f' detail='expected sequence 3').
- `reorder`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=2 event_id='event_0c469d4b61bd407bcf64d99ca20ea814' detail='stored hash does not match recomputed digest').
- `forge`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=6 event_id='event_agmiforged000000000000000000' detail='stored hash does not match recomputed digest').
- `cross_replay`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=5 event_id='event_96f58bcab976019008af1d216befa588' detail='stored hash does not match recomputed digest').
- `rollback_replay`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=5 event_id='event_ffd0fda230015841cb787a3422d286f1' detail='stored hash does not match recomputed digest').
- `metadata_tamper`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=3 event_id='event_a656460d68bcc0d473a4cbefa46a1e69' detail='stored hash does not match recomputed digest').
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### continuum-events+attest

- `tamper`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=3 event_id='event_fe6189bc355e3c357fc12eefbc560f0e' detail='stored hash does not match recomputed digest').
- `truncate`: reported. detected on reload (attest-verify: ALTERED (signed seq 5, live seq 3)).
- `delete_middle`: reported. detected on reload (verify_events: kind='SEQUENCE_GAP' run_id='agmi-run-A' sequence=4 event_id='event_8de5387f2f0af7aa2f3eceba50e93e39' detail='expected sequence 3').
- `reorder`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=2 event_id='event_746df41d1ba4b965f4906c234821ef29' detail='stored hash does not match recomputed digest').
- `forge`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=6 event_id='event_agmiforged000000000000000000' detail='stored hash does not match recomputed digest').
- `cross_replay`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=5 event_id='event_d2ade5c8cc0535e47299494f90aaa02b' detail='stored hash does not match recomputed digest').
- `rollback_replay`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=5 event_id='event_72cd73ec051cd6e9b68e8e934f1cfe9d' detail='stored hash does not match recomputed digest').
- `metadata_tamper`: reported. detected on reload (verify_events: kind='TAMPERED_CONTENT' run_id='agmi-run-A' sequence=3 event_id='event_90da6d3af1e4ea5be7ff1517e3a93366' detail='stored hash does not match recomputed digest').
- `snapshot_rollback`: reported. the store noticed it was older than its last committed state (attest-verify: ALTERED (signed seq 6, live seq 5)).

### recallspection-exact

Measured on: exactmemory.recallspection 3.2.0 at c62ef7a

- `tamper`: rejected. detected on reload (TamperError: Container MAC failed).
- `truncate`: rejected. detected on reload (TamperError: Container MAC failed).
- `delete_middle`: rejected. detected on reload (TamperError: Container MAC failed).
- `reorder`: rejected. detected on reload (TamperError: Container MAC failed).
- `forge`: rejected. detected on reload (TamperError: Container MAC failed).
- `cross_replay`: rejected. detected on reload (TamperError: Container MAC failed).
- `rollback_replay`: rejected. detected on reload (TamperError: Container MAC failed).
- `metadata_tamper`: rejected. detected on reload (TamperError: Container MAC failed).
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.
- `erase_resurrect`: accepted. the restored copy opened as current; the record the store had erased is served again without an error.

### recallspection-exact+anchor

Measured on: exactmemory.recallspection 3.2.0 at c62ef7a

- `tamper`: rejected. detected on reload (TamperError: Container MAC failed).
- `truncate`: rejected. detected on reload (TamperError: Container MAC failed).
- `delete_middle`: rejected. detected on reload (TamperError: Container MAC failed).
- `reorder`: rejected. detected on reload (TamperError: Container MAC failed).
- `forge`: rejected. detected on reload (TamperError: Container MAC failed).
- `cross_replay`: rejected. detected on reload (TamperError: Container MAC failed).
- `rollback_replay`: rejected. detected on reload (TamperError: Container MAC failed).
- `metadata_tamper`: rejected. detected on reload (TamperError: Container MAC failed).
- `snapshot_rollback`: rejected. the store noticed it was older than its last committed state (RollbackError: Log rollback vs remote anchor: log 5 < remote 6).
- `erase_resurrect`: rejected. the store noticed that a record it had erased was back (RollbackError: Log rollback vs remote anchor: log 5 < remote 6).

### hdp-token-content-ref

Measured on: @helixar_ai/hdp 0.2.2 at b753ba9, Node 22

- `tamper`: rejected. detected on reload (resolve: TokenReferenceIntegrityError: TOKEN_REFERENCE_INTEGRITY: content reference digest mismatch: expected 'sha256:oPLcm4W6NLezyPjRkx9KR_oyi_cWoY4M1M5-0mDtjbg', got 'sha256:Y5hgerTZMUOVLgxLq_OoRcyx).
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: rejected. detected on reload (resolve: TokenReferenceIntegrityError: TOKEN_REFERENCE_INTEGRITY: content reference digest mismatch: expected 'sha256:yq40jYFM0QMlJOTdlxbqFTFuaMDL1EUgKRIpBy7dkD0', got 'sha256:Ut_cb3s6iYWuZ47zoQb0H2MN).
- `forge`: rejected. detected on reload (verify: verifyToken failed at step 2: Signature invalid: root signature verification failed).
- `cross_replay`: rejected. detected on reload (resolve: TokenReferenceIntegrityError: TOKEN_REFERENCE_INTEGRITY: content reference digest mismatch: expected 'sha256:ZXLuOiKGTvM-RQHi1qN6hJEbHMpt9Se5jEPJ1SQGQrQ', got 'sha256:ENqncJC1sMC_aMOT-J96p9p2).
- `rollback_replay`: rejected. detected on reload (resolve: TokenReferenceIntegrityError: TOKEN_REFERENCE_INTEGRITY: content reference digest mismatch: expected 'sha256:Uf40Q9684qZOkLg2uWMv4Uerdj5azUWTK9Be8pQWTBg', got 'sha256:puL15rPCS9opMJ7bsTdvPsNt).
- `metadata_tamper`: rejected. detected on reload (resolve: TokenReferenceIntegrityError: TOKEN_REFERENCE_INTEGRITY: content reference digest mismatch: expected 'sha256:ITQlm4SeBkxCWAdRjkKQH3BRQ_9A1laIE3cBTw4DzFM', got 'sha256:sQACWE2XzRF2W1oDNFn6CQBS).
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### hdp-token-uuid

Measured on: @helixar_ai/hdp 0.2.2 at b753ba9, Node 22

- `tamper`: rejected. detected on reload (verify: verifyToken failed at step 4: Signature invalid: hop 1 signature verification failed).
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: rejected. detected on reload (resolve: TokenReferenceIntegrityError: TOKEN_REFERENCE_INTEGRITY: UUID reference '4df0b20a-a8b7-47b7-85e2-0deb37de4da6' resolved to token_id 'f9796c5b-653a-40f1-a410-34db3b1ca9a3').
- `forge`: rejected. detected on reload (verify: verifyToken failed at step 2: Signature invalid: root signature verification failed).
- `cross_replay`: rejected. detected on reload (resolve: TokenReferenceIntegrityError: TOKEN_REFERENCE_INTEGRITY: UUID reference 'eddd51f8-805b-4fb0-b41c-cb416ac6d508' resolved to token_id 'a7584276-a5a9-44ce-a030-e207914d61e0').
- `rollback_replay`: rejected. detected on reload (resolve: TokenReferenceIntegrityError: TOKEN_REFERENCE_INTEGRITY: UUID reference '67755c2a-b2c6-4e87-961a-40bea73d1157' resolved to token_id 'e63399e9-2936-4b00-bd59-7b1dbb0e7cd3').
- `metadata_tamper`: rejected. detected on reload (verify: verifyToken failed at step 2: Signature invalid: root signature verification failed).
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### acrf-memory-guard

- `tamper`: rejected. detected on reload (read_safe(ctx-A::02): Memory integrity check failed. Expected: sha256:7ca88280bdf5e6a1a715919b1... Got: sha256:681acbfb71f740e3ffc1a7d4f... Entry was modified after signing.).
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: rejected. detected on reload (read_safe(ctx-A::05): Memory integrity check failed. Expected: sha256:d457917a206a2ddf118409db8... Got: sha256:76f303877bda01a1960075e50... Entry was modified after signing.).
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: rejected. detected on reload (read_safe(ctx-A::02): Memory integrity check failed. Expected: sha256:b5b81806feb911b5e4afe6dca... Got: sha256:681acbfb71f740e3ffc1a7d4f... Entry was modified after signing.).
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### naive-mem(scoped)

Measured on: reference store, token-overlap ranking, no defences

- `memory_injection`: surfaced. planted memory served as trusted fact (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `cross_session_bleed`: kept out. user boundary held (cross-user: kept out 5 of 5).
- `retrieval_hijack`: surfaced. attacker entry took a slot from a genuine memory (external: 5 of 5, ranks 1, 1, 1, 1, 1 of 3; laundered: 5 of 5, ranks 1, 1, 1, 1, 1 of 3; agent-laundered: 5 of 5, ranks 1, 1, 1, 1, 1 of 3).
- `indirect_prompt_injection`: surfaced. instruction-shaped content delivered into context (external: 4 of 5; laundered: 4 of 5; agent-laundered: 4 of 5).
- `update_poisoning`: surfaced. attacker's correction served for the user's question (external: 5 of 5, alongside, alongside, alongside, alongside, alongside; laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside; agent-laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside).
- `metadata_poisoning`: surfaced. self-tagged memory passed the trust filter (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).

### naive-mem(unscoped)

Measured on: reference store, token-overlap ranking, no defences

- `memory_injection`: surfaced. planted memory served as trusted fact (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `cross_session_bleed`: surfaced. user A memory served to user B (cross-user: 5 of 5).
- `retrieval_hijack`: surfaced. attacker entry took a slot from a genuine memory (external: 5 of 5, ranks 1, 1, 1, 1, 1 of 3; laundered: 5 of 5, ranks 1, 1, 1, 1, 1 of 3; agent-laundered: 5 of 5, ranks 1, 1, 1, 1, 1 of 3).
- `indirect_prompt_injection`: surfaced. instruction-shaped content delivered into context (external: 4 of 5; laundered: 4 of 5; agent-laundered: 4 of 5).
- `update_poisoning`: surfaced. attacker's correction served for the user's question (external: 5 of 5, alongside, alongside, alongside, alongside, alongside; laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside; agent-laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside).
- `metadata_poisoning`: surfaced. self-tagged memory passed the trust filter (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).

### reference-defended(model)

Measured on: reference store with signed-write provenance, write-time quarantine of instruction-shaped records and a stuffing check; token-overlap ranking

- `memory_injection`: surfaced. planted memory served as trusted fact (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: 5 of 5).
- `cross_session_bleed`: kept out. user boundary held (cross-user: kept out 5 of 5).
- `retrieval_hijack`: kept out. every slot went to a genuine memory (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: kept out 5 of 5).
- `indirect_prompt_injection`: kept out. no instruction reached context (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: kept out 5 of 5).
- `update_poisoning`: surfaced. attacker's correction served for the user's question (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside).
- `metadata_poisoning`: surfaced. self-tagged memory passed the trust filter (external: kept out 5 of 5; laundered: kept out 5 of 5; agent-laundered: 5 of 5).

### langgraph-postgres

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### langgraph-redis

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### vertex-memory-bank

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.

### openclaw-memory-md

Measured on: openclaw 2026.10.1 from npm, read through its memory_get function in a fresh Node process per read; Linux x86_64 with Node 24.21.0, reproduced on macOS arm64 with Node 26.11.0

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### langgraph-sqlite-store

Measured on: langgraph-checkpoint-sqlite 3.1.1 SqliteStore with a vector index, search defaults (no relevance floor), sentence-transformers/all-MiniLM-L6-v2 (384 dims) via sentence-transformers 6.1.0, Darwin arm64, Python 3.12

- `memory_injection`: surfaced. planted memory served as trusted fact (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `cross_session_bleed`: kept out. user boundary held (cross-user: kept out 5 of 5).
- `retrieval_hijack`: surfaced. attacker entry took a slot from a genuine memory (external: 5 of 5, ranks 2, 3, 1, 2, 1 of 3; laundered: 4 of 5, ranks 2, out, 1, 2, 1 of 3; agent-laundered: 5 of 5, ranks 2, 3, 1, 2, 2 of 3).
- `indirect_prompt_injection`: surfaced. instruction-shaped content delivered into context (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `update_poisoning`: surfaced. attacker's correction served for the user's question (external: 5 of 5, alongside, alongside, alongside, alongside, alongside; laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside; agent-laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside).
- `metadata_poisoning`: surfaced. self-tagged memory passed the trust filter (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).

### letta-block-history

- `tamper`: accepted. accepted silently.
- `truncate`: accepted. accepted silently.
- `delete_middle`: accepted. accepted silently.
- `reorder`: accepted. accepted silently.
- `forge`: accepted. accepted silently.
- `cross_replay`: accepted. accepted silently.
- `rollback_replay`: accepted. accepted silently.
- `metadata_tamper`: accepted. accepted silently.
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### letta-archival

Measured on: letta 0.16.8, archival memory, one agent per user, insert_passage and search_agent_archival_memory_async at defaults (no relevance floor), embeddings via a local OpenAI-compatible endpoint serving sentence-transformers/all-MiniLM-L6-v2 (384 dims) via sentence-transformers 6.1.0, Darwin arm64, Python 3.12

- `memory_injection`: surfaced. planted memory served as trusted fact (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `cross_session_bleed`: kept out. user boundary held (cross-user: kept out 5 of 5).
- `retrieval_hijack`: surfaced. attacker entry took a slot from a genuine memory (external: 4 of 5, ranks 2, 2, 1, out, 3 of 3; laundered: 4 of 5, ranks 2, 2, 1, out, 3 of 3; agent-laundered: 4 of 5, ranks 2, 2, 1, out, 3 of 3).
- `indirect_prompt_injection`: surfaced. instruction-shaped content delivered into context (external: 5 of 5; laundered: 5 of 5; agent-laundered: 5 of 5).
- `update_poisoning`: surfaced. attacker's correction served for the user's question (external: 5 of 5, alongside, alongside, alongside, alongside, alongside; laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside; agent-laundered: 5 of 5, alongside, alongside, alongside, alongside, alongside).

### atmem-chain

Measured on: atmem 2.3.8 from PyPI (wheel SHA-256 05ca2c57), remeasured 2026-10-10 on Darwin arm64 and Linux x86_64, Python 3.12

- `tamper`: reported. detected on reload (verify: record row does not match its chained integrity commitment).
- `truncate`: reported. detected on reload (verify: record committed by the audit chain is missing).
- `delete_middle`: reported. detected on reload (verify: record committed by the audit chain is missing).
- `reorder`: reported. detected on reload (verify: record row does not match its chained integrity commitment).
- `forge`: reported. detected on reload (verify: record has no creation event in the audit chain).
- `cross_replay`: reported. detected on reload (verify: record row does not match its chained integrity commitment).
- `rollback_replay`: reported. detected on reload (verify: record row does not match its chained integrity commitment).
- `metadata_tamper`: reported. detected on reload (verify: record row does not match its chained integrity commitment).
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### atmem-chain+checkpoint

Measured on: atmem 2.3.8 from PyPI (wheel SHA-256 05ca2c57), remeasured 2026-10-10 on Darwin arm64 and Linux x86_64, Python 3.12

- `tamper`: reported. detected on reload (verify: record row does not match its chained integrity commitment).
- `truncate`: reported. detected on reload (verify: record committed by the audit chain is missing).
- `delete_middle`: reported. detected on reload (verify: record committed by the audit chain is missing).
- `reorder`: reported. detected on reload (verify: record row does not match its chained integrity commitment).
- `forge`: reported. detected on reload (verify: record has no creation event in the audit chain).
- `cross_replay`: reported. detected on reload (verify: record row does not match its chained integrity commitment).
- `rollback_replay`: reported. detected on reload (verify: record row does not match its chained integrity commitment).
- `metadata_tamper`: reported. detected on reload (verify: record row does not match its chained integrity commitment).
- `snapshot_rollback`: reported. the store noticed it was older than its last committed state (verify: pinned event at sequence 17 is missing (tail truncated?)).

### agent-memory

- `tamper`: rejected. detected on reload (RuntimeRecoveryError: SQLite canonical substrate digest mismatch).
- `truncate`: rejected. detected on reload (RuntimeRecoveryError: SQLite canonical substrate digest mismatch).
- `delete_middle`: rejected. detected on reload (RuntimeRecoveryError: SQLite canonical substrate digest mismatch).
- `reorder`: rejected. detected on reload (RuntimeRecoveryError: SQLite canonical substrate digest mismatch).
- `forge`: rejected. detected on reload (RuntimeRecoveryError: SQLite canonical substrate digest mismatch).
- `cross_replay`: rejected. detected on reload (RuntimeRecoveryError: SQLite canonical substrate digest mismatch).
- `rollback_replay`: rejected. detected on reload (RuntimeRecoveryError: SQLite canonical substrate digest mismatch).
- `metadata_tamper`: rejected. detected on reload (RuntimeRecoveryError: SQLite canonical substrate digest mismatch).
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### surgical-devops-g7

Measured on: surgical-dev-ops 2.6.0-rc.6 at f267cf38, Node v24.18.0

- `tamper`: rejected. detected on reload (Error: Store-integrity payload digest mismatch.).
- `truncate`: rejected. detected on reload (Error: G7 whole-store root does not match the independent monotonic witness.).
- `delete_middle`: rejected. detected on reload (Error: G7 whole-store root does not match the independent monotonic witness.).
- `reorder`: rejected. detected on reload (Error: Persisted G7 authorization record does not match its requested storage position.).
- `forge`: rejected. detected on reload (Error: Store-integrity payload digest mismatch.).
- `cross_replay`: rejected. detected on reload (Error: Persisted G7 store-integrity envelope context binding mismatch.).
- `rollback_replay`: rejected. detected on reload (Error: Persisted G7 authorization record does not match its requested storage position.).
- `metadata_tamper`: rejected. detected on reload (Error: Store-integrity envelope contains missing or unknown fields.).
- `snapshot_rollback`: rejected. the store noticed it was older than its last committed state (Error: G7 whole-store root does not match the independent monotonic witness.).

### verax-memory

Measured on: macOS, Python 3.12, Node v22.23.5, @verax-ai/body 0.8.2, 2026-11-14

- `tamper`: rejected. detected on reload (memory.get a3: memory-integrity-mismatch).
- `truncate`: rejected. detected on reload (memory.get a4: memory-integrity-missing).
- `delete_middle`: rejected. detected on reload (memory.get a3: memory-integrity-missing).
- `reorder`: rejected. detected on reload (memory.get a2: memory-integrity-mismatch).
- `forge`: rejected. detected on reload (memory.get a99: memory-integrity-unattested).
- `cross_replay`: rejected. detected on reload (memory.get a5: memory-integrity-mismatch).
- `rollback_replay`: rejected. detected on reload (memory.get a5: memory-integrity-mismatch).
- `metadata_tamper`: rejected. detected on reload (memory.get a3: memory-integrity-mismatch).
- `snapshot_rollback`: accepted. the older copy opened as current; the newest genuine record is gone without an error.

### verax-memory+head-outside

Measured on: macOS, Python 3.12, Node v22.23.5, @verax-ai/body 0.8.2, 2026-11-14

- `tamper`: rejected. detected on reload (memory.get a3: memory-integrity-mismatch).
- `truncate`: rejected. detected on reload (memory.get a4: memory-integrity-missing).
- `delete_middle`: rejected. detected on reload (memory.get a3: memory-integrity-missing).
- `reorder`: rejected. detected on reload (memory.get a2: memory-integrity-mismatch).
- `forge`: rejected. detected on reload (memory.get a99: memory-integrity-unattested).
- `cross_replay`: rejected. detected on reload (memory.get a5: memory-integrity-mismatch).
- `rollback_replay`: rejected. detected on reload (memory.get a5: memory-integrity-mismatch).
- `metadata_tamper`: rejected. detected on reload (memory.get a3: memory-integrity-mismatch).
- `snapshot_rollback`: rejected. the store noticed it was older than its last committed state (memory.get a1: memory-integrity-history-unavailable).
