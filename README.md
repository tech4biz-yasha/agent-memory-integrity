<p align="center">
  <img src="docs/logo.svg" width="96" alt="agmi">
</p>

<h1 align="center">agmi</h1>
<p align="center"><strong>Agent Memory Integrity</strong><br>
A conformance test suite that measures whether AI agent memory and checkpoint stores notice when they are tampered with.</p>

<p align="center">
  <a href="https://github.com/tech4biz-yasha/agmi/actions/workflows/scorecard.yml"><img src="https://github.com/tech4biz-yasha/agmi/actions/workflows/scorecard.yml/badge.svg" alt="scorecard"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="python">
  <img src="https://img.shields.io/badge/stores%20measured-26-green.svg" alt="stores measured">
</p>

[![Method paper DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22995111.svg)](https://doi.org/10.5281/zenodo.22995111)
[![SSRN](https://img.shields.io/badge/SSRN-7461118-blue)](https://ssrn.com/abstract=7461118)
[![Software DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22860886.svg)](https://doi.org/10.5281/zenodo.22860886)
[![PyPI](https://img.shields.io/pypi/v/agent-memory-integrity)](https://pypi.org/project/agent-memory-integrity/)
[![Website](https://img.shields.io/badge/site-agentmemoryintegrity.org-0F4C5C)](https://agentmemoryintegrity.org/)

---

## The result in one table

Twenty-six agent memory and checkpoint stores were seeded through their own APIs, edited behind their backs, and asked to read their memory again. The twelve that make no integrity claim, all three official LangGraph checkpointers, Google's managed Memory Bank, the event plane of AWS Bedrock AgentCore Memory and the memory of the OpenClaw and Hermes agents among them, served every applicable edit as genuine. The fourteen that do make a claim were measured against it, and the table shows exactly where each one holds and where it stops. The MythologIQ Agent Memory reference runtime was the first row to refuse all eight record-level edits on the read path; Surgical DevOps G7 is the first to refuse all nine there, including a whole-store rollback.

The ten edits: T1 content tamper, T2 tail truncation, T3 middle deletion, T4 reordering, T5 forged insertion, T6 cross-context replay, T7 rollback replay, T8 metadata tamper, T9 snapshot rollback, which restores an older complete copy of the store after one more genuine record was written through the tool's own API, and T10 erasure resurrection, in which the tool erases through its own API and the attacker restores the pre-erasure copy. T1 to T8 are the edits proposed as the test method for IETF draft-han-bmwg-agent-security-benchmark metric 5.4.7 and defined in draft-khandelwal-bmwg-agent-memory-integrity. T6, T7 and T9 use only bytes the store itself wrote, in the wrong place or at the wrong time; they are the edits that separate encryption from integrity, and T9 is the one that separates a stored head from an anchored one: a head kept beside the records rolls back with them. A store that catches T9 can still miss T10: a ledger of what must be present says nothing about what must be gone, and the LangGraph ledger row shows exactly that. T9 and T10 are measured where the adapter has the hooks; an n/a cell means not measured, not a pass.

| Target | Version | T1 | T2 | T3 | T4 | T5 | T6 | T7 | T8 | T9 | T10 |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| LangGraph `SqliteSaver` | langgraph-checkpoint-sqlite 3.1.1 | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted |
| LangGraph `PostgresSaver` | langgraph-checkpoint-postgres 3.1.2 on PostgreSQL 16 | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | n/a |
| LangGraph `RedisSaver` | langgraph-checkpoint-redis 0.5.2 on Redis 8 | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | n/a |
| OpenAI Agents SDK `SQLiteSession` | openai-agents 0.20.0 | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted |
| LlamaIndex `Memory` over SQLite | llama-index-core 0.14.24 | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted |
| CrewAI long-term memory, LanceDB dataset | crewai 1.15.23 | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | n/a |
| Vertex AI Agent Engine Memory Bank, managed store, edits through the data-plane API | google-cloud-aiplatform 2.4.0 | accepted | accepted | accepted | n/a | accepted | accepted | accepted | accepted | n/a | n/a |
| OpenClaw agent memory, `MEMORY.md` read through `memory_get` | openclaw 2026.10.1 | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | n/a |
| Hermes Agent memory, `MEMORY.md` read through the system-prompt snapshot | hermes-agent 0.19.0 | accepted | accepted | accepted | accepted | accepted | accepted | accepted | n/a | accepted | n/a |
| AWS Bedrock AgentCore Memory, event plane, edits through the data-plane API | AgentCore Memory (events), us-east-1 | n/a | accepted | accepted | n/a | accepted | n/a | n/a | n/a | n/a | n/a |
| Letta core memory checkpoint history | letta 0.16.8 | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | n/a |
| Mem0 local Qdrant store | mem0ai 2.0.20 | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted |
| inspeximus, receipts off (default), read path | inspeximus 3.0.0 | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | accepted | n/a |
| inspeximus, receipts on with a key, attacker holds the store's directory | inspeximus 3.0.0 | reported | reported | reported | reported | reported | reported | reported | reported | reported | n/a |
| inspeximus, receipts on with a key, attacker also holds the user's config home | inspeximus 3.0.0 | reported | accepted | reported | reported | reported | reported | reported | reported | accepted | n/a |
| langgraph-ledger over `SqliteSaver`, hash-chained ledger, `verify_thread()` audit | langgraph-ledger 0.3.0 | reported | reported | reported | reported | accepted | reported | reported | accepted | reported | accepted |
| memory-blackbox memory.md watcher, agent process alive, scan audit | memory-blackbox 0.1.1 | reported | reported | reported | reported | reported | reported | reported | reported | reported | n/a |
| memory-blackbox memory.md watcher, agent restarted before the scan, scan audit | memory-blackbox 0.1.1 (0.1.0 served all eight) | reported | reported | reported | reported | reported | reported | reported | reported | accepted | n/a |
| Atelya Attest, keyed hash chain, `verify_chain()` audit | atelya-attest 0.1.1 | reported | accepted | reported | reported | reported | reported | reported | reported | accepted | n/a |
| Atelya Attest, keyed hash chain plus anchored head, verify and consistency audit | atelya-attest 0.1.1 | reported | reported | reported | reported | reported | reported | reported | reported | reported | n/a |
| CONTINUUM event log, hash chain, `verify_events()` audit | continuum-agent 0.1.0 | reported | accepted | reported | reported | reported | reported | reported | reported | accepted | n/a |
| CONTINUUM event log, hash chain plus Ed25519-signed head, attest-verify audit | continuum-agent 0.1.0 | reported | reported | reported | reported | reported | reported | reported | reported | reported | n/a |
| AtMem 2.3.8, audit chain alone, `verify()` audit | atmem 2.3.8 | reported | reported | reported | reported | reported | reported | reported | reported | accepted | n/a |
| AtMem 2.3.8, audit chain with an external checkpoint outside the attacker-controlled store directory, `verify()` audit | atmem 2.3.8 | reported | reported | reported | reported | reported | reported | reported | reported | reported | n/a |
| acrf-memory-guard, per-entry HMAC over a JSON store, read path | acrf-memory-guard 0.1.0 | rejected | accepted | accepted | accepted | rejected | accepted | accepted | rejected | accepted | n/a |
| MythologIQ Agent Memory reference runtime, SQLite canonical substrate, read path | agent-memory-reference 0.2.0 at f2aef57 | rejected | rejected | rejected | rejected | rejected | rejected | rejected | rejected | accepted | n/a |
| Surgical DevOps G7, signed envelopes bound to their storage position with an independent witness, read path | surgical-dev-ops 2.6.0-rc.6 on Node v24.18.0 | rejected | rejected | rejected | rejected | rejected | rejected | rejected | rejected | rejected | n/a |
| Recallspection ExactMemory, anchor beside the store on the same disk, read path | exactmemory.recallspection 3.2.0 | rejected | rejected | rejected | rejected | rejected | rejected | rejected | rejected | accepted | accepted |
| Recallspection ExactMemory, anchor off the store, read path | exactmemory.recallspection 3.2.0 | rejected | rejected | rejected | rejected | rejected | rejected | rejected | rejected | rejected | rejected |
| HDP token store, content-addressed reference, read path | @helixar_ai/hdp 0.2.2 on Node 22 | rejected | accepted | accepted | rejected | rejected | rejected | rejected | rejected | accepted | n/a |
| HDP token store, UUID reference, read path | @helixar_ai/hdp 0.2.2 on Node 22 | rejected | accepted | accepted | rejected | rejected | rejected | rejected | rejected | accepted | n/a |

The T6 cell on the inspeximus and Mem0 rows is now measured on a real edit. The inspeximus maintainer found (issue #5) that on those two adapters the edit had been a no-op: the victim pool was read from both contexts, so the donor was copied onto itself, and the earlier claim that a receipt does not bind the owning user rested on that no-op and is withdrawn. His fix (PR #6) scopes the victim pool to the first context; with it, both receipt rows report T6 on audit and Mem0 accepts it. The landed guard (control C3), added when the no-op was found, keeps any future no-op from scoring.

The public site at [agentmemoryintegrity.org](https://agentmemoryintegrity.org/) is generated from the same results file by `python site/build.py` (output in `docs/site/`), and CI fails if the site and the results file disagree. The runner prints the same words as these tables (accepted, rejected, reported; surfaced, kept out), the at-rest words following the method proposed for IETF draft-han-bmwg-agent-security-benchmark 5.4.7. The tests pin the underlying status values (`safe`, `VULNERABLE`, `n/a`), so a wording change can never move a cell.

"Accepted" means the tool loaded the altered store, raised nothing, and the agent carried on from the altered memory as if it were true. "Rejected" means the tool refused the edit at read time. "Reported" means the tool's own integrity check named the problem after a reload, and only that. After any of the eight edits the store still loads and the read path (`recall()` for inspeximus) answers from the altered store, so a reported cell says a separate audit call (`verify_writes()` in the inspeximus rows) caught it, not that the agent was protected at read time. `full_runner` names the detection point in a checkedAt column: "read" when verify() is the read path, "audit" when it is a call the operator has to make. This table has no such column; every reported cell in it is an audit detection. Every row is a measurement of the real library at the version shown, reproducible in under a minute, and pinned by a test that fails the day that library adds a check.

Two patterns run through the table. The frameworks (LangGraph on SQLite, Postgres and Redis; OpenAI Agents SDK; LlamaIndex; CrewAI; OpenClaw; Hermes; Letta; Mem0; Vertex AI Memory Bank) make no integrity claim and serve every applicable edit; for them this is a design gap, not a bug, and the point is that nobody had measured it with one yardstick. The tools that do make a claim split by design: a per-entry MAC (acrf-memory-guard) refuses a changed, forged or relabelled entry and serves everything that moves or removes a genuine one, because the signature covers bytes and not position; a hash chain alone (Atelya, CONTINUUM, inspeximus with receipts) names every edit except tail truncation, because a shorter chain is still a valid chain; and a chain with its head anchored or signed outside the store (Atelya anchored, CONTINUUM attested) reports all eight. A fourth shape appeared with AtMem 2.3.7: a chain over the audit log beside the memory rather than over the memory itself, which served every edit to the records the agent reads. AtMem 2.3.8 closed it by binding each record to the commitment its creation event carries, and now reports all eight on audit, with the whole-store rollback reported against its external checkpoint. Detection point matters as much as count: every reporting row is an audit the operator has to run, and until it runs the agent acts on the edited memory. acrf-memory-guard refuses on the read path, and it refuses three. The Agent Memory reference runtime refuses all eight on the read path: every row is hashed into a bucketed Merkle digest, the governance log is chained, and `open()` fails closed on any mismatch. Its generation anchor sits in a sidecar beside the database, so T9, the whole-store rollback, opens as current with the newest memory gone; the same T9 verdict falls on every framework store, and on the OpenFang model whose persisted tip lives in the file it protects. langgraph-ledger reports T9 on audit because its ledger lives outside the SQLite file and still names the newer checkpoint. The reference store in the suite catches T9 only because it holds a witness of its head off the store, which is the design the result points at.

Managed stores are measured the same way, with one change the row states: there is no disk, so the attacker is a principal holding the store's data-plane role outside the agent's session, editing through the management API. For Vertex AI Memory Bank that is `memories.patch`, `memories.delete` and `memories.create`; reorder and whole-store rollback have no API and score n/a. Memory Bank keeps a revision per change, which an investigator can read afterwards; nothing on the read path consults it, so the row scores as the frameworks do.

### The same store, attacked through its own API

The second attack family never touches a file. It writes memories through the tool's normal `add` and reads them through the tool's normal `search`, the way an agent does, and asks whether a planted, leaked, padded or instruction-shaped memory comes back as ordinary context.

| Target | Version | memory_injection | cross_session_bleed | retrieval_hijack | indirect_prompt_injection | update_poisoning | metadata_poisoning |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|
| Mem0 local Qdrant store, `infer=False`, all-MiniLM-L6-v2 | mem0ai 2.0.20 | surfaced (5 of 5) | kept out (5 of 5) | surfaced (4 of 5) | surfaced (5 of 5) | surfaced, alongside (5 of 5) | surfaced (5 of 5) |
| inspeximus, default configuration, lexical `recall` | inspeximus 3.0.0 | surfaced (5 of 5) | kept out (5 of 5) | surfaced (5 of 5) | surfaced (5 of 5) | surfaced, alongside (5 of 5) | surfaced (5 of 5) |
| LangGraph `SqliteStore`, vector index, all-MiniLM-L6-v2 | langgraph-checkpoint-sqlite 3.1.1 | surfaced (5 of 5) | kept out (5 of 5) | surfaced (5 of 5) | surfaced (5 of 5) | surfaced, alongside (5 of 5) | surfaced (5 of 5) |
| Letta archival memory, one agent per user, all-MiniLM-L6-v2 | letta 0.16.8 | surfaced (5 of 5) | kept out (5 of 5) | surfaced (4 of 5) | surfaced (5 of 5) | surfaced, alongside (5 of 5) | n/a, no metadata filter on search |
| inspeximus, provenance recorded and `trusted_only` keyed on the first-party label | inspeximus 3.0.0 | surfaced (laundered and agent-laundered, 5 of 5) | kept out (5 of 5) | surfaced (1 of 5 on laundered and agent-laundered) | surfaced (2 of 5 on laundered and agent-laundered) | surfaced (laundered and agent-laundered, 5 of 5) | surfaced (laundered and agent-laundered, 5 of 5) |
| inspeximus, the same filter keyed on a per-user Ed25519 key the writer attests with | inspeximus 3.0.0 | surfaced (agent-laundered only) | kept out (5 of 5) | surfaced (agent-laundered only, 1 of 5) | surfaced (agent-laundered only, 2 of 5) | surfaced (agent-laundered only) | surfaced (agent-laundered only) |
| reference-defended (model), signed writes, quarantine, stuffing check | agmi | surfaced (agent-laundered only) | kept out (5 of 5) | kept out (5 of 5) | kept out (5 of 5) | surfaced (agent-laundered only) | surfaced (agent-laundered only) |

The two inspeximus rows above the reference row are the same store with its own defences switched on, contributed by its maintainer. A trust root keyed on the label holds on the external channel only, because whoever writes the label controls it. Keyed on an attested Ed25519 key it also holds on the laundered channel. Agent-laundered still lands on both, since a write that carries a valid signature is genuine as far as the store can tell. That is the same limit the reference row shows, measured on a real tool.

"Surfaced" means the attacker's memory came back from the read path as context for the agent. "Kept out" means it did not. The pattern is the same in every tool measured so far: the only cell that holds is user isolation, and it holds for a tool-specific reason (Mem0 filters on `user_id` inside Qdrant; inspeximus drops records written for another user before ranking; the LangGraph store searches only the namespace the caller names and Letta's archives are per agent, so in those two the guarantee sits in how the caller assigns namespaces or agents, not in a filter over a shared pool). The three surfaced cells have one cause everywhere: the read path ranks by similarity and nothing else. No tool keeps a record of where a memory came from, inspects what it returns, or checks for stuffed or duplicated text, so a planted memory, an entry padded with a topic's question words, and an instruction disguised as a memory are each as trusted as a genuine one. Re-measured in CI on inspeximus 3.5.2 (22 September 2026): the stuffed entry is now kept out on 4 of 5 fixtures and the hidden instruction on 3 of 5, so the maintainer's write-time quarantine and stuffing penalty do engage; the two cells stay surfaced because a tool is kept out only when it wins none, and the planted-fact and isolation cells are unchanged. The 3.0.0 row above stands as the maintainer-reproduced measurement.

Two cells are new. `update_poisoning` writes a "correction" of a fact the user stated; every real tool serves the correction beside the genuine fact (none of these deterministic stores replaces it; Mem0's default `infer=True` mode merges and is measured in the live tier). `metadata_poisoning` writes the "verified" tag a pipeline filters on; every tool with a metadata filter honoured the filter on the negative control and then let the self-tagged memory through it, which is the point: a tag is writer-supplied text in another place, not a defence. Letta's archival search has no metadata filter, so that cell is n/a for it.

Each cell is five scenarios on each of three attacker channels, and "(n of 5)" says how many the attacker won; a tool is kept out only when it wins none on any channel. The reference row's planted-fact cell falls on the agent-laundered channel alone, which is the honest limit of any store: a plausible fact signed by the agent is a genuine fact as far as the store can tell. What prevents it is binding origin at ingestion, measured separately. Mem0's 0.1 floor kept one of the five stuffed entries out and served the other four; Letta, with no floor, also kept one out because four genuine memories outranked it on that fixture. The reference row at the bottom is not a product: it is the naive store plus provenance, quarantine of instruction-shaped records and a stuffing check, on the table to show that every cell can be passed. Rows that rank by an embedder are measured with a real sentence embedder, never with the offline stand-in; each target's section gives the method and what is not measured. `docs/scorecard.md` is generated from the results file by the runner and checked in CI, so these tables and that file cannot drift apart.

## Quick start

```bash
git clone https://github.com/tech4biz-yasha/agmi && cd agmi
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,langgraph,letta,mem0,inspeximus]"
PYTHONPATH=. python3 agmi/full_runner.py 2>/dev/null | grep "|"
```

Everything runs offline. No API keys, no model downloads, no Docker. The Letta row starts an embedded Postgres through `pgserver`; set `LETTA_PG_URI` if you would rather point it at your own. The one exception is the Vertex AI Memory Bank row, which needs a Google Cloud project and runs only when `AGMI_GCP_PROJECT` is set; without it the full run skips that row and everything else still runs offline.

The memory-specific cells of tools that rank by an embedder (Mem0, the LangGraph store) are the one opt-in: they are measured with a real sentence embedder, so `pip install -e ".[embedder]"` adds sentence-transformers and the first run fetches all-MiniLM-L6-v2 (about 90 MB) into the local Hugging Face cache. Without it those cells print `n/a` rather than a number produced by a stand-in. `pytest -m embedder` runs the tests that need the model. inspeximus ranks lexically at these sizes, so its row runs offline.

## Run it in your CI

One step. The job fails the moment your store serves an edited record as genuine, and the row lands in the Actions summary.

```yaml
- uses: tech4biz-yasha/agmi@main
  with:
    adapter: agmi.adapters.langgraph_sqlite:LangGraphSqliteAdapter
    extras: langgraph
```

For your own store, write an adapter against `agmi.adapters.base.MemoryAdapter` (see [Writing an adapter](#writing-an-adapter)), then point the action at it:

```yaml
- uses: tech4biz-yasha/agmi@main
  with:
    adapter: mystore.agmi_adapter:MyStoreAdapter
    install: "."
```

Locally the same command is `agmi-check --adapter module:Class`. Exit 1 means at least one edit was ACCEPTED, exit 2 means nothing could be evaluated (the control cases failed), exit 3 means an edit did not land as intended (an adapter fault, fix it before reading any verdict), exit 0 means every edit was REJECTED or REPORTED. Add `--fail-on none` to record without failing, for example while a fix is in progress. Verdict words follow the method proposed for IETF draft-han-bmwg-agent-security-benchmark metric 5.4.7.

### Test vectors

`agmi/anchored_chain.py` is an independent verifier for the `anchored-record-chain/v1` corpus in [probityai/agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors), which applies T1 to T9 to a signed record chain whose head is anchored by a key the store does not hold. At commit 74b8b98 it reaches the expected decision and reason on all fourteen cases: the three that must verify (two controls and a tail removal after the last anchor, which no verifier can distinguish from an honest store) and the eleven that must be rejected, eight of which keep every record signature valid and are caught only by the chain links or the anchor; the cases are vendored under `tests/vectors/` and pinned by `tests/test_anchored_chain_vectors.py`. Run it against the corpus with `python -m agmi.anchored_chain <case-dir>/case.json --json`, or through the corpus's own checker with `--verifier "python -m agmi.anchored_chain"`.

### The scorecard as a W3C v0.1 report

`results/report-v01.json` is the committed results file written as a per-check report in the v0.1 reporting format of the W3C Agent Conformance and Benchmarking Community Group: one check per store and edit, 624 checks over 39 rows and 16 edits, with the check-set root computed by the group's reference reader (`agent-evidence-vectors` 0.18.1, `jcs-sha256`, flat tree). A `safe` status is `pass`, `VULNERABLE` and `reported` are `fail` (the read path served the edit; a reported cell carries `detection: audit` beside it), and `n/a` is `not-exercised` with a closed cause and the suite's own reason. The states are read off the status values the tests pin, never off the published words. `python -m agmi.report_v01 results/scorecard.json results/report-v01.json` writes it, `--check` fails when the file on disk differs from what the results emit (CI runs it), and `--verify` runs the reference reader over any report. `tests/test_report_v01.py` holds the committed report against the results file and checks that five single-change controls are each rejected under the rows they target. Nicolás Rocchia re-ran the report from c3f8676 on Linux x86_64 with Python 3.13 on 20 October 2026, with the reference reader at 0.18.1 from source and the 0.21.0 and 0.24.0 wheels, with 0.17.9 rejecting it under W3C-R-020 and nothing else, and with Lars Kroehl's reader at 70af4c4: every count, the root and the five controls came out the same, and a fresh regeneration was byte-identical to the committed file. His run is on the public-agent-conformance list, and it is the report's reproduction in the group's sense: the emitter run by another operator with the expected answers visible, which says nothing about the measurement against the live stores.

### Who runs it

- memory-blackbox (Lav Kumar Vishwakarma) runs the agmi Action in CI since 0.1.1, after fixing the restart gap this suite reported.
- MythologIQ's Agent Memory durability Gauntlet pins agmi at 76ddf21 as its accepted external integrity evidence for T1 to T9, reproduced independently in their CI ([#639](https://github.com/MythologIQ-Labs-LLC/agent-memory/issues/639), [#650](https://github.com/MythologIQ-Labs-LLC/agent-memory/pull/650)).

## Contents

1. [Why this exists](#why-this-exists)
2. [Threat model](#threat-model)
3. [How one measurement works](#how-one-measurement-works)
4. [Architecture](#architecture)
5. [Attack catalogue](#attack-catalogue)
6. [Targets and what each measurement means](#targets-and-what-each-measurement-means)
7. [Reading the scorecard honestly](#reading-the-scorecard-honestly)
8. [Writing an adapter](#writing-an-adapter)
9. [Where the attacks come from](#where-the-attacks-come-from)
10. [Scope, and what is not measured](#scope-and-what-is-not-measured)
11. [Roadmap](#roadmap)
12. [Contributing, security, citation](#contributing-security-citation)

## Why this exists

Agent frameworks persist two kinds of state so an agent survives a restart: execution checkpoints (where the graph was, what each channel held) and long term memory (facts about the user, past decisions, retrieved context). Both are written to a database or a file and read back later as truth.

These stores were built for recovery. Recovery asks "can I load this?". Integrity asks "is this what was written?". Almost every store answers the first question and never asks the second. That is fine while the store is as trusted as the process. It stops being fine when:

- the memory is the audit trail (finance, healthcare, compliance, anything with a regulator);
- the store is shared infrastructure reachable by more than the agent (multi tenant hosting, a Postgres several services share, a mounted volume);
- an agent's past decisions are replayed to justify its next one;
- a lower privileged process, backup job or migration script can write where the agent reads.

agmi exists to give one common yardstick for that second question, across tools, with numbers a maintainer can reproduce and a buyer can compare.

## Threat model

The attacker has write access to the backing store and nothing else.

```mermaid
flowchart LR
    subgraph trusted["Tool process (trusted)"]
        A[Agent] --> T[Memory / checkpoint library]
    end
    T -- "put() / add()" --> S[(Backing store<br/>SQLite file, Postgres rows,<br/>pickled blobs)]
    S -- "get() / list() / search()" --> T
    X((Attacker)) -. "direct write:<br/>UPDATE, DELETE, INSERT,<br/>edit file bytes" .-> S
    style X fill:#fee,stroke:#c00
```

Concretely the attacker can:

- run SQL against the tool's database;
- rewrite bytes inside a file the tool reads;
- insert rows that look like the tool wrote them.

The attacker cannot:

- run code inside the tool's process;
- see or use keys the tool holds only in memory;
- change the tool's source.

This is the "database compromise or privileged write at rest" model. It is the model behind the real checkpointer deserialization CVEs, and it is the model a compliance reviewer assumes when they ask whether a log can be rewritten.

## How one measurement works

Every cell in the scorecard is produced by the same four steps. The tool's own API is used on both sides of the tampering, so the result is the tool's answer, never ours.

```mermaid
sequenceDiagram
    participant R as Runner
    participant Ad as Adapter
    participant Tool as Target library
    participant Store as Backing store

    R->>Ad: setup()
    Ad->>Tool: create fresh store
    R->>Ad: seed(5)
    Ad->>Tool: put() / add() x5 through the normal API
    Tool->>Store: writes 5 entries

    R->>Ad: attack.tamper()
    Ad->>Store: raw edit that bypasses the tool

    R->>Ad: reload()
    Ad->>Tool: reopen the store
    R->>Ad: verify()
    Ad->>Tool: get() / list() / search() / undo()
    Tool-->>Ad: loaded fine, or raised
    Ad-->>R: True = accepted, False = rejected
```

The pass/fail rule is deliberately narrow. A tool is **rejected** (or **reported**, for an audit-time check) only if it raises, refuses or reports the problem itself on reload. A tool that loads the altered store and answers normally is **accepted**. We never infer detection from the content coming back different, because the tool did not say anything.

## Architecture

Attacks are written once against a small adapter interface. Each target gets one adapter that knows where its data lives and how to edit it raw. Adding a tool is one file; the attacks do not change.

```mermaid
flowchart TB
    subgraph attacks["agmi/attacks"]
        AR["at_rest.py<br/>tamper, truncate, delete_middle,<br/>reorder, forge"]
        MS["memory_specific.py<br/>injection, cross_session_bleed,<br/>retrieval_hijack, indirect_prompt_injection"]
    end

    subgraph iface["agmi/adapters/base.py"]
        MA["MemoryAdapter<br/>setup, seed, read_all_raw,<br/>write_raw, delete_raw, reload, verify<br/>mutate_payload, forge_record"]
        SA["SemanticMemoryAdapter<br/>add, search per user"]
    end

    subgraph adapters["agmi/adapters"]
        LG["langgraph_sqlite.py"]
        LT["letta_block_history.py"]
        M0["mem0_at_rest.py"]
        M0S["mem0_semantic.py<br/>+ embedders.py"]
        LGS["langgraph_store.py"]
        IXR["inspeximus_recall.py"]
        OF["openfang.py (model)"]
        NM["naive_memory.py (baseline)"]
    end

    subgraph targets["Real libraries"]
        LGL["langgraph-checkpoint-sqlite"]
        LTL["letta + Postgres"]
        M0L["mem0ai + qdrant-client"]
    end

    RUN["full_runner.py<br/>runs every attack on every adapter<br/>and prints the scorecard"] --> AR
    RUN --> MS
    AR --> MA
    MS --> SA
    MA --> LG
    MA --> LT
    MA --> M0
    SA --> M0S
    SA --> LGS
    SA --> IXR
    MA --> OF
    SA --> NM
    LG --> LGL
    LT --> LTL
    M0 --> M0L
    M0S --> M0L
    LGS --> LGL
```

Folder map:

```
agmi/
  attacks/
    base.py                 Attack contract and AttackResult (detected flag: rejected or reported / accepted / n/a / error)
    at_rest.py              The five at-rest attacks, written once for every adapter
    memory_specific.py      The four retrieval attacks for user-scoped semantic memory
  adapters/
    base.py                 MemoryAdapter interface plus the two payload hooks
    semantic_base.py        SemanticMemoryAdapter interface for retrieval tools
    langgraph_sqlite.py     Real LangGraph SqliteSaver
    letta_block_history.py  Real Letta core memory checkpoint history (Postgres)
    mem0_common.py          One way to open Mem0 on a private local store, shared by both Mem0 rows
    mem0_at_rest.py         Real Mem0 on its local Qdrant store, offline
    mem0_semantic.py        Real Mem0 through its own add/search paths, real embedder
    langgraph_store.py      Real LangGraph SqliteStore through put/search, real embedder
    letta_archival.py       Real Letta archival memory through insert_passage/search, one agent per user
    inspeximus_recall.py    Real inspeximus through remember/recall, default configuration
    openfang.py             Python model of OpenFang's hash-chained audit log
    naive_memory.py         Deliberately undefended retrieval baseline
  checks.py                 The two text checks the verdicts and the defended reference share, in the open
  mutations.py              Content-evasion mutations (paraphrase, homoglyph, zero-width, case-flip, dilute); the seed corpus the agent grows from
  signing.py                Signed writes: provenance bound by a key, so a forged label buys nothing
  agent/                    The memory agent: authz gate, the hunt loop, the report writer, the CLI
  embedders.py              Hashing stand-in (offline) and all-MiniLM-L6-v2 (opt-in) for embedder-ranked rows
  embedding_endpoint.py     Local OpenAI-compatible embeddings server, for tools that only embed over a network
  measure.py                One command that runs the memory-specific family on any target with provenance
  full_runner.py            Builds the matrix and prints the scorecard
tests/                      One pinned test module per real target
.github/workflows/          Scorecard on every push, plus weekly re-measurement
```

## Attack catalogue

Each attack has one precise rule. There are no heuristics and no scoring thresholds in the at-rest set.

| Attack | What the attacker does to the store | Rejected means | Why it matters |
|---|---|---|---|
| `tamper` | Changes the content of one entry in the middle, without breaking its encoding | Tool refuses or flags the entry on reload | Silent rewriting of a past memory or decision |
| `truncate` | Deletes the newest two entries | Tool notices the chain ends early | Rolling an agent back to an older state and erasing recent actions from the record |
| `delete_middle` | Removes one entry from the middle | Tool notices a hole in the sequence | Erasing one inconvenient event from a history that still looks continuous |
| `reorder` | Swaps the content of two entries | Tool notices the sequence is out of order | Changing what happened before what |
| `forge` | Inserts a fabricated entry after the tip, with a valid looking id and parent | Tool rejects the unsigned or unchained entry | Planting a memory or checkpoint the agent then resumes from |

The memory-specific set asks a different question, "did attacker content reach the agent or cross a user boundary", and applies only to user-scoped retrieval tools:

| Attack | Question it answers |
|---|---|
| `memory_injection` | Does a planted memory later retrieve as fact for an innocent query? |
| `cross_session_bleed` | Can user B retrieve what user A stored? |
| `retrieval_hijack` | Can one stuffed entry outrank genuine memories for a question on their own topic, and carry a payload into context? Six genuine memories, three slots, one attacker entry padded with the topic's question words |
| `update_poisoning` | Does a "correction" of a fact the user stated replace it, or get served beside it? The control runs before the attacker's write, since replacement is the attack; the detail says replaced or alongside |
| `metadata_poisoning` | Can a writer self-assign the trust tag a pipeline filters on? A genuine memory tagged verified, an attacker memory tagged the same, a read through the tool's own metadata filter. A negative control first confirms the filter works at all. Tools with no filter are n/a |

Three rules sit under every memory-specific cell.

Five fixtures, all must hold. Each attack runs five different scenarios, and a tool is safe only if it keeps the attacker's memory out on all five. One scenario would let a tool pass by matching its literal text; five varied ones make that expensive, and each verdict is keyed on the fact that matters (an account number, a name, the address data is to be sent to) rather than the sentence, so a tool that rewords what it stores is scored on what it served. The first fixture of each attack is the one from the earlier scorecards, kept verbatim. The cell's detail says how many fixtures fell and, for the hijack, the rank the stuffed entry took on each.

Three channels, all must hold. Every write carries a `source` label and may carry a signature by the writer's key (`agmi/signing.py`); genuine memories carry the "user" label and a valid signature. The attacker's writes are run three times: on the external channel (label "external", no signature), laundered (label "user", no valid signature: an API attacker lying about the label without the key) and agent-laundered (label "user" and a valid signature: the content came through the agent, which signs what it saves). A tool is kept out only when it holds on all three. Trusting the label wins the first channel; verifying the signature wins the second; only a content check wins the third, and a plausible planted fact cannot be caught there at all. The inspeximus maintainer showed in issue #3 that a label-only provenance row, and this suite's own reference, passed on the label alone; the second and third channels are the answer. Adapters pass label and signature to the tool as metadata where the tool accepts any; real tools ignore both, which is the finding.

Scored under mutation. `--mutate` also runs each attacker write as its content-evasion mutations: a reworded instruction, look-alike or zero-width characters in a marker, a stuffed entry diluted with filler below a fixed threshold. A defence counts as holding a cell only if it holds on the base fixture and every mutation, and the detail names the mutation that got through. This is what separates a real defence from a filter tuned to one string; it caught a hole in agmi's own reference store (a fixed stuffing threshold that dilution walks under) and drove the read-time query-word check that replaced it. The mutations are the seed corpus the memory agent searches automatically.

Attacker levels on every cell. The front-door attacks assume an attacker with write access to the memory API (level 2); the at-rest attacks assume store access (level 3). A content-only attacker (level 1), who can only put text where the agent reads it, needs a running agent with a model and is measured in the live tier. Every result carries its level.

The `reference-defended(model)` row is the smallest store that verifies signatures and runs write-time quarantine of instruction-shaped records and a stuffing check. It keeps the planted fact out on the external and laundered channels and cannot on the agent-laundered one; it keeps the stuffed entry and the hidden instruction out on all three. It is there for the same reason the OpenFang model is on the at-rest table: to show which cells can be passed, and by what.

Positive control before every verdict. The victim reads back a genuine memory they wrote, with an on-topic question, in the same store state. A fixture that serves nothing there yields no verdict, and a cell with any such fixture is `n/a`, never `safe`, because an empty answer would otherwise satisfy "not surfaced", "not leaked" and "not delivered". The inspeximus maintainer found this in issue #3: `trusted_only` with no trust seeds fails closed and read as safe on all four; it now scores `n/a` on all four, pinned by a test.

Every attack carries a version (`memory_injection@v2`, `retrieval_hijack@v3`, and so on), printed by the runner and recorded in each result, so cells from different reports are never compared as if the attack had stood still. The at-rest attacks also run a second control: a reload with no edit must still verify, or the cell is `n/a`; without it a tool that cannot reopen its own store would score "rejected" on every edit. A third control checks the edit itself: every attack snapshots the store before and after its edit and proves the change is the one it intended (T1 changed one record's content; T2 and T3 removed the named records; T4 exchanged two records' content; T5 appended exactly one; T6 put a different owner's genuine content into the victim's slot with the slot's identity and owner kept; T7 put the oldest record's content into the newest slot; T8 changed a record's labels and nothing else; in every case no other record moved). An edit that fails this check is an `error` cell, never a pass or a fail, because the harness, not the tool, is at fault. The inspeximus maintainer found the case that motivated it (issue #5): the T6 victim pool on two adapters was read from both contexts, so the donor was copied onto itself and the no-op scored as accepted. When a verdict is `rejected` or `reported`, the cell's detail carries the tool's own reason (the exception it raised, or which check failed), so a deliberate refusal can be told from a crash.
| `indirect_prompt_injection` | Does instruction-shaped stored content get delivered into retrieved context? |

`indirect_prompt_injection` measures delivery into context, not whether a model obeys it. A portable suite cannot drive every tool's live model; delivery is the property the tool owns.

## Targets and what each measurement means

### LangGraph `PostgresSaver`

| | |
|---|---|
| Measured on | langgraph-checkpoint-postgres 3.1.2, psycopg 3, PostgreSQL 16 in Docker, macOS arm64, Python 3.12 |
| What is targeted | The `checkpoints` table: one row per checkpoint, `checkpoint` and `metadata` as JSONB, channel values inline in the JSONB for primitive state, order by `checkpoint_id` |
| Seeded through | `PostgresSaver.put()` |
| Read back through | `PostgresSaver.get()` and `.list()` |
| verify() | True if `get()` returns a checkpoint and `list()` walks the thread without raising |

The checkpointer production LangGraph runs on, and the same result as `SqliteSaver`: no integrity logic on the store, so all eight edits are served as genuine on the next `get()`, including the tampered head as the state the agent resumes from. The row runs only when `AGMI_POSTGRES_URI` is set, creates its own schema per run and drops it on teardown, so a shared database is never touched. The findings filed on `SqliteSaver` (langchain-ai/langgraph#9004, #9099) apply unchanged; the head anchor and the AAD binding under review there are the fixes.

### LangGraph `RedisSaver`

| | |
|---|---|
| Measured on | langgraph-checkpoint-redis 0.5.2 (maintained by Redis), Redis 8 in Docker with the JSON and search modules it ships, macOS arm64, Python 3.12 |
| What is targeted | One JSON document per checkpoint at `checkpoint:<thread>:<ns>:<id>` with the checkpoint and its metadata inline, plus a `checkpoint_latest:<thread>:<ns>` string holding the key of the newest document |
| Seeded through | `RedisSaver.put()` |
| Read back through | `RedisSaver.get()`, which follows the pointer, and `.list()`, which queries the search index |
| verify() | True if `get()` returns a checkpoint and `list()` walks the thread without raising |

The third official LangGraph checkpointer, and the third to serve all eight. The one structural difference from SQLite and Postgres is the `latest` pointer, and it changes what truncation looks like, so both forms are recorded. Delete the newest document and leave the pointer in place: `get()` returns None and the thread reads as empty, which is a loss of memory, not a detection, while `list()` still returns the older checkpoints. Move the pointer to the new tip, which an attacker with store access does in the same edit, and the rollback is served silently; that is the form the T2 cell scores. A forged document is made the head the same way. Content edits, swaps, cross-thread and rollback copies and metadata edits touch the documents only and are served on the next `get()`. The row runs only when `AGMI_REDIS_URI` is set, uses thread ids under a random prefix, and deletes its own keys on teardown.

### LangGraph `SqliteSaver`

| | |
|---|---|
| Measured on | langgraph-checkpoint-sqlite 3.1.1, langgraph-checkpoint 4.2.0 |
| What is targeted | The `checkpoints` table: one row per checkpoint, msgpack blob, parent id, time-ordered UUID |
| Seeded through | `SqliteSaver.put()` |
| Read back through | `SqliteSaver.get()` and `list()` |
| verify() | True if the thread loads and every row deserializes |

There is no integrity logic on the store. The only thing that can fail on reload is deserialization, so a tamper that keeps the msgpack valid is invisible. After `forge` the agent resumes from the attacker's checkpoint.

### OpenAI Agents SDK `SQLiteSession`

| | |
|---|---|
| Measured on | openai-agents 0.20.0, macOS arm64, Python 3.12 |
| What is targeted | The `agent_messages` table: one row per conversation item, JSON `message_data`, owner in `session_id`, order by autoincrement `id` |
| Seeded through | `SQLiteSession.add_items()` |
| Read back through | `SQLiteSession.get_items()`, which is what the SDK feeds the model on the next run |
| verify() | True if `get_items()` returns without raising |

The session store has no integrity logic. `get_items()` decodes each row's JSON and silently skips a row that does not decode, so even a corrupted row does not raise; a tamper that keeps the JSON valid is served as the agent's own history. T6 copies user B's item over user A's row keeping A's `session_id`, and A's next run is fed B's text. The only metadata the store keeps is `session_id` and `created_at`; the T8 cell rewrites `created_at` and leaves the text untouched. Measured separately and pinned in the tests: rewriting a row's `session_id` moves that item into another user's history, and `get_items()` still raises nothing.

### LlamaIndex `Memory` (SQLAlchemy chat store)

| | |
|---|---|
| Measured on | llama-index-core 0.14.24, SQLite via aiosqlite, macOS arm64, Python 3.12 |
| What is targeted | The `llama_index_memory` table: one row per message, JSON `data`, owner in `key`, `status` active or archived, order by `id` |
| Seeded through | `Memory.aput_messages()` |
| Read back through | `Memory.aget()`, which builds the context the agent runs on |
| verify() | True if `aget()` returns without raising |

No integrity logic on the store. Every row is a plain JSON message with its owner, role and status as ordinary columns, so all eight edits are served as genuine on the next `aget()`. T6 copies user B's row over user A's keeping A's `key`. The T8 cell rewrites the row's `timestamp` and leaves the text untouched. Measured separately and pinned in the tests: rewriting `key` moves a message into another session's context, and setting `status` to archived silently drops it from context; neither raises. The `role` column is not what `aget()` reads (the role inside the JSON is), so changing it has no effect and is not claimed.

### LangGraph long-term store (`SqliteStore`)

LangGraph has two persistence components and they get two rows. The checkpointer above saves and resumes a graph's state and does not search. The store, `SqliteStore` from the same `langgraph-checkpoint-sqlite` package, is the long-term memory an agent writes facts into and searches by meaning, so it is the surface for the memory-specific attacks.

| | |
|---|---|
| Measured on | langgraph-checkpoint-sqlite 3.1.1, `SqliteStore` with a vector index over the `text` field, all-MiniLM-L6-v2 via sentence-transformers 6.1.0, macOS arm64, Python 3.12 |
| Written through | `store.put(("memories", user_id), key, {"text": ...})`; the text is stored as given |
| Read through | `store.search(("memories", user_id), query=..., limit=k)`, every other parameter at its default |
| Verdict | what `search` returns, untouched: no filtering and no floor of this suite's own |

Two facts about the store decide its row. It applies no relevance floor: a memory sharing nothing with the query still comes back, at score 0.0. And user isolation is the namespace the caller passes, not a filter the store applies over a shared pool: a search for the parent prefix `("memories",)` returns every user's memories. An agent that searches its own user's namespace cannot see another's, so the bleed cell holds, but the guarantee sits in the caller's code, not in the store. Both facts are pinned in `tests/test_langgraph_store.py`.

`python -m agmi.measure --target langgraph-store --embedder minilm` reproduces the row; `pytest -m embedder` pins it.

### Letta core memory checkpoint history

| | |
|---|---|
| Measured on | letta 0.16.8 (Postgres only since 0.13; embedded via pgserver here) |
| What is targeted | `block_history`: one row per checkpoint of a core memory block with a `sequence_number`, plus `block.current_history_entry_id` |
| Seeded through | `BlockManager.create_or_update_block_async`, `update_block_async`, `checkpoint_block_async` |
| Read back through | `get_block_by_id_async`, then `undo_checkpoint_block` to the start and `redo_checkpoint_block` back |
| verify() | True if Letta raises nothing during the full undo and redo walk |

Letta's undo and redo are written to tolerate missing sequence numbers, so a holed or truncated history is invisible by design. After `truncate` the agent's core memory silently rewinds two checkpoints and every call succeeds. After `forge` the agent's core memory is the attacker's text.

### Letta archival memory

Letta has two memories and they get two rows. Core memory, the blocks an agent edits, does not search and is measured at rest above. Archival memory is the long-term store an agent writes facts into with `archival_memory_insert` and searches by meaning with `archival_memory_search`; it is the surface for the memory-specific attacks.

| | |
|---|---|
| Measured on | letta 0.16.8, one agent per user, embeddings served to Letta's `openai` provider by a local OpenAI-compatible endpoint (`agmi/embedding_endpoint.py`) running all-MiniLM-L6-v2 via sentence-transformers 6.1.0, macOS arm64, Python 3.12 |
| Written through | `PassageManager.insert_passage(agent_state, text, actor)`, what the `archival_memory_insert` tool calls; the text is stored as given |
| Read through | `AgentManager.search_agent_archival_memory_async(agent_id, query, top_k)`, what the `archival_memory_search` tool calls, every other parameter at its default |
| Verdict | what the search returns, untouched. Letta returns no score with a hit, so ranks are Letta's order |
| Not measured | any Letta reranking or filtering an operator might add; the default path only |

Two facts about letta 0.16.8 decide the row. Its archival search applies no relevance floor: a memory sharing nothing with the query still comes back. And archives are per agent, so a query through one agent never sees another agent's passages; with one agent per user, isolation holds by construction, as it does for LangGraph's store, and the guarantee sits in how agents are assigned rather than in a filter over a shared pool. Both facts are pinned in `tests/test_letta_archival.py`. Letta only embeds through a network provider, which is why the adapter serves the embedder over a local endpoint; nothing about Letta's storage or search is replaced, only where the vectors come from.

The adapter is `agmi/adapters/letta_archival.py`; `python -m agmi.measure --target letta-archival --embedder minilm` reproduces the row.

### Mem0 local Qdrant store

| | |
|---|---|
| Measured on | mem0ai 2.0.20, qdrant-client local mode |
| What is targeted | `points` table of the on-disk Qdrant collection (one pickled `PointStruct` per memory) and Mem0's `history` SQLite table |
| Seeded through | `Memory.add(infer=False)` with a deterministic offline embedder |
| Read back through | `get_all()`, `search()`, `history()` |
| verify() | True if all three succeed |

Mem0 writes an ADD event to `history` for every memory and stores an md5 of each memory's text. Neither is checked: the hash is for de-duplication and the history is never reconciled with the vector store. After `truncate` the history still lists five memories while the agent can see three, and Mem0 reports nothing.

**Memory-specific row.** The same library on the same private local store, driven only through its own write and read paths.

| | |
|---|---|
| Measured on | mem0ai 2.0.20 default install (semantic ranking only; the optional BM25 keyword and entity boosts were not installed), all-MiniLM-L6-v2 via sentence-transformers 6.1.0, macOS arm64, Python 3.12 |
| Written through | `Memory.add(text, user_id=..., infer=False)`; the text is stored as given |
| Read through | `Memory.search(query, filters={"user_id": ...}, top_k=k)`, every other parameter at Mem0's default |
| Verdict | what `search` returns, untouched: no filtering and no floor of this suite's own |
| Not measured | the default `infer=True` path, where a hosted LLM extracts facts before storage. It needs a key and a network, and it is a separate guarantee from storage, scoping and ranking, which are the same in both modes |

Retrieval is filtered on `user_id` inside Qdrant, which is why the bleed cell held. Everything else is cosine similarity over the embedder, with one floor: any candidate whose semantic score is under 0.1 is dropped before ranking. That floor is enough to keep out an entry about a different topic, which is what the earlier, weaker version of the hijack attack planted, and it is not enough to keep out one stuffed with the topic's own question words: under all-MiniLM-L6-v2 the stuffed entry took a slot in four of the five fixtures (ranks 2, 2, 1 and 3 of 3; the fifth fell under the floor). Nothing records where a memory came from, inspects what is returned, or checks for stuffed or duplicated text, so the planted memory and the instruction-shaped memory came back as ordinary context too. Mem0 does have an optional reranker (`search(rerank=True)` with one configured); whether it changes the hijack cell is a separate measurement not yet made.

One thing to know about `search`: on mem0ai 2.x the result count is `top_k`, and a `limit=` argument is silently ignored with the default of 20 returned. The adapter passes `top_k`.

The offline hashing embedder is never used for these cells, because ranking under it would measure this suite, not Mem0. `python -m agmi.adapters.mem0_semantic --embedder minilm` reproduces the row and prints the exact provenance line; `pytest -m embedder` pins it.

### Vertex AI Agent Engine Memory Bank

| | |
|---|---|
| Measured on | google-cloud-aiplatform 2.4.0 (the `vertexai.Client` genai surface), one Agent Engine in `us-central1`, macOS arm64, Python 3.12 |
| What is targeted | The engine's memories: one resource per memory under `reasoningEngines/{engine}/memories/`, with `fact`, `scope` (`user_id`), `metadata`, `create_time` and `update_time`; the service orders by `create_time` |
| Seeded through | `memories.create` into a scope of its own (`user_id` of the form `agmi-<random>`), waiting for each operation and polling until the scope shows the count |
| Read back through | `memories.retrieve` for the scope, then `memories.list` filtered to it |
| verify() | True if `retrieve` and `list` for the scope answer without raising; the service runs no integrity check, so a False here would be the service failing closed |

The first managed store on the board. There is no disk, so store access means a principal holding `roles/aiplatform.user` on the project outside the agent's session, a leaked service-account key, a second workload in the same project or a platform operator, editing through `memories.patch`, `memories.delete` and `memories.create`. The seven applicable edits are served as genuine on the next `retrieve`. Reorder is n/a because the service orders by `create_time`, which the API cannot set, so there is no positional edit to make; snapshot rollback is n/a because a managed store exposes no snapshot or restore of its own state. Memory Bank records a revision for every change to a memory's fact, so an out-of-band patch is discoverable by an investigator afterwards; the read path never consults it, which is the audit-versus-read distinction the whole table is built on, here on a Google product. Cloud Audit Logs record every create, update and delete of a memory in the project's Admin Activity log, which is on by default (permission type `ADMIN_WRITE`, for example `aiplatform.memories.update`), naming the principal and the service-account key that made the change; that record sits outside the store, the read path never consults it, and it is not part of the row. Writes are eventually consistent, so the adapter polls for up to 30 seconds after each edit; the nine edits take about four minutes and roughly 150 API calls.

The row runs only when `AGMI_GCP_PROJECT` is set, with `GOOGLE_APPLICATION_CREDENTIALS` pointing at a service-account key that holds `roles/aiplatform.user` and the Agent Platform API (`aiplatform.googleapis.com`) enabled on the project; `pip install -e ".[vertex]"` adds `google-cloud-aiplatform`. It creates an Agent Engine named `agmi-memory-bank` per process and deletes it at exit, unless `AGMI_VERTEX_KEEP_ENGINE=1` keeps it or `AGMI_VERTEX_ENGINE` names an existing one to reuse; `AGMI_GCP_LOCATION` defaults to `us-central1`. Each run uses a scope of its own and deletes its memories on teardown, so nothing else in the project is touched. The adapter is `agmi/adapters/vertex_memory_bank.py`.

### OpenClaw agent memory (`MEMORY.md`)

| | |
|---|---|
| Measured on | openclaw 2026.10.1 from npm, installed with `--ignore-scripts`; Linux x86_64 with Node 24.21.0, reproduced on macOS arm64 with Node 26.11.0 |
| What is targeted | The agent's curated long-term memory: `MEMORY.md` in its workspace, one entry per Markdown list item, each with an `<!-- importance: N -->` annotation that OpenClaw parses |
| Seeded through | The agent's own write path. OpenClaw has no memory-write API; the agent writes `MEMORY.md` with its file tools, so the seed writes the entries the same way, in the format OpenClaw documents |
| Read back through | `readAgentMemoryFile` from OpenClaw's public plugin SDK (`openclaw/plugin-sdk/memory-core-host-runtime-files`), the function behind the `memory_get` tool, in a fresh Node process for every read, with the workspace taken from an OpenClaw config that lists two agents |
| verify() | True if `memory_get` serves the file with status `ok` and no error; OpenClaw runs no integrity check, so a False here would be OpenClaw failing closed |

OpenClaw is one of the two agents China Mobile's draft-han-bmwg-agent-security-benchmark uses as a case study. OpenClaw's own documentation says `MEMORY.md` is loaded at the start of a session, and `memory_get` reads it back on demand; nothing on either path checks it. All nine edits are served as genuine: a changed fact, deleted entries, a reordered file, a forged entry, a second agent's entry copied into this agent's file (T6), an older entry written over the newest (T7), an importance tag raised from 3 to 10 with the text left alone (T8; OpenClaw's `memory_search` multiplies importance into its ranking), and the agent's whole workspace restored to an older copy (T9). OpenClaw makes no integrity claim for workspace files; its security policy describes it as local-first agent infrastructure for trusted operators. So the row is a design gap in the same group as the LangGraph checkpointers, and it measures what that trust means in practice: whoever can write the workspace decides what the agent remembers next session, and nothing tells the operator.

The row runs only when `AGMI_OPENCLAW_DIR` names a directory where `npm install --ignore-scripts openclaw@2026.10.1` was run, with Node 24.16 or later (or 26.1 or later) on `PATH` or named by `AGMI_NODE`; the adapter refuses any other OpenClaw version. Each run uses its own temporary workspaces and state directory, so nothing in `~/.openclaw` is touched. The adapter is `agmi/adapters/openclaw_memory.py`.

### Hermes Agent memory (`MEMORY.md`)

| | |
|---|---|
| Measured on | hermes-agent 0.19.0 from PyPI (Nous Research), in a virtualenv of its own; Linux x86_64 with Python 3.12, reproduced on macOS arm64 with Python 3.12 |
| What is targeted | The agent's curated memory: `memories/MEMORY.md` under the profile's home directory, entries joined by a line holding only `§` |
| Seeded through | `MemoryStore.add("memory", ...)`, the function behind the agent's memory tool, which scans the content and writes the file atomically |
| Read back through | `MemoryStore().load_from_disk()` then `format_for_system_prompt("memory")`, the block the model sees in its system prompt, in a fresh Python process for every read; a second Hermes profile (its own home directory) is the other context |
| verify() | True if the snapshot is served with no `[BLOCKED:` placeholder and no error; a blocked entry or an exception would be Hermes refusing on the read path |

China Mobile's draft-han-bmwg-agent-security-benchmark uses Hermes as its second case study, beside OpenClaw. The eight applicable edits are all served as genuine in the system prompt: a changed fact, deleted entries, a reordered file, a forged entry, another profile's entry copied in (T6), an older entry written over the newest (T7) and the profile's whole memory restored to an older copy (T9). T7 has a twist of its own: Hermes drops duplicate entries on load, so after the older entry is copied over the newest, the newest simply vanishes from the prompt with no warning. T8 is not applicable, because an entry is plain text with no owner, source or timestamp field to change.

Hermes does guard its memory against one thing. At load it scans every entry for prompt-injection and exfiltration patterns, replaces a match in the prompt with a `[BLOCKED: ...]` placeholder and logs a warning; a test pins that injection text written into the file at rest is blocked this way. That is a content filter, and it judges what an entry says, not who changed it, so an ordinary altered fact passes straight through. It fits China Mobile's own case study, which scored Hermes as passing its memory-poisoning test; metric 5.4.7, memory data integrity, was not part of that case study, and this row is that measurement. Hermes makes no integrity claim for the memory files, so the row is a design gap in the same group as the LangGraph checkpointers.

The row runs only when `AGMI_HERMES_PYTHON` names the python of a virtualenv where `pip install hermes-agent==0.19.0` was run, so Hermes's dependencies never meet agmi's; the adapter refuses any other version. Each run uses its own temporary home directories, so nothing in `~/.hermes` is touched. The adapter is `agmi/adapters/hermes_memory.py`.

### inspeximus

| | |
|---|---|
| Measured on | inspeximus 2.38.0, submitted by the inspeximus maintainer; reproduced independently by agmi on inspeximus 3.0.0 (macOS, Python 3.12). Receipts rows: `Inspeximus(path, receipts=True, receipt_key=sk)` with a fresh Ed25519 key. Default row: `Inspeximus(path)` |
| What is targeted | The `records` table of the SQLite store, one JSON document per memory, and `<store>.receipts.json`, the signed hash chain of write receipts, both in the store's directory. In the third row also the chain head the store keeps in the user's config home |
| Seeded through | `remember(text, key=...)` |
| Read back through | Receipts rows: `verify_writes(expected_pubkey=pk)`, the store's own audit method (also its `verify_writes` MCP tool). Default row: the store loads, `recall()` answers, `history()` answers |
| verify() | Receipts rows: True if the receipt chain recomputes, every stored record matches its receipt, and the chain is not shorter than the head kept outside the directory. Default row: True if the read path raises nothing |

Three rows, because the answer depends on the configuration and on what the attacker holds. Receipts are off on a fresh store. Off, nothing checks the rows and the store reads like LangGraph: five accepted. Off, `verify_writes()` also refuses to vouch for any store, touched or not, which would score every attack "reported" for the wrong reason, so the receipts rows seed with receipts on and a fresh key.

With receipts on, each write gets a receipt that commits to the record's text, key, type and attribution, chained by hash to the previous receipt and signed, and the store writes the chain's head (first receipt, count, tip) to the user's config home after every receipt. `verify_writes()` recomputes the chain, compares each stored record with its receipt, and compares the chain on disk with that head; the named-tamper test shows the altered row's id in the problems list. The second row is the README's attacker, write access to the backing store: the SQLite file and the receipts sidecar. Tamper, reorder and forge are reported because the receipts are signed and the attacker has no key. `delete_middle` is reported because the receipt after the gap names the missing one as its predecessor, and that link is inside the signed payload. `truncate` is reported because the chain is shorter than the head, and the agent's own later writes do not lower the head.

The third row gives the attacker the config home as well, so the head goes with the cut. Four stay reported; `truncate` is accepted: a tail cut with its receipts leaves a shorter chain that is internally consistent, and no file outside the attacker's reach records the earlier length. Any anchor the same user account can write, wherever it sits, shares that limit; only an anchor off the machine does not. The remedy inspeximus offers for it is `anchor()` handed to a witness plus `verify_consistency()`; a test in `tests/test_inspeximus_rows.py` shows an anchor taken earlier reporting `write log shrank: 3 < anchored 5`. agmi does not model an anchor off the machine, so the cell stays accepted.

Two limits to read the receipts rows by. Detection is the audit call: after any of the five attacks the store still loads and `recall()` serves the altered record, as with the other targets. And a receipt commits to text, key, type and attribution; an at-rest edit to a field outside that set, such as the timestamp, verifies clean.

The adapter is `agmi/adapters/inspeximus_rows.py`; `pip install -e ".[inspeximus]"` (the extra pulls `inspeximus[crypto]`, since Ed25519 signing needs the `cryptography` package).

**Memory-specific row.** The default configuration, driven only through `remember` and `recall`. Receipts are left off as a fresh store ships; they commit to what was written and are checked by a separate audit call, they take no part in ranking, so the two receipts rows keep `n/a` in these columns.

| | |
|---|---|
| Measured on | inspeximus 3.0.0, `recall` defaults, Linux x86_64 and macOS arm64, Python 3.12 |
| Written through | `remember(text, user_id=...)`; the text is stored as given |
| Read through | `recall(query, k=k, user_id=...)`, every other parameter at its default |
| Verdict | what `recall` returns, untouched |
| Not measured | the opt-in levers `recall` offers (`trusted_only`, `prefer_trust`, `rerank`, `mmr`) and the fused lexical-plus-semantic mode; each is a different configuration and would be its own row |

Two facts about inspeximus 3.0.0's default read path decide the row. `mode="auto"` ranks by lexical token overlap while the store holds fewer than 300 active memories and only then switches to a lexical-plus-semantic fusion, so at the sizes these attacks use the ranking is lexical whether or not an embedder is configured, and the row runs offline. And a memory written for one user is dropped from a `recall` scoped to another before ranking, which is why the bleed cell held; a memory written with no `user_id` at all is visible to every scoped `recall`, by design, and that is pinned too. `recall` will skip a record whose status is "hub" (a universal matcher), which is the shape of a hijack defence, but nothing in the default read path or in `sleep()`, the store's maintenance pass, flagged the stuffed entry as one, so it was served first at relevance 1.0.

The adapter is `agmi/adapters/inspeximus_recall.py`; `python -m agmi.measure --target inspeximus` reproduces the row.

### langgraph-ledger

| | |
|---|---|
| Measured on | langgraph-ledger 0.3.0 over langgraph-checkpoint-sqlite 3.1.1, keyless chain, macOS arm64, Python 3.12 |
| What is targeted | The inner `SqliteSaver`'s `checkpoints` table, the memory the agent resumes from; the per-thread JSONL ledger beside it is left untouched |
| Seeded through | `TracingCheckpointSaver.put()`, which writes the checkpoint and appends a hash-chained `state/snapshot` event with the checkpoint's SHA-256 |
| Read back through | the inner `SqliteSaver`, unchanged |
| verify() | `verify_thread()`: chain intact, and every logged checkpoint still present in the saver with the logged digest |

An audit-time design, and a good one for what it logs: every checkpoint the ledger recorded is re-fetched by id and re-hashed, so a changed (T1), removed (T2, T3), swapped (T4), cross-thread (T6) or rolled-back (T7) checkpoint is named in the report. Two edits pass. A forged checkpoint appended past the tail (T5) was never logged, so the audit never looks for it, and on resume it is the head the agent continues from. A metadata edit (T8) passes because the digest covers the checkpoint and not its metadata column. The read path is plain LangGraph, so all eight are served on resume until someone runs the audit; the README is explicit that the keyless chain assumes a trusted head and that the head should be anchored outside the log, and that an attacker who also rewrites the ledger is out of scope keyless and in scope with `hmac_key`. The suite's edits touch the checkpoint store only, so the keyed mode measures the same here.

### memory-blackbox

| | |
|---|---|
| Measured on | memory-blackbox 0.1.1, macOS arm64, Python 3.12 (restart row first measured on 0.1.0) |
| What is targeted | A MEMORY.md memory file, one memory per line with a trailing HTML comment as its label; AGENTS.md stands in for the second context |
| Seeded through | the agent writes the file, then `MemoryMdAdapter.scan()` captures the write as a signed provenance record in the ledger |
| Read back through | the file itself, unchanged |
| verify() | `scan()` after the edit: a recorded write for MEMORY.md means the watcher saw a change the agent did not make |

memory-blackbox is a flight recorder: a BLAKE3 hash chain, a signed Merkle root and Ed25519 signatures protect its own ledger, and its README places it as post-incident reconstruction rather than a runtime block. The suite never edits the ledger. What it measures is the memory-file watcher, which keeps a digest of each watched file and records an out-of-band write for any file that changed since the last scan.

Two rows. With the agent process alive across the edit, every one of the eight edits changes the digest and is reported on the next scan, including the cross-context copy and the rollback, because the watcher compares bytes and not meaning. With the agent restarted between the edit and the scan, 0.1.0 served all eight: `baseline()` seeded the watcher from the file bytes, so an edit made while the agent was down became the trusted state and the scan had nothing to compare against. That position was reported privately to the maintainer under the project's SECURITY.md on 2 October 2026, held off this table meanwhile, and fixed the same day in 0.1.1 ([PR #31](https://github.com/lavkumarv/memory-blackbox/pull/31)): `baseline()` now takes the ledger's last write for each watched file as the trusted state, and a file the ledger has never seen is recorded once, so a cold start shows in the audit as a first-seen write rather than a mismatch. The maintainer ran this suite against the fix before tagging, and now runs the agmi Action in CI. Re-measured on 0.1.1, both rows report all eight. `tests/test_memory_blackbox.py` carries the reproduction (seed, scan, close, edit, reopen, baseline, scan) so the gap cannot come back unnoticed. In both rows the read path is the file, so the agent still acts on the edit until the scan runs.

### Atelya Attest

| | |
|---|---|
| Measured on | atelya-attest 0.1.1, macOS arm64, Python 3.12 |
| What is targeted | The chain file, one entry per memory event with `seq`, `event_id`, `ts`, the event payload, `prev_hash` and `curr_hash`; a second chain file stands in for the second context |
| Seeded through | `build_chain()` with an HMAC key, the way the README's quick start attests an op-log; the anchored row also checkpoints the head with `make_entry()` into a ledger in a separate directory |
| Read back through | the chain file itself, replayed |
| verify() | `verify_chain()`; the anchored row also runs `consistency()` against the last checkpoint |

Two rows from one package, because its README draws exactly this line. The chain alone names the first bad entry for a changed payload (T1), a middle deletion (T3), a swap (T4), a forged entry (T5), an entry copied from the other context (T6), an older entry over the newest (T7) and a changed timestamp (T8), since all of those break a sequence number, a link or a hash. Tail truncation (T2) passes, because a shorter chain is still a valid chain. The anchored row checkpoints the head (sequence, length, root) into a ledger the attacker cannot reach, and `consistency()` reports the truncation as history vanished below an anchored checkpoint: all eight. The chain is keyed in both rows; the README is clear that a keyless chain can be rewritten and re-chained by an attacker who holds the file, and that the anchor is the answer to that, which the suite's edits do not attempt. Detection is on the audit in both rows: the agent replays whatever the file holds until `verify` runs.

### CONTINUUM

| | |
|---|---|
| Measured on | continuum-agent 0.1.0 (Cyrax321/CONTINUUM), macOS arm64, Python 3.12 |
| What is targeted | The `events` table of one run in the SQLite store, one row per WORK_COMPLETED event with `sequence`, `event_id`, `type`, `timestamp`, `payload`, `prev_hash` and `hash`; a second run stands in for the second context |
| Seeded through | `SQLiteStorage.append_event()`; the attested row also signs the head with `sign_chain()` (Ed25519) into a document kept outside the store |
| Read back through | `project()` over `read_events()`, which rebuilds the agent's state after a restart |
| verify() | `verify_events()`; the attested row also runs what `continuum attest-verify` runs: signature valid, live head sequence and hash equal to the signed point |

The same boundary as Atelya, measured independently. `verify_events()` names a changed payload (T1), a middle deletion as a sequence gap (T3), a swap, a forged row, a cross-run copy, a rollback and a changed timestamp (T4 to T8) as tampered content at the sequence where it happened. Tail truncation (T2) passes, because the surviving rows still form a valid chain. With the signed head, `attest-verify` reports the truncation as the live head no longer matching the signed sequence: all eight. One store property shaped the edits: `event_id` is unique across the table, so a row moved into another slot keeps that slot's id and brings every other column; the hash covers the id, so the chain is designed to catch exactly that. The chain is keyless SHA-256 and the suite does not re-chain; the README's answer to a re-chaining attacker is the signed head, which the second row measures. Detection is on the audit in both rows: `project()` replays whatever rows are present until the audit runs.

### AtMem

| | |
|---|---|
| Measured on | atmem 2.3.8 from PyPI (wheel SHA-256 05ca2c57, code identical to the aetna000/atmem v2.3.8 tag), macOS arm64 and Linux x86_64, Python 3.12; remeasured 10 October 2026 |
| What is targeted | The `records` table of one `memories.db`, one row per memory with `id`, `subject_id`, `content`, `source_type`, `trust_tier`, `created_at`, `status`, `scope`; a second subject stands in for the second context |
| Seeded through | `Memory.remember()` on the trusted `user_message` path, which writes the record and appends `memory.record_created` to the audit chain with the record's `content_sha256`; the checkpoint row also calls `checkpoint()` into a JSONL file kept outside the store directory |
| Read back through | `Memory.list()` for the subject, in the engine's own order |
| verify() | `Memory.verify()` for the subject; the checkpoint row passes the checkpoints file |

From 2.3.8, AtMem binds each memory record to the integrity commitment its creation event carries in the audit chain, and `verify()` checks every active record against it. All eight record-level edits are reported on both rows: a changed, swapped, cross-subject, rolled-back or relabelled record no longer matches its commitment (T1, T4, T6, T7, T8), a deleted record is one the chain committed and the table no longer holds (T2, T3), and a forged record has no creation event (T5). `list()` still returns what is in the `records` table, so detection is on the audit, not the read path. A rollback of the whole store to an older genuine copy (T9) is consistent with itself and is reported only by the checkpoint row. The checkpoint result is conditional: it holds only while the checkpoints file stays outside the attacker's reach and is written again after every genuine write, which is how the row runs it; a checkpoints file the attacker can edit, or one left behind the newest genuine record, would serve the rollback too. On 2.3.7 the same eight record-level edits were served on both rows, because `verify()` recomputed the chain without comparing any record to it. The 2.3.8 result was submitted by the maintainer in PR #7 with the unchanged harness and reproduced independently from the published wheel on Linux and macOS before publication; it is pinned in `tests/test_atmem.py`. AtMem 2.3.8 requires cryptography below 49 while the Agent Memory reference runtime requires 50, so these rows are measured in their own environment and carried into the results file with `python -m agmi.merge_rows`.

### acrf-memory-guard

| | |
|---|---|
| Measured on | acrf-memory-guard 0.1.0, macOS arm64, Python 3.12 |
| What is targeted | A JSON store of signed entries keyed by id, the layout the package's CLI verifies; two users share one store and one secret, keys `ctx-A::nn` and `ctx-B::nn`, owner carried inside the signed entry as the README's `user_id` is |
| Seeded through | `sign_entry()`, HMAC-SHA256 over the entry's canonical JSON, secret from the environment |
| Read back through | `read_safe()` on each of the agent's entries, which raises `MemoryIntegrityError` on a mismatch or a missing signature |
| verify() | True if every entry of the first context passes `read_safe()` |

The first defended row measured from a product that claims tamper evidence. The package signs each entry's bytes and checks them on read, so a changed entry (T1), a forged one (T5) and a relabelled one (T8, the timestamp lives inside the signed entry) are refused before they reach the agent. The signature covers one entry and nothing about its slot, its neighbours or its count, so a missing entry leaves nothing to fail (T2, T3), two genuine entries swapped between slots both verify (T4), a genuine entry from the other user's slot verifies under this user's key even though the signed content names the other owner (T6), and an older genuine entry over the newest verifies (T7). The package's README says it does not protect against rollback; the measurement agrees and adds the other four. Binding the key into the signed input would close T4, T6 and T7; a previous-entry link or a signed count would close T2 and T3.

### MythologIQ Agent Memory reference runtime

| | |
|---|---|
| Measured on | agent-memory-reference 0.2.0 at commit f2aef57 (not on PyPI; `pip install "git+https://github.com/MythologIQ-Labs-LLC/agent-memory@f2aef57293b516e065cad5d0afea26ac7e3c28a9"`), macOS arm64, Python 3.12 |
| What is targeted | The `facts` table of `agent-memory.sqlite3`, one row per remembered fact, owned by `group_id`; the digest tables and the `configuration-binding.json` sidecar are left alone |
| Seeded through | `AgentMemory.open()` / `remember()` |
| Read back through | `AgentMemory.open()` / `recall()` |
| verify() | True if `open()` succeeds and `recall()` admits the seeded facts; `open()` raising `RuntimeRecoveryError` is a refusal on the read path |

The first row on the scorecard that refuses every record-level edit before the agent reads anything. Every canonical row is hashed into a bucketed Merkle digest, the governance log is hash-chained, and a sidecar binds the configuration to the last committed generation; `open()` fails closed on any mismatch, and the agent cannot read a fact without `open()`. Rollback of the SQLite file alone is refused by the generation binding. Two limits, pinned in `tests/test_agent_memory.py`: T9, rolling back the whole state directory, database and sidecar together, opens as current with the newest memory gone and no error, because the generation anchor lives beside the store it anchors; and the digests are unkeyed SHA-256, so an attacker who recomputes them is not caught by the digests alone, which is not one of the nine edits. The row was measured for the maintainers' own qualification of agmi as the integrity evidence for their durability benchmark ([MythologIQ-Labs-LLC/agent-memory#639](https://github.com/MythologIQ-Labs-LLC/agent-memory/issues/639)).

### Reference rows

`openfang(model,fixed)` is a Python re-implementation of OpenFang's hash-chained audit log, including the tip persistence fix from [openfang PR #1287](https://github.com/RightNow-AI/openfang/pull/1287). It proves the five attacks are detectable by a chained store. It is not a measurement of the Rust binary.

`naive-mem` is a deliberately undefended retriever. It exists so the memory-specific attacks have an undefended floor to compare real tools against; it fails every cell except user isolation. `reference-defended(model)` is the same store with provenance, quarantine and a stuffing check added, and it passes all four; the pair isolates what those three defences buy.

## Reading the scorecard honestly

- **`n/a` is information.** Which attacks apply depends on what a tool claims to be. An audit log cannot be memory-injected; a bare vector store has no chain to truncate. No tool faces all fifteen. The map of which cells apply is part of the finding.
- **"Accepted" is not "vulnerable to remote attack".** The attacker already has store access. The question is only whether the tool can tell.
- **Model rows are labelled.** Anything not measured against the real library says `(model)` in its name. Two appear in the headline tables, the OpenFang hash chain and the defended store, only to show that every cell can be passed; neither is a product.
- **Versions are pinned.** Each real target has a test asserting the measured result at the measured version. When a maintainer adds a check the test fails, the CI goes red, and the scorecard gets updated with the new version and a note. The weekly CI run does this against the latest release without anyone needing to remember.

## Writing an adapter

One file. Implement `MemoryAdapter` from `agmi/adapters/base.py`:


# second embedder, scale tier, and the live Mem0 tier (real key, its default infer=True mode)
PYTHONPATH=. python -m agmi.measure --target mem0 --embedder bge-small
PYTHONPATH=. python -m agmi.measure --target mem0 --embedder minilm --scale 1000
OPENAI_API_KEY=... PYTHONPATH=. python -m agmi.measure --target mem0-live --embedder minilm

# the results file every published table is generated from
PYTHONPATH=. python agmi/full_runner.py --json results/scorecard.json
PYTHONPATH=. python -m agmi.render results/scorecard.json docs/scorecard.md
```python
class MyToolAdapter(MemoryAdapter):
    name = "mytool-store"

    def setup(self): ...          # fresh, isolated store in a temp dir or scratch db
    def teardown(self): ...
    def seed(self, n): ...        # write n entries through the TOOL'S OWN API
    def read_all_raw(self): ...   # list[Record] in chain order, raw fields, bypassing the tool
    def write_raw(self, rec): ... # write one Record back, raw
    def delete_raw(self, seq): ...
    def reload(self): ...         # reopen the store the way a restart would
    def verify(self): ...         # the TOOL'S answer: True loaded fine, False it complained

    # Optional hooks for blob-based stores
    def mutate_payload(self, rec): ...  # change meaning without breaking encoding
    def forge_record(self, tmpl): ...   # a plausible new tip with a valid-looking id
```

Rules that keep a row honest:

1. Seed and verify through the tool's public API, never through the raw store.
2. `verify()` reports what the tool says. Do not compare content and call a difference "rejected".
3. Pin the version in a test, as `tests/test_langgraph_sqlite.py` does.
4. If the target needs a hosted model or an API key to run, nobody can reproduce it; find an offline path or mark the cell `n/a` with a reason.
5. Label anything that is not the real library `(model)`.

Then add the adapter to `full_runner.py` and open a PR with the new scorecard row.

## Where the attacks come from

None of the four front-door attacks is new; what is new is measuring named tools against them with one method and publishing the cells. The lineage, so readers can check the fixtures against the papers:

| agmi attack | The published attack it measures |
|---|---|
| `memory_injection` | MINJA, "A Practical Memory Injection Attack against LLM Agents" (Dong et al., 2025, arXiv:2503.03704): a plausible false memory planted through normal use and later retrieved as the user's own |
| `retrieval_hijack` | PoisonedRAG (Zou et al., USENIX Security 2025, arXiv:2402.07867) and AgentPoison (Chen et al., NeurIPS 2024, arXiv:2407.12784): entries crafted to be retrieved for a target class of queries |
| `indirect_prompt_injection` | "Not what you've signed up for" (Greshake et al., 2023, arXiv:2302.12173): instructions delivered to the model through retrieved content |
| `cross_session_bleed` | The isolation property in the IETF agent security benchmark draft (metric 5.4.4) and OWASP ASI06 |

The five at-rest edits come from the tamper-evidence literature on append-only logs (hash chains, Merkle logs) applied to agent stores; the paper gives the references.

## Scope, and what is not measured

- Measured on Linux (CI) and macOS (the maintainer's machine), Python 3.11 and 3.12. Windows is untested; Letta's embedded Postgres in particular has not been tried there.
- Letta's archival row models one user as one agent, which is how Letta separates users; a deployment that shares one agent between users has no isolation to measure.
- Fixtures are in English. A tokenizer or lexical ranker may behave differently on other scripts; non-English fixtures are later work.
- Mem0's published row uses `infer=False`. Its default `infer=True` mode, where a hosted model extracts facts before storage, is a separate opt-in tier (`--target mem0-live`) that needs a real key; it is measured and published only with the model and date named.
- The hidden-instruction cell measures delivery into context, not whether a model obeys.
- Rows are single, deterministic runs at the version shown. The scale tier (`--scale N`) and the second embedder (`bge-small`) are there to show a cell holds beyond the default fixture size and model; a cell is published as "holds under both" only once both have been run.
- The preprint describes 0.5, the at-rest family only. The front-door family, the positive controls and the fixture sets are documented here and in the October report.

## The memory agent

The scorecard measures a tool against fixed attacks. The agent does the opposite: point it at one target and it searches the attacks, channels and mutations for the first that gets a false memory served as trusted, proves each landing, and reports only what it proved with the exact steps to reproduce. That is the "proof, not a checklist" posture applied to memory. Every proven landing is a new fixture the benchmark can adopt, so the agent grows the scorecard from its own work.

```
python -m agmi.agent --target defended        # a library target
python -m agmi.agent --target mem0 --embedder minilm --json
```

On the undefended reference it lands all five write-based attacks in nine attempts; on the defended reference it searches over a hundred and lands only on the signed channel, reaching for the dilution mutation on the hijack, the exact hole the mutation engine found. Against the real tools it walks straight in:

| Target | Attempts | Findings | Channel of every finding | Mutation needed |
|---|---|---|---|---|
| Mem0 local Qdrant store, all-MiniLM-L6-v2 | 5 | 5 | external | none |
| LangGraph `SqliteStore`, all-MiniLM-L6-v2 | 5 | 5 | external | none |
| inspeximus 3.0.0, default | 5 | 5 | external | none |
| Letta archival memory, all-MiniLM-L6-v2 | 4 | 4 (no metadata filter, so that attack does not apply) | external | none |
| reference-defended (model) | 131 | 4 | agent-laundered only | dilute, on the hijack |

Measured 24 September 2026 on macOS arm64, Python 3.12. One attempt per attack means the first base fixture on the honest channel landed; nothing had to be disguised or laundered. The only target that made the agent search is the reference store, and the only channel it landed on there is the one no store can close. What "lands" means is the attacker's memory served back as trusted context for an innocent question, the tool-attributable step and the precondition for downstream harm; it is not the model obeying, which no portable suite can drive.

Two things keep the agent a security tool rather than an attack tool. An authorisation gate (`agmi/agent/authz.py`) runs before any target is touched and fails closed: a library target the caller already holds is allowed, a network host is allowed only on proven control (a host-named environment token or a consent file the operator writes), and anything else raises before the hunt starts. And the search is deterministic and offline by default, so the same target yields the same findings and the agent makes no network calls of its own beyond the target adapter's. Live HTTP targets, and an obedience oracle that watches for a canary action the model takes only if it believed the poison, are the next tier.

## Roadmap

agmi is built in phases. Each phase ships with the measurement that
proves it, and the scorecard columns follow the test method proposed
for IETF draft-han-bmwg-agent-security-benchmark metric 5.4.7
([bmwg list, 24 Sep 2026](https://mailarchive.ietf.org/arch/browse/bmwg/)).

| Phase | Scope | Status |
|---|---|---|
| 0.1 to 0.5 | Attack catalogue, adapter interface, five at-rest edits measured on LangGraph, Letta and Mem0; inspeximus rows from its maintainer, reproduced independently; preprint, software DOI, PyPI | done |
| Phase 1 | Three attacker channels (external, laundered, agent-laundered), signed writes, attacker level on every cell; provenance alone can no longer pass a content cell | done |
| Phase 2 | Mutation engine on every attacker write; update poisoning and metadata poisoning as attacks five and six; twelve-column scorecard on four real stores | done |
| Memory agent, v1 | Hunt loop over six attacks, three channels and mutations; proof and reproduction script per finding; authorisation gate that fails closed | done |
| 0.6.0 | Eight at-rest edits T1 to T8 (adds cross-context replay, rollback replay, metadata tamper) with control cases and read/audit detection points, matching the proposed 5.4.7 method | done |
| 0.6.1 | Control C3, the landed guard, on every edit; the defended rows (acrf-memory-guard, langgraph-ledger, memory-blackbox, Atelya Attest, CONTINUUM) and the LangGraph Postgres and Redis checkpointers; findings filed with LangChain, OpenAI and LlamaIndex; method text in IETF BMWG and OWASP AIMM | done |
| 0.6.2 | memory-blackbox restart row, before and after the maintainer's fix (0.1.1), the first store fix driven by the suite; every scorecard row links to the code it measures | done |
| 0.6.3 | T9 snapshot rollback with its own landed control, measured on every at-rest row; the Agent Memory row, accepted by its maintainers as external integrity evidence (#639, #650); the CrewAI row; the memory agent's storage-side hunt and composition engine, which found and closed a truncate-then-write launder in the reference store | done |
| 0.6.4 | Managed stores, measured through the data-plane API because a managed store has no other door: Google Vertex AI Memory Bank and AWS Bedrock AgentCore Memory, both on the board | done |
| 0.7.0 | T10, erasure resurrection, with its own landed control, and `agmi.merge_rows` so a new column does not lose rows measured in other environments; the scorecard published as a W3C v0.1 per-check report, held to the results file in CI; rows for Surgical DevOps G7, Recallspection, HDP, OpenClaw and Hermes; the contributor path and a site built from the results file | done |
| 0.7.1 | Hosted stores measured through their front door only: Zep, Letta Cloud; Graphiti | next |
| Phase 3 | Live targets over HTTP (MCP memory servers, deployed LangGraph and Letta) behind the authorisation gate; obedience oracle that proves the agent acted on the poison; ingestion marking measured on each framework | planned |
| Phase 4 | Memory agent driving content-only attacks through a real model, with the same proof discipline | planned |
| 0.9 | Deserialization safety (stored payloads that execute on load) and a reference integrity layer: a hash chain over checkpoint ids, offered upstream as an optional mode | planned |
| 1.0 | Stable adapter interface, published conformance levels, vendor badges, monthly report cadence; hosted runs through AuditTrax Labs, with the open benchmark free | planned |

Standards position: the eight-edit method, verdict rules and control cases were sent to the IETF BMWG list as proposed text for metric 5.4.7 of draft-han-bmwg-agent-security-benchmark. If no revision takes it up, it will be filed as a companion Internet-Draft.

## Contributing, security, citation

- Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md). New real-library adapters are the most valuable thing you can send.
- Security: agmi finds design gaps and discusses them in public. If you find an actual vulnerability in a target using this suite, see [SECURITY.md](SECURITY.md) and do not open a public issue.
- Changes: [CHANGELOG.md](CHANGELOG.md).

If you use agmi in a paper, a review or a procurement decision, cite it:

```
Yasha Khandelwal (2026). agmi: Agent Memory Integrity, a conformance test suite for
tamper evidence in AI agent memory and checkpoint stores. https://github.com/tech4biz-yasha/agmi
```

MIT licensed. Copyright (c) 2026 Yasha Khandelwal, yasha.khandelwal@tech4biz.io.
