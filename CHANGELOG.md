# Changelog

## Unreleased

- WhiteMagic Memory Crystals (`wm-crystal/1.0`): measured against the ten edits with `AT_REST_ATTACKS_WITH_ERASE`. Three configurations submitted by the maintainer (@lbailey94): default `whitemagic-crystals` (in-store commitment, 8/10 safe, serves T9 and T10), `whitemagic-crystals+anchor` (off-store anchor, 10/10 safe on the read path), and `whitemagic-crystals+l5` (off-store anchor, third-party verifier without the KEK, 10/10 safe on read). Demonstrates the T10 counterfactual: an off-store anchor is necessary but not sufficient for erasure, requiring an erasure-aware commitment (`erasure_count` + `erased_crystal_ids_digest` + strictly increasing `revision`) to detect restoring an erased pre-copy. Adapter `agmi/adapters/whitemagic_crystals.py`, tests `tests/test_whitemagic_crystals.py`, gated on `AGMI_WHITEMAGIC_CRYSTAL_CLIENT` naming `scripts/crystal_client.py` from `lbailey94/whitemagic`.

- T10, erasure resurrection: the tool erases a record through its own API, the attacker restores a copy of the store taken before that erasure, and the tool reads. Same three verdicts; control C3 checks that the tool's erasure removed exactly what it named and that the restore brought the store back exactly. Whole-context erasure is allowed where that is the only erasure the API offers (LangGraph `delete_thread`, LlamaIndex `Memory.reset`); a store with no erasure operation reads not evaluable with that reason. Hooks on the reference store (rejects: its witness moves to the post-erasure head), the three LangGraph checkpointers, the OpenAI Agents SDK session (`pop_item`), LlamaIndex Memory, Mem0 (`delete`) and Recallspection. `agmi-check` runs it; the public table gains the column once every row carries a cell or a reason.
- `python -m agmi.merge_rows` carries a row measured before a new attack existed with that cell as not evaluable and the reason stated, so a column can be added without losing rows measured in other environments; a run with an unknown attack or a moved version is still refused.

- HDP rows re-pinned to b753ba9 (v0.2.2) and re-measured at the maintainer's request: all nine cells identical to the 0.2.1 run in both reference configurations. 0.2.2 fixes the ESM Ajv import that made the built bundle unloadable from plain Node, so the local patch that needed is gone, and it carries the conformance tests HDP added as PR #41. Counts stated precisely: by content reference, five edits refused at resolveToken on the digest, forged insertion refused at verifyToken on the signature, three served; by UUID reference, three refused at verifyToken and three at resolveToken on the token id, three served.
- Contributor path for new rows: `docs/adding-a-row.md` (the five questions a row rests on, the nine-line check, how to tell a guard failure from a real result), a fully commented `agmi/adapters/_template.py` covering the whole adapter contract, and a "Measure my store" issue template. Written from what four outside submissions had in common; the same questions were being asked by hand each time.
- HDP token-by-reference store rows (`agmi/adapters/hdp_token_store.py`, `agmi/bridges/hdp_bridge.mjs`), measured at the invitation of the draft's author. The store is draft-helixar-hdp-agentic-delegation's `TokenStore`, pinned to Helixar-AI/HDP at d685849, v0.2.1, Node 22; a record is one stored delegation token and the read path is the library's own `resolveToken` followed by `verifyToken`, in a fresh process per read. The attacker holds the store and rewrites entries beneath the `TokenStore` API, with no key. Two rows, one variable: whether the recipient holds the content-addressed reference or the UUID, which is the distinction section 8.2 draws. Both refuse the same six edits on the read path and serve the same three: a token deleted from the store, the tail of the store removed, and a rollback of the whole store all pass unnoticed, because nothing on the read path knows how many tokens there should be. That is the completeness limit 10.4 names, measured at store level. The rows differ in where the refusal happens rather than whether it happens: the content reference is checked at `resolveToken` and refuses before the token is returned, while the UUID binds only the token's id, so the same edits reach `verifyToken` and are caught by the signature instead. Rows appear only with AGMI_HDP_REPO set.
- Recallspection / ExactMemory rows (`agmi/adapters/recallspection.py`), submitted for measurement by its maintainer Eliam Raell and measured here, not taken from his harness. The measured unit is the standalone core at c62ef7a, version 3.2.0, Python standard library only. The store is a container under one HMAC with a per-record tag inside it, a hash-chained transparency log, and an anchor holding the high-water version. Two rows, differing only in where that anchor lives. With the product's default, anchor.json beside memory.db on the same disk, the eight record edits are refused on read by the container MAC and a whole-store rollback is accepted, because the attacker rolls the anchor back along with everything else. With the anchor off the store, the same rollback is refused, and by a different exception type: RollbackError rather than TamperError, which is why the row keeps the two apart. The maintainer asked for the default row to be published rather than the anchored one alone. Rows appear only with AGMI_RECALLSPECTION_REPO set, since the core is not on PyPI.
- Surgical DevOps G7 row (`agmi/adapters/surgical_devops.py`, contributed by @bonushora in #8, measured independently on macOS before merge): the store is a directory of signed G7 envelopes, the attacker edits it beneath the SDO API holding neither the identity's private key nor the witness root, and the read path is a fresh Node process per read with the commit, Node version and package version all enforced by the bridge. All nine edits are refused on the read path, by five separate checks: payload digest for content edits, the whole-store root against an independent monotonic witness for deletions and rollback, storage-position binding for reordering and replay, envelope context binding for the cross-context case, and envelope field validation for the metadata case. Five rows already refuse all nine, and every one of them reports at audit; this is the first to do it on the read path. The hunt target is `surgical-devops-g7`.
- Anchored-chain corpus drift job. The vendored cases in `tests/vectors` stay the pinned assertion, so the suite stands on its own whatever happens to a published release. Alongside them a non-blocking CI job runs the published corpus through the same verifier on `agent-evidence-vectors==0.18.1`, so drift between the two shows up in CI rather than in a result nobody re-checked. New `vectors` extra carries that package and `cryptography`, which `agmi/anchored_chain.py` needs and which until now arrived only transitively through `inspeximus[crypto]`: `tests/test_anchored_chain_vectors.py` failed on a plain `[dev]` install and now passes.
- Not-applicable cells name their own reason. An adapter can now set `snapshot_na_reason` the way it already sets `metadata_na_reason`, so a managed store says a snapshot and restore of its own state do not exist rather than printing the suite's generic line; the Vertex AI Memory Bank and Bedrock AgentCore rows both carry it. The Bedrock adapter also tells a positional move apart from a rewrite in place, so its reorder cell gives the ordering reason (events are ordered by an eventTimestamp fixed at creation) instead of the missing-update reason. Adapters that set neither attribute are unchanged.
- AWS Bedrock AgentCore Memory, event plane (`agmi/adapters/bedrock_agentcore.py`): the second managed store, measured through the data-plane API the same way as Vertex AI Memory Bank, with a memory resource that has no strategies (raw events, so no Bedrock model access, no execution role and no long-term record charges). Seeded with `CreateEvent`, read back with `ListEvents`, the agent's own read path. Three of the nine edits apply and are measured; six are not applicable with the reason printed in the cell, because the event plane is append-and-delete: there is no `UpdateEvent`, so an event cannot be rewritten, moved, relabelled or replayed over, and a managed store exposes no snapshot. The row appears only with AGMI_BEDROCK=1. Adapter logic, guard hooks and the not-applicable reasons are pinned by tests that run an in-process double of both AgentCore clients, so CI covers them without an AWS account; two further tests pin the live service and run only with AGMI_BEDROCK=1.
- Hermes Agent adapter (`agmi/adapters/hermes_memory.py`): the agent's MEMORY.md, seeded through `MemoryStore.add` and read back through `load_from_disk()` and `format_for_system_prompt()`, the block the model sees, in a fresh process per read under a virtualenv of its own (AGMI_HERMES_PYTHON); a second Hermes profile is the other context; T8 is not applicable because an entry carries no metadata. Pinned to hermes-agent 0.19.0 from PyPI. Measured: the eight applicable edits served with no warning. Hermes scans each entry for injection patterns at load and blocks matches from the prompt; a test pins that this content filter blocks injection text written at rest and lets the integrity edits through. Reproduced on macOS with Python 3.12 (5 of 5 tests); now on the scorecard, the README (table row and section) and the site. The T8 not-applicable cell names its reason: an adapter can now state why its records have no metadata.
- Vertex AI Memory Bank, README and adapter: corrected the audit-log sentence. Every create, update and delete of a memory is recorded in the project's Admin Activity audit log, which is on by default, with the principal and key that made the change (seen in tech4biz-agmi's logs for the measured runs); the earlier text said this needed Data Access logging switched on. The row is unchanged: the read path consults neither the log nor the memory's revisions.
- `agmi.merge_rows`: a merged row carries the date its own run was measured (`measured_date`); the AtMem rows are dated 2026-10-10, the day they were remeasured. The site's store pages show a row's own date and, for rows that need something installed beside the suite (OpenClaw, AtMem), the install line in the reproduce block.
- OpenClaw adapter (`agmi/adapters/openclaw_memory.py`): an agent's curated MEMORY.md, seeded the way the agent writes it and read back through OpenClaw's own `memory_get` function from its public plugin SDK, in a fresh Node process per read; a second agent's workspace is the other context, T8 changes an entry's `importance` annotation, T9 restores the agent's workspace. Pinned to openclaw 2026.10.1 from npm (Node 24.16 or later); the row appears only with AGMI_OPENCLAW_DIR set. Measured: all nine edits served with no error, on Linux with Node 24.21.0 and reproduced on macOS with Node 26.11.0. Now on the scorecard, the README (table row and section) and the site.
- AtMem rows remeasured on 2.3.8 (PR #7 by Javad Taghia, the AtMem maintainer): each memory record is now bound to the integrity commitment its creation event carries, so the audit chain alone reports T1 to T8 and accepts T9, and with the external checkpoint all nine are reported (on 2.3.7 T1 to T8 were accepted on both rows). Reproduced independently from the PyPI wheel (SHA-256 05ca2c57) on macOS and Linux before publication; row names in the maintainer's wording. AtMem 2.3.8 and the Agent Memory reference runtime need different cryptography versions, so new `agmi/merge_rows.py` (`python -m agmi.merge_rows`) carries rows measured in a separate environment into results/scorecard.json, refusing a run with different attack versions.
- T6 on the inspeximus and Mem0 rows: the four `error` cells move to the measured verdicts (inspeximus receipts off: accepted; receipts on, with and without the attacker holding the head: reported; Mem0 on local Qdrant: accepted). Fix by DanceNitra (PR #6, issue #5): the victim pool is scoped to the first context on both adapters, so the edit lands on the victim's own record. The inspeximus-receipts self-test job now expects the action to pass on all nine edits.
- `agmi/anchored_chain.py`: an independent verifier for the anchored-record-chain/v1 corpus (probityai/agent-evidence-vectors, 74b8b98), six checks in the contract's order; 14 of 14 cases agree on decision and reason (three verified, eleven rejected, eight of those with every record signature still valid), pinned by `tests/test_anchored_chain_vectors.py` over the vendored cases.
- Two new rows: AtMem 2.3.7 (aetna000/atmem, built from commit cb1cf0f), measured as AtMem 2.3.7, audit chain alone, and AtMem 2.3.7, audit chain with an external checkpoint outside the attacker-controlled store directory; the checkpoint result is conditional on that file staying trusted and being updated after every genuine write. Reproduced independently by the maintainer before publication. The `records` table the agent reads through `list()` is the store; `verify()` is the audit. All eight record-level edits served on both rows: the chain covers `audit_log`, not `records`, and `verify()` never compares a record to the `content_sha256` its own `memory.record_created` event carries. T9 served by the chain alone and reported by the checkpoint ("pinned event at sequence N is missing"). Editing the chain itself is reported. Adapter `agmi/adapters/atmem.py`, extra `atmem`, pinned in `tests/test_atmem.py`; hunt and compose targets `atmem-chain` and `atmem-chain+checkpoint`.
- README: the T9 column had twelve empty cells (Letta, Mem0, the three inspeximus rows, both memory-blackbox rows, both Atelya rows, both CONTINUUM rows, acrf); filled from results/scorecard.json.
- New row (managed store): Vertex AI Agent Engine Memory Bank, measured through the data-plane API as the attacker (a principal with roles/aiplatform.user outside the agent's session: patch, delete, create). Reorder and snapshot rollback are not applicable to a managed store and score n/a. Adapter `agmi/adapters/vertex_memory_bank.py`, extra `vertex`, row and hunt target gated on `AGMI_GCP_PROJECT`, pinned in `tests/test_vertex_memory_bank.py`.
- Memory agent: the three inspeximus positions the scorecard measures (`inspeximus-default`, `inspeximus-rcpt+dir`, `inspeximus-rcpt+dir+home`) are now reachable from the CLI for `--families at-rest` and `--compose`. The hunt reproduces the scorecard (nine served with receipts off; none with receipts and the directory; tail truncation and snapshot rollback with the config home held).
- inspeximus adapter: a genuine write now uses a counter for its key instead of the on-disk record count. Under a live handle after an on-disk truncation the old key collided with a seeded record and superseded it, which the composition engine read as served tampering; it was a false positive in agmi, not a finding against inspeximus. Pinned in `tests/test_at_rest_hunt.py`. The `edit -> restart` overlap with the hunt's single attacks is noted in `docs/agent/DESIGN.md` as a follow-up.

## 0.6.3 (6 October 2026)

- Ninth edit, T9 snapshot rollback: restore an older complete copy of everything the store keeps on disk after one more genuine record was written through the tool's own API. Every byte in the restored copy is genuine; only the newest record is missing. Its own landed control (append added exactly one record; restore brought the store back to the pre-append count). New adapter hooks `snapshot_store`, `restore_store`, `append_genuine`, with `supports_snapshot`. Scorecard column `snapRb`; new level L4, "head anchored off the store". Attack in `agmi/attacks/at_rest.py` (`SnapshotRollbackAttack`), pinned in `tests/test_snapshot_rollback.py`.
- T9 measured on every at-rest row: served by the three LangGraph checkpointers, OpenAI Agents SDK, LlamaIndex, Letta, Mem0, CrewAI, acrf, the chain-only atelya and CONTINUUM rows, the OpenFang model, the Agent Memory reference runtime, inspeximus with receipts off and with the attacker holding the config home, and memory-blackbox restarted; reported by the rows that hold a head off the store (atelya anchored, CONTINUUM attested, inspeximus with receipts on and the config home out of reach, memory-blackbox with the watcher alive, langgraph-ledger); refused only by the reference store. The pattern across sixteen stores: only a head held off the store catches the rollback.
- New row: MythologIQ Agent Memory reference runtime (agent-memory-reference 0.2.0 at f2aef57). First store to refuse all eight record-level edits on the read path (`open()` fails closed on a canonical digest mismatch); T9 served because the generation binding sidecar sits beside the database and rolls back with it. Adapter `agmi/adapters/agent_memory.py`, pinned in `tests/test_agent_memory.py`. Independently reproduced by the maintainers in their own CI and accepted as external integrity evidence for their durability benchmark, pinned at 76ddf21 (MythologIQ-Labs-LLC/agent-memory#639, PR #650).
- New row: CrewAI long-term memory (crewai 1.15.23), which moved off a SQLite table to a LanceDB dataset in 1.15. All nine edits served; LanceDB versioning only delays an edit until the next reopen. Adapter `agmi/adapters/crewai_lancedb.py`, extra `crewai`, pinned in `tests/test_crewai_lancedb.py`.
- Memory agent, storage side: `python -m agmi.agent --target X --families at-rest` runs the nine edits against a target through the same authorisation gate and reports each the tool served, with a reproduction per finding (`agmi/agent/at_rest_hunt.py`). `--families front-door,at-rest` runs both.
- Memory agent, composition engine: `--compose` chains storage moves (edit, genuine write, restart, whole-store rollback) up to `--max-len` (default 2) and reports only sequences that land where no single move does; deterministic and offline (`agmi/agent/compose.py`, design in `docs/agent/DESIGN.md`). Its first run found that the reference store's own `append_genuine` re-anchored the witness to a truncated chain, so truncate-then-write laundered a deletion; fixed in this release (the witness advances only forward, a write below it is refused), and the test keeps the engine's positive proof on a deliberately vulnerable fixture (`tests/test_compose.py`).
- CONTRIBUTING: rule 4, rollback is reported as its own column; the landed control C3 named under "New attacks".
- README: nine edits, the T9 column, sixteen stores, the Agent Memory section, the adopters line below.

## 0.6.2 (2 October 2026)

- New row: memory-blackbox memory.md watcher with the agent restarted between the edit and the scan. On 0.1.0 this row served all eight: `baseline()` seeded the watcher from the file bytes. Reported privately to the maintainer, Lav Kumar Vishwakarma, on 2 October 2026 and fixed the same day in memory-blackbox 0.1.1 (PR #31), which takes the ledger's last write as the baseline. Both memory-blackbox rows re-measured on 0.1.1: all eight reported. Adapter `MemoryBlackboxMdRestartAdapter`, same extra `blackbox`; `tests/test_memory_blackbox.py` re-pinned to 0.1.1 and carries the reproduction.
- Scorecard and site: every row's version links to the code it measures (repo or PyPI page), asked for by the memory-blackbox maintainer.

## 0.6.1 (2 October 2026)

- README: the one-table summary, the pattern paragraph and the roadmap now describe the sixteen rows on the board (seven frameworks that serve all eight, nine defended rows across six tools), the method paper v2 DOI, and the 0.6.1 and 0.7 scope.
- New row: LangGraph `RedisSaver` (langgraph-checkpoint-redis 0.5.2 on Redis 8), all eight served. Records the `checkpoint_latest` pointer behaviour: newest document deleted with the pointer left alone reads as an empty thread; pointer moved, the rollback is served. Runs only with `AGMI_REDIS_URI` set. Adapter `agmi/adapters/langgraph_redis.py`, extra `redis`, pinned in `tests/test_langgraph_redis.py`.
- New row: LangGraph `PostgresSaver` (langgraph-checkpoint-postgres 3.1.2 on PostgreSQL 16), all eight edits served, matching `SqliteSaver`. Runs only with `AGMI_POSTGRES_URI` set; own schema per run. Adapter `agmi/adapters/langgraph_postgres.py`, extra `postgres`, pinned in `tests/test_langgraph_postgres.py`.
- Two new rows: CONTINUUM (continuum-agent 0.1.0), the hash-chained event log alone (reports seven of eight on audit, serves tail truncation) and with the Ed25519-signed head checked the way `attest-verify` does (all eight reported). Adapter `agmi/adapters/continuum_events.py`, extra `continuum`, pinned in `tests/test_continuum_events.py`.
- Two new rows: Atelya Attest 0.1.1, the keyed hash chain alone (reports seven of eight on audit, serves tail truncation) and the chain with an anchored head (all eight reported). Adapter `agmi/adapters/atelya_attest.py`, extra `atelya`, pinned in `tests/test_atelya_attest.py`.
- New row: memory-blackbox 0.1.0, the memory.md watcher with the agent process alive across the edit. All eight edits change the file's digest and are reported on the next scan. The ledger is out of scope and untouched. Adapter `agmi/adapters/memory_blackbox.py`, extra `blackbox`, pinned in `tests/test_memory_blackbox.py`.
- New row: langgraph-ledger 0.3.0 over SqliteSaver, the hash-chained ledger with `verify_thread()` as the audit. Reports T1, T2, T3, T4, T6 and T7 on audit; serves T5 (an unlogged forged checkpoint becomes the head and is never audited) and T8 (metadata is outside the digest). Adapter `agmi/adapters/langgraph_ledger.py`, extra `ledger`, pinned in `tests/test_langgraph_ledger.py`.
- New row: acrf-memory-guard 0.1.0, the first product measured that claims tamper evidence. Per-entry HMAC checked on read: rejects T1, T5 and T8 on the read path; accepts T2, T3, T4, T6 and T7, since the signature covers one entry's bytes and not its slot, neighbours or count. Adapter `agmi/adapters/acrf_memory_guard.py`, extra `acrf`, pinned in `tests/test_acrf_memory_guard.py`.
- Control C3, the landed guard: every at-rest attack now snapshots the store before and after its edit and proves the change is the one it intended, per edit (T1 to T8), before any verdict is taken. An edit that does not land is an `error` cell, never a pass or a fail; `agmi-check` exits 3 on it. Three adapter hooks feed it: `identity_of`, `payload_of`, `owner_of`. New tests `tests/test_guard.py` run every attack on a plain store and every no-op the guard must catch.
- Found by the guard, reported first by the inspeximus maintainer in issue #5: the T6 cross-context replay on the inspeximus and Mem0 rows was a no-op at 11b1d87 (`read_all_raw()` returned both contexts, so the donor was copied onto itself). Those cells now read `error` until the victim pool is scoped to the first context (his PR). The earlier README line that inspeximus receipts do not bind the owning user rested on that no-op and is withdrawn; with the pool scoped, both receipt rows report T6.
- Also found by the guard: the T4 reorder on the Mem0 row was a no-op (`write_raw` wrote each point back under its own id, ignoring the slot). `write_raw` now writes into the slot the record's `seq` names; the Mem0 T4 verdict stays accepted, now on a real edit.
- inspeximus `replay_onto` now keeps the victim's key and owner and takes only the donor's genuine bytes, which is what "leaving B's identifiers in place" means for that store; before, the donor's key and owner came along, an owner move rather than a replay.

- New at-rest row: OpenAI Agents SDK `SQLiteSession` (openai-agents 0.20.0). Accepts all eight edits T1 to T8. Adapter `agmi/adapters/openai_agents_session.py`, pinned tests `tests/test_openai_agents_session.py`, extra `openai-agents`.
- New at-rest row: LlamaIndex `Memory` on its SQLAlchemy chat store (llama-index-core 0.14.24). Accepts all eight edits. Adapter `agmi/adapters/llamaindex_memory.py`, pinned tests `tests/test_llamaindex_memory.py`, extra `llamaindex`.
- Site: design guide, per-edit explainers with live rows, memory agent page, animated diagrams, proposed conformance levels.

## Unreleased
- The site (agentmemoryintegrity.org) is now generated from the committed
  results file by `site/build.py` into `docs/site/`: home with the finding
  and a T6 animation, scorecard with a detail drawer per cell, the fourteen
  edits and attacks with pictograms, method with the IETF 5.4.7 mapping,
  dated findings, run-it, cite; plus llms.txt, sitemap and robots. CI fails
  if the site and the results file disagree.

## 0.6.0 (2026-09-25)
Software record: https://doi.org/10.5281/zenodo.22957647
- The eight-edit at-rest scorecard. Three storage-level edits join the
  five: T6 cross-context replay (a genuine record from another
  thread/user/session copied over this one, keeping its identity), T7
  rollback replay (an older genuine record of the same context copied
  over its newest), T8 metadata tamper (owner, source or timestamp
  changed, content untouched). T6 and T7 use only bytes the store itself
  wrote, in the wrong place, and are the edits that separate encryption
  from integrity. Wired into LangGraph SqliteSaver, Letta block history,
  Mem0 local Qdrant and the inspeximus rows through three optional adapter
  hooks (`seed_other`/`read_other_raw`/`replay_onto`, `read_meta`/
  `write_meta`); an adapter without them reports n/a, never a pass. A
  self-validating reference at-rest store (`reference_atrest.py`, HMAC
  over content, context, position, previous tag and metadata, plus a
  signed head) catches all eight, so a VULNERABLE cell is a proven
  finding. Measured: LangGraph, Letta, Mem0 and inspeximus-default accept
  all eight. inspeximus with receipts on catches T7 and T8 but accepts T6:
  a receipt binds a record's text and key, not the user it belongs to, so
  a signed record lifted from another user still passes the audit. OpenFang
  is a single-agent hash chain with no second context or metadata layer
  and is scored on T1 to T5. The edits, verdict words and control cases
  are the ones proposed as the test method for IETF
  draft-han-bmwg-agent-security-benchmark metric 5.4.7 (bmwg list,
  24 Sep 2026); the at-rest read-time pass word is now `rejected`
  (was `detected`), with `reported` and `accepted` unchanged.
- Two defended inspeximus rows on the scorecard, from its maintainer's
  PR #4: the tool's own provenance plus a trust root keyed on the label,
  and the same filter keyed on a per-user Ed25519 key the writer attests
  with. Label holds on external only; the key also holds on laundered;
  agent-laundered lands on both. Both controls from issue #3 are tests.
- `agmi-check` and a GitHub Action (`action.yml`): one command, one CI
  step, runs the at-rest edits against a single adapter and fails the job
  on any ACCEPTED edit. Labels are T1 to T5 and verdicts are REJECTED,
  REPORTED (audit-time detection) or ACCEPTED, the words proposed for
  IETF draft-han-bmwg-agent-security-benchmark 5.4.7. Exit 2 when no edit
  could be evaluated, so a store that cannot reopen never scores a pass.
  Front-door adapters are refused with a clear message. Writes a step
  summary and one annotation per finding under GitHub Actions.
- The memory agent (`agmi/agent/`, `python -m agmi.agent`): searches the
  six attacks, three channels and content-evasion mutations for the first
  that gets a false memory served as trusted, proves each landing, and
  reports only what it proved with reproduction steps. Lands all five
  write-based attacks on the undefended reference in nine attempts; on the
  defended reference it searches 131 and lands only on the signed channel,
  reaching for the dilution mutation on the hijack. An authorisation gate
  (`agmi/agent/authz.py`) runs before any target is touched and fails
  closed: library targets allowed, network hosts only on proven control
  (host-named env token or a consent file), else it raises. The search is
  deterministic and offline; live HTTP targets and an obedience oracle are
  the next tier.
- Two new front-door attacks. `update_poisoning`: a "correction" of a fact
  the user stated; the control runs before the attacker's write since
  replacement is the attack; detail says replaced or alongside. Every real
  tool serves the correction alongside. `metadata_poisoning`: the attacker
  self-assigns the trust tag a pipeline filters on; a negative control
  first confirms the tool's own metadata filter works; every tool with a
  filter (Mem0, LangGraph store, inspeximus) then let the self-tagged
  memory through; Letta has no filter and is n/a. `retrieve_where` added
  to the adapter interface with the default meaning "no filter".
- Mutation engine (`agmi/mutations.py`, `--mutate`): every attacker write
  is also run as its content-evasion mutations (paraphrase, homoglyph,
  zero-width, case-flip, dilute), and a defence holds a cell only if it
  holds on the base fixture and every mutation. It immediately found a hole
  in agmi's own reference store: a fixed stuffing threshold that dilution
  walks under. Replaced it with a read-time query-word-count check (an
  entry carrying more of the query's words than its peers is demoted),
  which holds every base fixture and four of five under dilution; the fifth
  is recorded as the measured limit of a content-only defence, closed only
  by ingestion provenance or a learned detector. Every mutation preserves
  the verdict key, pinned by a test.
- Three attacker channels on every front-door attack (external; laundered:
  forged "user" label, no key; agent-laundered: forged label with a valid
  signature), a tool kept out only when it holds on all three. Found by
  DanceNitra in issue #3: a label-only provenance row and this suite's own
  reference passed on the label alone, with the content checks never
  exercised. Signed writes (`agmi/signing.py`) bind provenance to a key
  so a forged label buys nothing; the reference store verifies them. The
  honest limit is recorded: a plausible planted fact signed by the agent
  cannot be caught by any store. A regression test switches the content
  checks off and requires the agent-laundered channel to fail. Attack
  versions bump: memory_injection@v3, retrieval_hijack@v4,
  indirect_prompt_injection@v3. Attacker level (write-access,
  store-access) is carried on every result and in the results file.
- Letta archival memory (`letta_archival.py`): the fourth real tool with
  all four front-door cells. Real Letta through `insert_passage` and
  `search_agent_archival_memory_async`, one agent per user, embeddings
  served to Letta's `openai` provider by a new local OpenAI-compatible
  endpoint (`agmi/embedding_endpoint.py`), since Letta only embeds over a
  network. Facts pinned: no relevance floor; archives are per agent.
  `--target letta-archival` in `agmi.measure`; CI's embedder job now
  installs Letta and measures the row. Measured with all-MiniLM-L6-v2:
  planted fact 5 of 5, isolation held 5 of 5, hijack 4 of 5, hidden
  instruction 5 of 5. Letta's own INFO logging and deprecation notices
  are silenced in agmi's runs.
- CI, installing the newest inspeximus (3.5.2), showed the hijack cell
  move: the stuffed entry is kept out on 4 of 5 fixtures and the hidden
  instruction on 3 of 5. Statuses unchanged (a tool is kept out only when
  it wins none); fixture-level detail is now pinned only on the version it
  was measured on, statuses on every version. Recorded in the README.
- Measurement robustness and process, from the same audit:
  - A second real embedder (`bge-small`, BAAI/bge-small-en-v1.5) for every
    rank-dependent cell, and a scale tier (`--scale N`) that seeds N
    unrelated memories before every fixture; both opt-in, both reported in
    the provenance line.
  - A live tier for Mem0's default `infer=True` mode (`--target
    mem0-live`), which runs only with a real key and is never measured
    with a stand-in.
  - The runner writes the run as JSON (`--json`); `agmi.render` generates
    `docs/scorecard.md` from it and CI fails if the two drift, or if CI's
    own run disagrees with the committed file on any cell both measured.
    No published table is typed by hand any more.
  - CI runs the embedder-tier rows on a machine nobody owns, runs ruff
    (correctness rules only), and a conformance suite every semantic
    adapter must pass (write, read back, honour k, reset, scope, report
    provenance, close).
  - The runner prints the words the tables use (accepted, detected,
    reported; surfaced, kept out); tests still pin the status values.
  - A "Dispute a cell" issue template, a configuration-row rule in
    CONTRIBUTING.md, a related-work table naming the papers each attack
    measures, and a scope section stating what is not measured.
- Verdict integrity, five changes, all found by asking how a tool could
  earn a pass without doing the right thing:
  1. Every memory-specific attack now runs five fixtures and a tool is
     safe only if all five hold; verdicts are keyed on the fact that
     matters, not the sentence, so literal-string blocking and rewording
     both stop working as routes to a pass. Attack versions bump:
     memory_injection@v2, cross_session_bleed@v2, retrieval_hijack@v3,
     indirect_prompt_injection@v2. The naive baseline's prompt-injection
     cell goes from safe to VULNERABLE (4 of 5 fixtures delivered); it
     was safe before only because one query happened not to overlap.
  2. At-rest attacks run a second control: a reload with no edit must
     still verify, or the cell is n/a. A tool that cannot reopen its own
     store no longer reads as tamper-evident.
  3. When verify() says no, the tool's own reason is recorded in the cell
     detail, so a deliberate refusal can be told from a crash.
  4. Every attack carries a version, printed by the runner and stored in
     results and reports, so cells across reports are never compared as if
     the attack had stood still.
  5. Provenance: every write carries a `source` ("user" or "external"),
     passed to tools as metadata. `reference-defended(model)`, the naive
     store plus provenance, write-time quarantine and a stuffing check,
     passes all four cells and is on the scorecard to show each is
     winnable. The two checks live in `agmi/checks.py`, shared with the
     verdicts, in the open.
- Base classes gain `close()` and `measured_on()` with defaults, so an
  adapter never has to guess what the runner will call.
- Positive control on every memory-specific attack: the victim must read
  back a genuine memory with an on-topic question in the same store state,
  or the cell is n/a rather than safe. Closes the route where a read path
  that returns nothing passes every cell. Found by DanceNitra (issue #3):
  inspeximus `trusted_only` with no trust seeds fails closed and read as
  safe on all four; it now scores n/a on all four, pinned by a test. The
  hidden-instruction fixture gained a genuine memory beside the payload so
  the control has something to read; verdict rule unchanged.
- `InspeximusRecallAdapter(recall_kwargs=...)` scores one of the tool's
  opt-in recall levers as its own configuration row.
- Two more targets for the memory-specific family. `inspeximus_recall.py`
  drives real inspeximus through `remember`/`recall` in its default
  configuration; `recall` ranks lexically below 300 memories, so the row
  runs offline and lands in the inspeximus default row. `langgraph_store.py`
  drives LangGraph's `SqliteStore` with a vector index through
  `put`/`search`; it is a separate row from the checkpointer because they
  are different components, and its cells are published only with a real
  embedder. Facts pinned: the store applies no relevance floor and its user
  isolation is the caller's namespace; inspeximus drops another user's
  records before ranking and shares records written with no user.
- `agmi/measure.py`: one command for the memory-specific family on any
  target, printing the row with its provenance line.
- `retrieval_hijack` rebuilt so a relevance floor cannot pass it. The
  victim holds six genuine memories on one topic and the agent takes three;
  the attacker's single entry is stuffed with the topic's question words
  around an unrelated payload, so it is on topic by construction and can
  only appear by outranking a genuine memory. The earlier version padded
  toward a different topic, which any score floor kept out for free. The
  naive baseline now fails this cell at rank 1, as an undefended ranker
  should; earlier scorecards showed it as safe. Mem0's cell is re-measured
  in this release.
- CI actions moved to `actions/checkout@v5` and `actions/setup-python@v6`
  (the v4/v5 tags run on Node 20, which GitHub is retiring).
- Mem0 memory-specific adapter (`mem0_semantic.py`): real Mem0 driven
  through its own `add(infer=False)` and `search(filters, top_k)` paths on
  a private local Qdrant store, for the injection, bleed, hijack and
  indirect-prompt-injection attacks. The embedder is pluggable
  (`agmi/embedders.py`): the offline hashing embedder for plumbing and the
  bleed cell, all-MiniLM-L6-v2 via sentence-transformers (new `embedder`
  extra) for every cell that depends on ranking. Rows carry a
  `measured_on()` line naming the Mem0 version, embedder and which of
  Mem0's optional ranking signals were on.
- Recorded two facts about mem0ai 2.0.20's default read path that the row
  depends on: it drops candidates whose semantic score is under 0.1 before
  ranking, and its result count is `top_k` (a `limit=` argument is silently
  ignored and 20 returned).
- Shared Mem0 plumbing moved into `mem0_common.py`; the at-rest adapter
  now opens its store through it. Measured behaviour unchanged.
- pytest tiers: the default run stays offline; `pytest -m embedder` runs
  tests that need the cached model.
- inspeximus adapter (inspeximus 2.38.0, SQLite store with an opt-in signed
  receipt chain and a chain head kept in the user's config home), three rows:
  receipts off reads like LangGraph, five accepted; receipts on with the
  attacker holding the store's directory, five reported; receipts on with the
  attacker also holding the config home, four reported and a tail truncation
  accepted. Detection is the tool's audit call, not the read path.

## 0.5.0 (2026-09-14)
- License (MIT), authorship, file headers, contributing and security
  policy, CI workflow.
- README rewritten: headline table, threat model, measurement sequence,
  architecture diagrams, attack catalogue, per-target method, adapter guide.

## 0.4.0 (2026-09-14)
- Mem0 adapter (mem0ai 2.0.20, local Qdrant store, fully offline).
- All five at-rest attacks accepted silently on Mem0; history table and
  vector store left disagreeing after truncate.

## 0.3.0 (2026-09-14)
- Letta adapter (letta 0.16.8, core memory block checkpoint history).
- Embedded Postgres via pgserver so the Letta row runs without Docker.
- Fixed the truncate attack, which removed one entry instead of two on
  stores that address rows by position.

## 0.2.0 (2026-09-14)
- First real target: LangGraph SqliteSaver (langgraph-checkpoint-sqlite
  3.1.1). All five at-rest attacks accepted silently.
- Adapters now own payload mutation so blob-based stores can be attacked
  without corrupting their encoding.

## 0.1.0
- Attack catalogue, adapter interface, Python model of the OpenFang audit
  chain, naive memory reference target.
