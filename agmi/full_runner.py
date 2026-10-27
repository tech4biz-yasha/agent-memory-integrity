# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Full scorecard across both attack families.

At-rest attacks (storage tampering) apply to any persisted store. Memory
attacks (injection, bleed, hijack, indirect injection) apply only to tools
that do user-scoped semantic retrieval. A tool that lacks one surface simply
scores n/a there, which is itself informative: an audit log cannot be
memory-injected; a bare vector store has no chain to truncate. LangGraph
gets two rows because its checkpointer (at rest) and its long-term store
(retrieval) are different components.

The checkedAt column names the detection point an adapter measures: "read"
means verify() is the tool's read path, the call that returns memories to the
agent; "audit" means verify() is a separate integrity call the operator has to
make, and the read path still serves the altered data. A detection on an audit
call prints "reported" rather than "safe" so the two are never read as the
same guarantee.
"""

from __future__ import annotations


import datetime as _dt
import json
import os
import platform
import sys

#: Filled by full_scorecard(); written out by ``--json``.
_LAST_RUN: dict = {}


def _verdict(status: str, memory_attack: bool, point) -> str:
    """The word printed on the scorecard and the site. The internal status
    values (safe / VULNERABLE / n/a) are what the tests pin; these are what
    a reader sees. At rest the words follow the method proposed for IETF
    draft-han-bmwg-agent-security-benchmark 5.4.7: rejected (the tool
    refused the edit on read), reported (its audit named it), accepted (it
    served the edit as genuine). Front door: surfaced, kept out."""
    if status == "n/a":
        return "n/a"
    if status == "ERROR":
        return "error"
    if memory_attack:
        return "kept out" if status == "safe" else "surfaced"
    if status == "reported":
        return "reported"
    if status == "safe":
        return "reported" if point == "audit" else "rejected"
    return "accepted"


def write_json(path: str) -> None:
    """Write the last run as JSON: every cell with its status, printed
    verdict and detail, each row's provenance line, the attack versions,
    the date and the platform. This file is the single source every
    published table is generated from (see ``agmi.render``)."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(_LAST_RUN, fh, indent=2)
        fh.write("\n")


def _mem0_semantic():
    """The memory-specific adapter for the Mem0 row, or None.

    Those cells are published only when measured with a real sentence
    embedder, so the row gets its semantic adapter only if
    sentence-transformers is installed and the model can be loaded. Without
    it the memory-specific columns stay n/a rather than being measured with
    the offline hashing stand-in, which would measure this suite, not Mem0.
    """
    try:
        from agmi.adapters.mem0_semantic import Mem0SemanticAdapter
        from agmi.embedders import SentenceTransformerEmbedder
        return Mem0SemanticAdapter(SentenceTransformerEmbedder())
    except (ImportError, NotImplementedError, OSError):
        return None


def _langgraph_store_semantic():
    """The LangGraph long-term store row, or None. Same rule as Mem0: its
    cells depend on ranking, so the row appears only with a real sentence
    embedder available."""
    try:
        from agmi.adapters.langgraph_store import LangGraphSqliteStoreAdapter
        from agmi.embedders import SentenceTransformerEmbedder
        return LangGraphSqliteStoreAdapter(SentenceTransformerEmbedder())
    except (ImportError, NotImplementedError, OSError):
        return None


def _letta_archival_semantic():
    """The Letta archival row, or None: same rule as the Mem0 and LangGraph
    store rows, a real sentence embedder or no row."""
    try:
        from agmi.adapters.letta_block_history import _ensure_env
        _ensure_env()  # before letta is imported anywhere
        from agmi.adapters.letta_archival import LettaArchivalAdapter
        from agmi.embedders import SentenceTransformerEmbedder
        import letta  # noqa: F401
        return LettaArchivalAdapter(SentenceTransformerEmbedder())
    except (ImportError, NotImplementedError, OSError):
        return None


def full_scorecard() -> str:
    from agmi.adapters.openfang import OpenFangAdapter
    from agmi.adapters.langgraph_sqlite import LangGraphSqliteAdapter
    try:
        from agmi.adapters.openai_agents_session import OpenAIAgentsSessionAdapter
        openai_session = OpenAIAgentsSessionAdapter()
    except ImportError:
        openai_session = None
    try:
        from agmi.adapters.llamaindex_memory import LlamaIndexMemoryAdapter
        llamaindex_memory = LlamaIndexMemoryAdapter()
    except ImportError:
        llamaindex_memory = None
    try:
        from agmi.adapters.crewai_lancedb import CrewAILanceDBAdapter
        crewai_ltm = CrewAILanceDBAdapter()
    except ImportError:
        crewai_ltm = None
    lg_store = _langgraph_store_semantic()
    letta_archival = _letta_archival_semantic()
    try:
        import langgraph_ledger  # noqa: F401
        from agmi.adapters.langgraph_ledger import LangGraphLedgerAdapter
        ledger_row = ("langgraph-ledger", LangGraphLedgerAdapter(), None)
    except ImportError:
        ledger_row = None
    try:
        import memory_blackbox  # noqa: F401
        from agmi.adapters.memory_blackbox import (
            MemoryBlackboxMdAdapter, MemoryBlackboxMdRestartAdapter,
        )
        mbb_rows = [("memory-blackbox-md", MemoryBlackboxMdAdapter(), None),
                    ("memory-blackbox-md+restart", MemoryBlackboxMdRestartAdapter(), None)]
    except ImportError:
        mbb_rows = []
    try:
        import amem_attest  # noqa: F401
        from agmi.adapters.atelya_attest import (
            AtelyaAttestAnchoredAdapter, AtelyaAttestChainAdapter,
        )
        atelya_rows = [("atelya-attest-chain", AtelyaAttestChainAdapter(), None),
                       ("atelya-attest-chain+anchor", AtelyaAttestAnchoredAdapter(), None)]
    except ImportError:
        atelya_rows = []
    try:
        import atmem  # noqa: F401
        from agmi.adapters.atmem import AtMemAnchoredAdapter, AtMemChainAdapter
        atmem_rows = [("atmem-chain", AtMemChainAdapter(), None),
                      ("atmem-chain+checkpoint", AtMemAnchoredAdapter(), None)]
    except ImportError:
        atmem_rows = []
    try:
        import langgraph.checkpoint.postgres  # noqa: F401
        from agmi.adapters.langgraph_postgres import LangGraphPostgresAdapter, postgres_uri
        if not postgres_uri():
            LangGraphPostgresAdapter = None  # noqa: N806 - row only with AGMI_POSTGRES_URI
    except ImportError:
        LangGraphPostgresAdapter = None  # noqa: N806
    try:
        import vertexai  # noqa: F401
        from agmi.adapters.vertex_memory_bank import VertexMemoryBankAdapter, gcp_project
        if not gcp_project():
            VertexMemoryBankAdapter = None  # noqa: N806 - row only with AGMI_GCP_PROJECT
    except ImportError:
        VertexMemoryBankAdapter = None  # noqa: N806
    if os.environ.get("AGMI_BEDROCK") == "1":  # row only with AGMI_BEDROCK=1; it bills per run
        from agmi.adapters.bedrock_agentcore import BedrockAgentCoreEventsAdapter
        bedrock_rows = [("bedrock-agentcore-events", BedrockAgentCoreEventsAdapter(), None)]
    else:
        bedrock_rows = []
    if os.environ.get("AGMI_HDP_REPO"):  # row only with the pinned HDP checkout and Node 22
        from agmi.adapters.hdp_token_store import (
            HdpTokenStoreAdapter, HdpTokenStoreUuidAdapter,
        )
        hdp_rows = [
            ("hdp-token-content-ref", HdpTokenStoreAdapter(), None),
            ("hdp-token-uuid", HdpTokenStoreUuidAdapter(), None),
        ]
    else:
        hdp_rows = []
    if os.environ.get("AGMI_RECALLSPECTION_REPO"):  # row only with the pinned checkout
        from agmi.adapters.recallspection import (
            RecallspectionAdapter, RecallspectionAnchoredAdapter,
        )
        recallspection_rows = [
            ("recallspection-exact", RecallspectionAdapter(), None),
            ("recallspection-exact+anchor", RecallspectionAnchoredAdapter(), None),
        ]
    else:
        recallspection_rows = []
    if os.environ.get("AGMI_WHITEMAGIC_CRYSTAL_CLIENT"):  # row only with pinned crystal_client.py
        from agmi.adapters.whitemagic_crystals import (
            WhiteMagicCrystalsAdapter,
            WhiteMagicCrystalsAnchoredAdapter,
            WhiteMagicCrystalsL5Adapter,
        )
        whitemagic_rows = [
            ("whitemagic-crystals", WhiteMagicCrystalsAdapter(), None),
            ("whitemagic-crystals+anchor", WhiteMagicCrystalsAnchoredAdapter(), None),
            ("whitemagic-crystals+l5", WhiteMagicCrystalsL5Adapter(), None),
        ]
    else:
        whitemagic_rows = []
    from agmi.adapters.openclaw_memory import openclaw_dir
    if openclaw_dir():  # row only with AGMI_OPENCLAW_DIR; a wrong version fails loudly
        from agmi.adapters.openclaw_memory import OpenClawMemoryAdapter
        openclaw_row = [("openclaw-memory-md", OpenClawMemoryAdapter(), None)]
    else:
        openclaw_row = []
    if os.environ.get("AGMI_HERMES_PYTHON"):  # row only with AGMI_HERMES_PYTHON; a wrong version fails loudly
        from agmi.adapters.hermes_memory import HermesMemoryAdapter
        hermes_row = [("hermes-memory-md", HermesMemoryAdapter(), None)]
    else:
        hermes_row = []
    try:
        import langgraph.checkpoint.redis  # noqa: F401
        from agmi.adapters.langgraph_redis import LangGraphRedisAdapter, redis_uri
        if not redis_uri():
            LangGraphRedisAdapter = None  # noqa: N806 - row only with AGMI_REDIS_URI
    except ImportError:
        LangGraphRedisAdapter = None  # noqa: N806
    try:
        import continuum  # noqa: F401
        from agmi.adapters.continuum_events import (
            ContinuumEventsAdapter, ContinuumEventsAttestedAdapter,
        )
        continuum_rows = [("continuum-events", ContinuumEventsAdapter(), None),
                          ("continuum-events+attest", ContinuumEventsAttestedAdapter(), None)]
    except ImportError:
        continuum_rows = []
    try:
        import agentmem_ref  # noqa: F401
        from agmi.adapters.agent_memory import AgentMemoryAdapter
        agent_memory_row = ("agent-memory", AgentMemoryAdapter(), None)
    except ImportError:
        agent_memory_row = None
    try:
        import acrf_memory_guard  # noqa: F401
        from agmi.adapters.acrf_memory_guard import AcrfMemoryGuardAdapter
        acrf_row = ("acrf-memory-guard", AcrfMemoryGuardAdapter(), None)
    except ImportError:
        acrf_row = None
    if os.environ.get("AGMI_SDO_REPO"):
        from agmi.adapters.surgical_devops import SurgicalDevOpsAdapter
        surgical_devops_rows = [
            ("surgical-devops-g7", SurgicalDevOpsAdapter(), None)
        ]
    else:
        surgical_devops_rows = []
    try:
        from agmi.adapters.mem0_at_rest import Mem0AtRestAdapter
        mem0_row = ("mem0-qdrant-local", Mem0AtRestAdapter(), _mem0_semantic())
    except ImportError:
        mem0_row = None
    try:
        from agmi.adapters.letta_block_history import LettaBlockHistoryAdapter
        letta_row = ("letta-block-history", LettaBlockHistoryAdapter(), None)
    except ImportError:
        letta_row = None
    try:
        import inspeximus  # noqa: F401 - the adapter imports it lazily, so probe for it here
        from agmi.adapters.inspeximus_rows import (InspeximusDefaultAdapter, InspeximusRowsSidecarAdapter,
                                                   InspeximusRowsSidecarHeadAdapter)
        from agmi.adapters.inspeximus_recall import InspeximusRecallAdapter
        # recall ranks lexically at these sizes, so the default row's memory
        # cells need no embedder and run everywhere; receipts do not take
        # part in ranking, so the two receipts rows keep n/a there.
        from agmi.measure import _inspeximus_defended, _inspeximus_defended_key
        # The two defended targets from PR #4: the tool's own provenance and a
        # trust root, keyed on the label and then on an attested key. Memory
        # cells only; the at-rest path is the default row's.
        inspeximus_rows = [("inspeximus-default", InspeximusDefaultAdapter(), InspeximusRecallAdapter()),
                           ("inspeximus-rcpt+dir", InspeximusRowsSidecarAdapter(), None),
                           ("inspeximus-rcpt+dir+home", InspeximusRowsSidecarHeadAdapter(), None),
                           ("inspeximus-defended", None, _inspeximus_defended("none")),
                           ("inspeximus-defended-key", None, _inspeximus_defended_key("none"))]
    except ImportError:
        inspeximus_rows = []
    from agmi.adapters.naive_memory import NaiveMemoryAdapter
    from agmi.adapters.defended_memory import DefendedMemoryAdapter
    from agmi.attacks.at_rest import AT_REST_ATTACKS_WITH_ERASE as ALL_AT_REST_ATTACKS
    from agmi.attacks.memory_specific import ALL_MEMORY_ATTACKS

    at_rest = [c() for c in ALL_AT_REST_ATTACKS]
    mem = [c() for c in ALL_MEMORY_ATTACKS]
    all_names = [a.name for a in at_rest] + [a.name for a in mem]

    # (label, at-rest adapter or None, semantic adapter or None)
    rows = [
        ("openfang(model,fixed)", OpenFangAdapter(strict_tip=True), None),
        ("langgraph-sqlite", LangGraphSqliteAdapter(), None),
        *([("langgraph-postgres", LangGraphPostgresAdapter(), None)] if LangGraphPostgresAdapter else []),
        *([("langgraph-redis", LangGraphRedisAdapter(), None)] if LangGraphRedisAdapter else []),
        *([("openai-agents-sqlite-session", openai_session, None)] if openai_session else []),
        *([("llamaindex-memory-sqlite", llamaindex_memory, None)] if llamaindex_memory else []),
        *([("crewai-ltm-lancedb", crewai_ltm, None)] if crewai_ltm else []),
        *([("vertex-memory-bank", VertexMemoryBankAdapter(), None)] if VertexMemoryBankAdapter else []),
        *bedrock_rows,
        *openclaw_row,
        *hermes_row,
        *([("langgraph-sqlite-store", None, lg_store)] if lg_store else []),
        *([letta_row] if letta_row else []),
        *([("letta-archival", None, letta_archival)] if letta_archival else []),
        *([mem0_row] if mem0_row else []),
        *inspeximus_rows,
        *([ledger_row] if ledger_row else []),
        *mbb_rows,
        *atelya_rows,
        *continuum_rows,
        *atmem_rows,
        *surgical_devops_rows,
        *recallspection_rows,
        *whitemagic_rows,
        *hdp_rows,
        *([acrf_row] if acrf_row else []),
        *([agent_memory_row] if agent_memory_row else []),
        ("naive-mem(scoped)", None,
         NaiveMemoryAdapter(enforce_user_scope=True)),
        ("naive-mem(unscoped)", None,
         NaiveMemoryAdapter(enforce_user_scope=False)),
        ("reference-defended(model)", None, DefendedMemoryAdapter()),
    ]

    cells: dict[tuple[str, str], str] = {}
    details: dict[tuple[str, str], str] = {}
    checked_at: dict[str, str] = {}
    measured_on: dict[str, str] = {}
    for label, ar_ad, sm_ad in rows:
        if ar_ad is not None:
            ar_ad.name = label
            point = getattr(ar_ad, "detection_point", "read")
            checked_at[label] = point
            provenance = getattr(ar_ad, "measured_on", None)
            if callable(provenance):
                measured_on[label] = provenance()
            for atk in at_rest:
                res = atk.run(ar_ad)
                status = res.status
                if status == "safe" and point == "audit":
                    status = "reported"
                cells[(label, atk.name)] = status
                details[(label, atk.name)] = getattr(res, "guard", None) or res.detail or res.error or ""
        else:
            for atk in at_rest:
                cells[(label, atk.name)] = "n/a"
        if sm_ad is not None:
            sm_ad.name = label
            for atk in mem:
                res = atk.run(sm_ad)
                cells[(label, atk.name)] = res.status
                details[(label, atk.name)] = getattr(res, "guard", None) or res.detail or res.error or ""
            measured_on[label] = sm_ad.measured_on()
            sm_ad.close()
        else:
            for atk in mem:
                cells[(label, atk.name)] = "n/a"
    _LAST_RUN.clear()
    _LAST_RUN.update({
        "date": _dt.date.today().isoformat(),
        "platform": f"{platform.system()} {platform.machine()}, Python "
                    f"{sys.version_info.major}.{sys.version_info.minor}",
        "attack_versions": {a.name: a.version for a in at_rest + mem},
        "attackers": {**{a.name: "store-access" for a in at_rest},
                      **{a.name: "write-access" for a in mem}},
        "rows": [
            {"label": label,
             "checked_at": checked_at.get(label),
             "measured_on": measured_on.get(label),
             "cells": {a.name: {"status": cells[(label, a.name)],
                                "verdict": _verdict(cells[(label, a.name)],
                                                    a.name in {m.name for m in mem},
                                                    checked_at.get(label)),
                                "detail": details.get((label, a.name), "")}
                       for a in at_rest + mem}}
            for label, _, _ in rows],
    })

    short = {
        "tamper": "tamp", "truncate": "trunc", "delete_middle": "delMid",
        "reorder": "reord", "forge": "forge",
        "cross_replay": "xReplay", "rollback_replay": "rollbk",
        "metadata_tamper": "metaTmp", "snapshot_rollback": "snapRb",
        "erase_resurrect": "erase",
        "memory_injection": "inject",
        "cross_session_bleed": "bleed", "retrieval_hijack": "hijack",
        "indirect_prompt_injection": "promptInj",
        "update_poisoning": "update",
        "metadata_poisoning": "metadata",
    }
    cols = ["checkedAt"] + [short[n] for n in all_names]
    label_w = max(len(r[0]) for r in rows) + 1
    col_w = max(max(len(c) for c in cols), 10)

    def c(t): return t.center(col_w)
    head = " " * label_w + "| " + " | ".join(c(x) for x in cols)
    versions = ", ".join(f"{a.name}@v{a.version}" for a in at_rest + mem)
    lines = [f"attack versions: {versions}", "", head, "-" * len(head)]
    for label, _, _ in rows:
        line = [label.ljust(label_w) + "|"]
        line += [c(checked_at.get(label, "n/a"))]
        line += [c(_verdict(cells[(label, n)], n in {m.name for m in mem},
                            checked_at.get(label))) for n in all_names]
        lines.append(" ".join(line[:1]) + " " + " | ".join(line[1:]))
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(prog="python agmi/full_runner.py")
    ap.add_argument("--json", metavar="PATH",
                    help="also write the run as JSON to PATH")
    args = ap.parse_args()
    print(full_scorecard())
    if args.json:
        write_json(args.json)
