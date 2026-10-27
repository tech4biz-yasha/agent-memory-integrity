# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""The storage-side hunt: run the nine at-rest edits against one target and
report what the tool served, with a reproduction for each finding.

The front-door hunt (``agmi.agent.hunter``) poisons through the tool's API.
This one is the other side of the API: it edits the tool's storage directly
and asks the tool, through its own read path or audit, whether it noticed.
A finding is an edit the tool served as genuine (or merely lost, never
flagged). It is the same oracle the scorecard uses, driven as a hunt so the
agent covers both families in one run and hands back a script per finding.

Authorisation runs before the target is touched (``agmi.agent.authz``): the
at-rest targets here are all in-process library stores the caller already
holds. A network target would go through the same gate the front-door hunt
uses, and is not reachable from this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from agmi.adapters.base import MemoryAdapter
from agmi.agent.authz import Authorisation, authorise_library
from agmi.attacks.at_rest import AT_REST_ATTACKS_WITH_ERASE


@dataclass
class AtRestFinding:
    """One storage edit the target served as genuine (or lost) without flagging."""
    edit: str            # the attack name (tamper, truncate, ... , snapshot_rollback)
    outcome: str         # "served" (read path) or "lost" (gone, no error)
    detection_point: str  # where the tool would have had to catch it: read / audit
    detail: str
    repro: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"edit": self.edit, "outcome": self.outcome,
                "detection_point": self.detection_point,
                "detail": self.detail, "repro": self.repro}


def _repro(adapter_name: str, edit: str, detection_point: str) -> list:
    return [
        f"# target={adapter_name}, edit={edit}",
        "seed the store through the tool's own API (5 records)",
        f"apply the {edit} edit to the storage directly, bypassing the tool",
        "confirm the edit landed as intended (control C3)",
        "reload the store the way the tool's users would",
        ("read back: the tool served the edited store with no refusal"
         if detection_point == "read"
         else "run the tool's audit: it did not report the edit"),
    ]


def hunt_at_rest(adapter: MemoryAdapter, *, target: str = "library",
                 authorisation: Authorisation | None = None):
    """Run every at-rest edit against ``adapter``; return (authz_line, findings).

    Each edit the tool accepts (served as genuine, or lost without an error)
    becomes a finding with a reproduction. Edits the tool refuses on read or
    reports on audit are not findings. Edits that error (the harness could not
    land them, or the target does not support that edit) are skipped, never
    counted as findings.
    """
    authz = authorisation or authorise_library()
    findings: list[AtRestFinding] = []
    dp = getattr(adapter, "detection_point", "read")
    for attack_cls in AT_REST_ATTACKS_WITH_ERASE:
        result = attack_cls().run(adapter)
        if result.error is not None or result.guard is not None:
            continue  # not applicable / did not land — never a finding
        if result.detected:
            continue  # refused on read or reported on audit — the tool caught it
        outcome = "lost" if "gone" in (result.detail or "").lower() else "served"
        findings.append(AtRestFinding(
            edit=result.attack, outcome=outcome, detection_point=dp,
            detail=result.detail or "accepted with no refusal",
            repro=_repro(adapter.name, result.attack, dp)))
    return f"{authz.kind}: {authz.detail}", findings


# The at-rest targets the hunt can reach: in-process library stores that carry
# the nine edits. Keyed by the same names the scorecard uses.
def at_rest_target(name: str) -> MemoryAdapter:
    if name == "reference":
        from agmi.adapters.reference_atrest import ReferenceAtRestAdapter
        return ReferenceAtRestAdapter()
    if name == "langgraph-sqlite":
        from agmi.adapters.langgraph_sqlite import LangGraphSqliteAdapter
        return LangGraphSqliteAdapter()
    if name == "llamaindex":
        from agmi.adapters.llamaindex_memory import LlamaIndexMemoryAdapter
        return LlamaIndexMemoryAdapter()
    if name == "crewai":
        from agmi.adapters.crewai_lancedb import CrewAILanceDBAdapter
        return CrewAILanceDBAdapter()
    if name == "openai-agents":
        from agmi.adapters.openai_agents_session import OpenAIAgentsSessionAdapter
        return OpenAIAgentsSessionAdapter()
    # inspeximus in the three positions the scorecard measures: receipts off (the
    # default, verify is the read path); receipts on with the attacker holding the
    # store directory; and receipts on with the attacker also holding the config
    # home where the chain head lives.
    if name == "inspeximus-default":
        from agmi.adapters.inspeximus_rows import InspeximusDefaultAdapter
        return InspeximusDefaultAdapter()
    if name == "inspeximus-rcpt+dir":
        from agmi.adapters.inspeximus_rows import InspeximusRowsSidecarAdapter
        return InspeximusRowsSidecarAdapter()
    if name == "inspeximus-rcpt+dir+home":
        from agmi.adapters.inspeximus_rows import InspeximusRowsSidecarHeadAdapter
        return InspeximusRowsSidecarHeadAdapter()
    if name == "openclaw-memory-md":
        from agmi.adapters.openclaw_memory import OpenClawMemoryAdapter
        return OpenClawMemoryAdapter()
    if name == "hermes-memory-md":
        from agmi.adapters.hermes_memory import HermesMemoryAdapter
        return HermesMemoryAdapter()
    if name == "hdp-token-content-ref":
        from agmi.adapters.hdp_token_store import HdpTokenStoreAdapter
        return HdpTokenStoreAdapter()
    if name == "hdp-token-uuid":
        from agmi.adapters.hdp_token_store import HdpTokenStoreUuidAdapter
        return HdpTokenStoreUuidAdapter()
    if name == "recallspection-exact":
        from agmi.adapters.recallspection import RecallspectionAdapter
        return RecallspectionAdapter()
    if name == "recallspection-exact+anchor":
        from agmi.adapters.recallspection import RecallspectionAnchoredAdapter
        return RecallspectionAnchoredAdapter()
    if name == "surgical-devops-g7":
        from agmi.adapters.surgical_devops import SurgicalDevOpsAdapter
        return SurgicalDevOpsAdapter()
    if name == "bedrock-agentcore-events":
        from agmi.adapters.bedrock_agentcore import BedrockAgentCoreEventsAdapter
        return BedrockAgentCoreEventsAdapter()
    if name == "vertex-memory-bank":
        from agmi.adapters.vertex_memory_bank import VertexMemoryBankAdapter
        return VertexMemoryBankAdapter()
    # AtMem in the two positions the scorecard measures: the chain alone, and the
    # chain with a checkpoints file the attacker cannot reach.
    if name == "atmem-chain":
        from agmi.adapters.atmem import AtMemChainAdapter
        return AtMemChainAdapter()
    if name == "atmem-chain+checkpoint":
        from agmi.adapters.atmem import AtMemAnchoredAdapter
        return AtMemAnchoredAdapter()
    if name == "whitemagic-crystals":
        from agmi.adapters.whitemagic_crystals import WhiteMagicCrystalsAdapter
        return WhiteMagicCrystalsAdapter()
    if name == "whitemagic-crystals+anchor":
        from agmi.adapters.whitemagic_crystals import WhiteMagicCrystalsAnchoredAdapter
        return WhiteMagicCrystalsAnchoredAdapter()
    if name == "whitemagic-crystals+l5":
        from agmi.adapters.whitemagic_crystals import WhiteMagicCrystalsL5Adapter
        return WhiteMagicCrystalsL5Adapter()
    raise SystemExit(
        f"unknown at-rest target {name!r}; choose one of: reference, "
        f"langgraph-sqlite, llamaindex, crewai, openai-agents, inspeximus-default, "
        f"inspeximus-rcpt+dir, inspeximus-rcpt+dir+home, vertex-memory-bank, bedrock-agentcore-events, surgical-devops-g7, recallspection-exact, recallspection-exact+anchor, hdp-token-content-ref, hdp-token-uuid, openclaw-memory-md, hermes-memory-md, "
        f"atmem-chain, atmem-chain+checkpoint, whitemagic-crystals, whitemagic-crystals+anchor, whitemagic-crystals+l5")
