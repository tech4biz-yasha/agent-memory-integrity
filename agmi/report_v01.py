# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Write an agmi results file as a per-check report in the v0.1 format of the
W3C Agent Conformance and Benchmarking Community Group, and hold the written
report against the group's reference reader.

    python -m agmi.report_v01 results/scorecard.json results/report-v01.json
    python -m agmi.report_v01 results/scorecard.json results/report-v01.json --check
    python -m agmi.report_v01 --verify results/report-v01.json

One check per cell of the scorecard: one store under test, one edit. The
check is the read-path requirement the IETF draft states for every at-rest
edit and the suite states for every write-path edit: the store does not serve
the attacker's record as genuine. The states are read off the status values
the tests pin (``safe``, ``VULNERABLE``, ``reported``, ``n/a``), never off
the published words, so a wording change cannot move a record:

    safe          pass           the edit did not open as current
    VULNERABLE    fail           the edit opened as current
    reported      fail           the edit opened as current on the read path;
                                 the audit surface flagged it afterwards, and
                                 the annotation says so
    n/a           not-exercised  with a cause from the closed vocabulary and
                                 the suite's own reason carried beside it
    anything else void           the harness could not establish a verdict

The check-set root is computed by the reference reader's own functions
(``agent_evidence_vectors.w3creport``), so the digest encoding is the
group's by construction and not a reimplementation of it. The roll-up is
recomputed from the records at write time and again at check time. The
``--check`` form fails when the report on disk differs from what the results
file emits; CI runs it, the same way it holds ``docs/scorecard.md``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    from agent_evidence_vectors import w3creport as w3c
except ImportError:  # pragma: no cover - the message is the point
    w3c = None

FORMAT = "public-agent-conformance/report/v0.1"
DOMAIN_ID = "d-agmi-live-stores"
TREE_SHAPE = "flat"

#: status value in the results file -> v0.1 state. Verdict words are not read.
STATE_OF_STATUS = {
    "safe": "pass",
    "VULNERABLE": "fail",
    "reported": "fail",
    "n/a": "not-exercised",
}

#: The IETF draft's edit numbers for the at-rest edits, the suite's own
#: letters for the write-path edits, as the published tables name them.
EDIT_NAMES = {
    "tamper": "T1", "truncate": "T2", "delete_middle": "T3", "reorder": "T4",
    "forge": "T5", "cross_replay": "T6", "rollback_replay": "T7",
    "metadata_tamper": "T8", "snapshot_rollback": "T9", "erase_resurrect": "T10",
    "memory_injection": "W1", "cross_session_bleed": "W2", "retrieval_hijack": "W3",
    "indirect_prompt_injection": "W4", "update_poisoning": "W5",
    "metadata_poisoning": "W6",
}

CROSSWALK = {
    "pass": "status safe: the attacker's record did not open as current on the "
            "read path (the suite's words: rejected, kept out)",
    "fail": "status VULNERABLE or reported: the attacker's record opened as "
            "current on the read path (accepted, surfaced); a reported cell was "
            "flagged at the store's audit surface afterwards, which the "
            "annotation detection carries, and the read path still served it",
    "not-exercised": "status n/a: the cell was not measured, with the suite's own "
                     "reason carried in the annotation and mapped to the nearest "
                     "closed cause: not_applicable when the edit cannot exist on "
                     "that store or belongs to the other attacker, "
                     "unsupported_input when the adapter has no hook for the "
                     "operation the edit needs, unavailable when the row was "
                     "measured before the edit existed and its environment has "
                     "not been re-run",
    "inconclusive": "not emitted: the suite has no cell that ran and reached no "
                    "conclusion; a guard that fails is void",
    "void": "any other status: the harness could not establish that the edit "
            "landed (the C3 guard failed), cause evidence-does-not-hold",
}


def _require_reader() -> None:
    if w3c is None:
        sys.exit(
            "agmi.report_v01 needs the group's reference reader: "
            'pip install -e ".[vectors]"'
        )


def _cause_for(detail: str, own_class: bool, attacker: str) -> tuple[str, str]:
    """The closed cause for an n/a cell, and the reason text carried beside it."""
    if not detail:
        other = "write-access" if attacker == "store-access" else "store-access"
        return "not_applicable", (
            f"this edit belongs to the {attacker} attacker; the row is measured "
            f"under the {other} attacker"
        )
    if detail.startswith("not applicable"):
        return "not_applicable", detail
    if detail.startswith("not measured"):
        return "unavailable", detail
    return "unsupported_input", detail


def _check(row: dict[str, Any], edit: str, cell: dict[str, Any],
           version: int, attacker: str, row_classes: set[str]) -> dict[str, Any]:
    status = cell["status"]
    state = STATE_OF_STATUS.get(status, "void")
    record: dict[str, Any] = {
        "check": f"{row['label']}/{edit}@v{version}",
        "state": state,
        "annotations": {
            "store": row["label"],
            "edit": edit,
            "edit-name": EDIT_NAMES.get(edit, edit),
            "attack-version": version,
            "attacker": attacker,
            "status": status,
            "verdict": cell["verdict"],
            "detail": cell.get("detail", ""),
        },
    }
    if row.get("checked_at"):
        record["annotations"]["checked-at"] = row["checked_at"]
    if row.get("measured_on"):
        record["annotations"]["measured-on"] = row["measured_on"]
    if status == "reported":
        record["annotations"]["detection"] = "audit"
    elif state == "fail":
        record["annotations"]["detection"] = "none"
    elif state == "pass":
        record["annotations"]["detection"] = "read"
    if state in ("pass", "fail"):
        record["other-verdict"] = {"value": "unknown"}
        record["discrimination"] = {"value": "unknown"}
    elif state == "not-exercised":
        code, reason = _cause_for(cell.get("detail", ""), attacker in row_classes, attacker)
        record["cause"] = {"code": code, "detail": reason}
    else:
        record["cause"] = {"code": w3c.VOID_CAUSE if w3c else "evidence-does-not-hold",
                           "detail": cell.get("detail", "") or f"status {status!r}"}
    return record


def _checks(results: dict[str, Any]) -> list[dict[str, Any]]:
    versions = results["attack_versions"]
    attackers = results["attackers"]
    out: list[dict[str, Any]] = []
    for row in results["rows"]:
        classes = {attackers[a] for a, c in row["cells"].items() if c["status"] != "n/a"}
        for edit in versions:  # the file's own column order
            cell = row["cells"][edit]
            out.append(_check(row, edit, cell, versions[edit], attackers[edit], classes))
    return out


def _rollup(checks: list[dict[str, Any]]) -> dict[str, Any]:
    counts = w3c._counts(checks)
    declared, exercised = counts["declared"], counts["exercised"]
    verdicts = counts["pass"] + counts["fail"]
    rollup: dict[str, Any] = dict(counts)
    rollup["carried"] = 0
    rollup["referenced"] = 0
    rollup["negative-capable"] = {"kind": "shown-by-run" if counts["fail"] else "nothing"}
    rollup["completeness"] = {
        "accounting": {"population": declared,
                       "claim": "satisfied" if declared else "not-claimable"},
        "execution": {"population": declared,
                      "claim": ("not-claimable" if not declared else
                                "satisfied" if exercised == declared else "not-satisfied")},
        # discrimination is unknown on every record, so evidence completeness
        # is not satisfied by the format's own test; it is written, not skipped
        "evidence": {"population": verdicts,
                     "claim": "not-claimable" if not verdicts else "not-satisfied"},
        "no-void": {"population": declared,
                    "claim": ("not-claimable" if not declared else
                              "satisfied" if counts["void"] == 0 else "not-satisfied")},
    }
    return rollup


def _suite_version() -> str:
    """The suite version from pyproject.toml, so the checker identity in the
    report is the one the repository states and not whatever an older install
    left behind in its metadata."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    try:
        match = re.search(r'^version = "([^"]+)"', pyproject.read_text(encoding="utf-8"), re.M)
    except OSError:
        match = None
    if match:
        return match.group(1)
    from importlib.metadata import version
    return version("agent-memory-integrity")


def emit(results: dict[str, Any], results_bytes: bytes, results_path: str,
         tree_shape: str = TREE_SHAPE) -> dict[str, Any]:
    """The v0.1 report for one results file. Deterministic: same bytes in, same report out."""
    _require_reader()
    checks = _checks(results)
    report: dict[str, Any] = {
        "format": FORMAT,
        "domain": {
            "id": DOMAIN_ID,
            "description": "the memory stores the suite drives as installed, pinned by "
                           "version, each edit applied to the live store through the "
                           "attacker's own access and read back through the tool's own "
                           "read path; one check per store and edit",
        },
        "fixed": {
            "checker": {"name": "agmi", "version": _suite_version()},
            "constraint-set": {"attack-versions": results["attack_versions"],
                               "attackers": results["attackers"]},
            "domain": DOMAIN_ID,
        },
        "source": {
            "suite": "agmi",
            "results-file": results_path,
            "results-sha256": hashlib.sha256(results_bytes).hexdigest(),
            "date": results.get("date"),
            "platform": results.get("platform"),
            "rows": len(results["rows"]),
            "edits": len(results["attack_versions"]),
        },
        "crosswalk": CROSSWALK,
        "checks": checks,
        "evidence": [],
        "roll-up": _rollup(checks),
        "check-set": {
            "tree-shape": tree_shape,
            "digest-encoding": "jcs-sha256",
            "leaf-count": len(checks),
            "sha256": w3c.check_set_root(checks, tree_shape),
        },
    }
    return report


def verify(report: dict[str, Any]) -> list[str]:
    """Every finding the reference reader has against the report; empty means accepted."""
    _require_reader()
    findings = list(w3c.shape_errors(report))
    if findings:
        return findings
    findings = list(w3c.rejections(report))
    refusal = w3c.check_set_refusal(report)
    if refusal and refusal not in findings:
        findings.append(refusal)
    return findings


def dumps(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agmi.report_v01", description=__doc__.split("\n\n")[0])
    parser.add_argument("results", nargs="?", help="results file, e.g. results/scorecard.json")
    parser.add_argument("report", nargs="?", help="where to write the v0.1 report")
    parser.add_argument("--check", action="store_true",
                        help="fail if the report on disk differs from what the results emit")
    parser.add_argument("--verify", metavar="REPORT",
                        help="run the reference reader over an existing report and stop")
    parser.add_argument("--tree-shape", default=TREE_SHAPE)
    args = parser.parse_args(argv)
    _require_reader()

    if args.verify:
        report = json.loads(Path(args.verify).read_text(encoding="utf-8"))
        findings = verify(report)
        binding = report.get("check-set", {})
        print(f"leaf-count: {binding.get('leaf-count')} | tree-shape: {binding.get('tree-shape')} "
              f"| root: {binding.get('sha256')}")
        if findings:
            print("rejected under: " + ", ".join(findings))
            return 1
        print("verify: OK (the reference reader accepts the report, no row fires)")
        return 0

    if not args.results or not args.report:
        parser.error("results and report paths are required unless --verify is given")
    results_bytes = Path(args.results).read_bytes()
    results = json.loads(results_bytes)
    report = emit(results, results_bytes, args.results, args.tree_shape)
    findings = verify(report)
    if findings:
        print("the emitted report is rejected by the reference reader: " + ", ".join(findings))
        return 2
    text = dumps(report)
    out = Path(args.report)
    rollup = report["roll-up"]
    summary = (f"checks: {rollup['declared']} | pass {rollup['pass']} | fail {rollup['fail']} "
               f"| not-exercised {rollup['not-exercised']} | void {rollup['void']} "
               f"| root: {report['check-set']['sha256']}")
    if args.check:
        on_disk = out.read_text(encoding="utf-8") if out.exists() else None
        if on_disk != text:
            print(f"{out} does not match what {args.results} emits; regenerate it")
            print(summary)
            return 1
        print(f"{out} matches {args.results}")
        print(summary)
        return 0
    out.write_text(text, encoding="utf-8")
    print(f"wrote {out}")
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
