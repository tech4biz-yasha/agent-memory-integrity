# IETF 127 hackathon: agent memory integrity

**Does your agent's memory store notice tampering?**
Remote, Saturday 14 November 2026, 09:00 to 13:00 Pacific (17:00 to 21:00 UTC, 22:30 to 02:30 IST).
Champion: Yasha Khandelwal, yasha.khandelwal@tech4biz.io. The meeting link goes by email to everyone who writes ahead; write for other hours if these do not suit you.

The method is draft-khandelwal-bpm-agent-memory-integrity. You bring the memory or checkpoint store your agent uses and leave with its own row: ten edits applied beneath the store's own API, read back through that API, each one recorded as refused on read, served and reported at a later audit, or served as genuine.

## Before the day (30 minutes, on your own)

Do this before Saturday so the four hours go on your store, not on setup.

1. Python 3.11 or later, and git.
2. Clone the suite and install it. The published release, 0.7.0, carries all ten edits, so `pip install agent-memory-integrity` is enough to run them; clone anyway if you want to write an adapter for your own store, which is what most of the day is.

```
git clone https://github.com/tech4biz-yasha/agent-memory-integrity
cd agent-memory-integrity
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,langgraph]"
```

3. Run the warm-up on a store that ships with the suite. It needs no network.

```
python -m agmi.agent --target langgraph-sqlite --families at-rest
```

You should see ten numbered results, [1] tamper to [10] erase_resurrect, each with the edit's outcome and its detection point. If you see them, you are ready.

4. Have a local instance of your own store running, with whatever client or SDK an agent would use to write to it and read from it.

5. Read `docs/adding-a-row.md`. It is short, and every question it asks will come up.

## The four hours

### 09:00 to 09:15. What a row is

The method in ten minutes: the adversary edits the store beneath the API and holds no key; the store is stopped during the edit; the verdict is what its own read path does after the restart. Then the five questions every row rests on, read from `docs/adding-a-row.md`, step 1.

### 09:15 to 09:45. Answer the five questions for your store

Open an issue on the repository with the template "Measure my store" and answer, in the issue, before any code:

1. What exactly is the store? The file, table, directory or API surface, not the product.
2. What is one record? The unit the ten edits apply to.
3. Where does the attacker stand? What they can read and write, and what they cannot.
4. What is the read path? The call an agent makes before acting, and whether a fresh process is involved.
5. What exactly do we pin? Version, commit, runtime.

If a deployment choice changes the answer, say which configuration ships by default; that is two rows. The champion reads each issue as it comes in, in the order posted.

### 09:45 to 11:30. Write the adapter

Copy `agmi/adapters/_template.py` to `agmi/adapters/<your_store>.py` and work through it. Every method carries a comment saying what it is for and what gets it wrong. Three methods decide whether the row is honest:

- `verify()` returns what the tool says, never what the adapter thinks.
- `owner_of()` derives the context from where the record sits, not from a field inside it.
- `delete_raw()` raises when there is nothing at that position.

Ask in the call as soon as a method's meaning is unclear for your store; the answer usually settles what one record is.

### 11:30 to 12:15. Run the ten edits and read the ten lines

```
PYTHONPATH=. python -c "
from agmi.adapters.your_store import YourAdapter
from agmi.attacks.at_rest import AT_REST_ATTACKS_WITH_ERASE as X
for c in X:
    r = c().run(YourAdapter())
    print(f'{r.attack:20} {r.status:11} {(r.guard or r.detail or r.error or \"\")[:90]}')
"
```

Read every line before anything else:

- `error` with a guard message means the edit did not land the way the attack intended, and the suite refuses to score it. That is almost always the adapter, not the store.
- `n/a` means the edit cannot apply to this store, and the cell must carry its reason in the tool's own words.
- A verdict that surprises you is the row. Do not adjust the adapter to change it; say what you expected in the issue.

### 12:15 to 12:45. Pin it and post it

Add `tests/test_<your_store>.py` asserting the verdicts you saw, with the version and commit from question 5. Paste the ten-line print and the exact commands into your issue. If you want the row on the scorecard, open the pull request as `docs/adding-a-row.md` step 6 describes; a row submitted by a store's own maintainer is reproduced independently before it lands and marked as such.

### 12:45 to 13:00. Detection points, side by side

Every row's lines are read together: which stores refused on the read path, which reported only at a later audit, which served the edit as genuine, and where the anchor sits in the ones that caught the whole-store rollback. What the day measured goes into the BPM presentation on Wednesday 18 November, session 2 of the joint BMWG/IPPM session.

## What you leave with

A row you can reproduce with one command, pinned to the version you measured; an issue on the repository holding the five answers and the ten lines; and, if you opened the pull request, a place on the public scorecard once the row is reproduced.

## Links

- Draft: https://datatracker.ietf.org/doc/draft-khandelwal-bpm-agent-memory-integrity/
- Code: https://github.com/tech4biz-yasha/agent-memory-integrity
- Scorecard: https://agentmemoryintegrity.org
- Guide: `docs/adding-a-row.md` in the repository
