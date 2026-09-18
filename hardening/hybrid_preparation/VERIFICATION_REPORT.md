# Exact hybrid verification — 2026-09-18

Recommendation: RUN ONE LIVE ARENA TEST. No live evaluation was performed.

## Working-tree integrity and preservation
Initial status: main, up to date with origin/main; HEAD 04e25a610ec2824a3ecc0b1029ac18deab3e8bed. Two modified files: agent.py and final_semantics.py. Three untracked files: REGRESSION_ANALYSIS.md, regression_analysis.py, regression_analysis_results.json. No staged or unrelated changes. Initial diff: 2 files, 36 insertions, 28 deletions.

No agent or existing test edits were made during preparation. All five original candidate files and baseline remain byte-for-byte identical after validation. The differential command rewrote its results JSON with identical bytes. No commits, pushes, checkout, reset, cleanup or history changes.

hardening/hybrid_candidate.patch was created using `git diff > hardening/hybrid_candidate.patch`; it captures only the two tracked modifications. Untracked analysis artifacts are NOT in that patch. Their exact names and bytes, plus both modified sources, baseline and patch, are separately preserved under hybrid_preparation/snapshot with hashes.json. Read-only `git apply --reverse --check` passes. Git emitted LF-to-CRLF warnings; no normalization was performed.

## SHA-256
- agent.py: 2cc8df02077f82efe4203f806bb21f44391192d05f0c7359e5c0208ce956aa29
- baseline_agent.py: dc6118c38b0127cda831098438ee0a547b3256d9ac75d8a9ca2c48a712e86985
- hybrid_candidate.patch: 5aecca463e86427942cb0bf87f4d16cabee286976b6ddccac219a40bbb8edad7

Baseline provenance verified: a895b28 plus exactly the 21-line customer_message parser. Historical hash discrepancy resolved: Git stores the regressed source with LF throughout (SHA-256 7cffb4d2aa091fd7481491a4346c98d2c2885dd76a9569b062f65a7d1b0de698). Changing ONLY its final line ending to CRLF reproduces supplied SHA-256 4f01c4b853b105767aa2572ac35cc764d959b13465364d75ee74f668a2075b7e. No source-content discrepancy.

## Existing suites (all final runs exit 0)
| Suite / command suffix after python -B | Pass | Fail | Average / maximum calls |
|---|---:|---:|---|
| hardening/regression.py | 30/30 | 0 | 7.63 / 8 |
| hardening/regression.py --live-format | 30/30 | 0 | 7.63 / 8 |
| hardening/adversarial.py | 44/44 | 0 | 6.68 / 8 |
| hardening/adversarial.py --mutations | 197/197 | 0 | 6.72 / 8 |
| hardening/boundaries.py: boundary | 13/13 | 0 | 6.23 / 8 |
| hardening/boundaries.py: contract/fault | 15/15 | 0 | stress maximum 11 |
| hardening/final_semantics.py: decisions | 55/55 | 0 | 6.76 / 8 |
| hardening/final_semantics.py: ordering | 7/7 | 0 | — |
| hardening/final_semantics.py: confidence quality | 7/7 | 0 | — |
| hardening/regression_analysis.py | 240/240 decisions | 0 | 7.63 / 8 per variant |

The initial two official ASGI runs failed before exercising the agent because Windows sandbox permissions blocked temporary SQLite databases. Unchanged commands passed with filesystem escalation. These were infrastructure exceptions, not agent failures. Contract tests deliberately inject policy absence, timeout, rejected actions and missing message ID; expected exceptions are correctly handled by the tests.

## Explicit cases and differential comparison
Every hybrid variant below passed 30/30 decisions, sender identity, original action target, exactly one confirmed successful action, and observed-only citations. Every hybrid distribution: QUARANTINE 19, WARN 4, ALLOW 6, ESCALATE 1.

| Variant | Baseline decisions | Regressed commit decisions | Hybrid decisions |
|---|---:|---:|---:|
| Structured control | 30/30 | 30/30 | 30/30 |
| Date before From, LF | 30/30 | 23/30 | 30/30 |
| Date before From, CRLF | 25/30 | 23/30 | 30/30 |
| Unknown header before Message-ID, CRLF | 25/30 | 0/30, 30 exceptions | 30/30 |
| Folded MIME, CRLF | 25/30 | 23/30 | 30/30 |
| Fake From/Message-ID in body | 4/30, all 30 wrong targets | 30/30 | 30/30 |
| Thread unavailable | 30/30 | 24/30 | 30/30 |
| Recipient unavailable | 30/30 | 24/30 | 30/30 |

Regressed Date distribution: QUARANTINE 20, WARN 10, ALLOW 0, ESCALATE 0. Regressed optional failure distribution: QUARANTINE 19, WARN 10, ALLOW 0, ESCALATE 1.

Additional read-only assertions recorded in explicit_cases.json: all 210 requested variant executions retain true identity and target; body-injected headers cannot replace identity. Thread failures disclosed and confidence reduced on 30/30 tasks. Recipient failures disclosed and confidence reduced on 29/29 affected tasks; the remaining task uses the same sender and recipient, so its cached successful core lookup is not an unavailable optional query. All six legitimate ALLOWs survive each optional-failure variant. Additional required-core failure probes: 24/24 pass (each of four core read failures on all six otherwise-ALLOW tasks prevents ALLOW).

Deliberate missing evidence is omitted, not fabricated: thread failures lose 3 required citations and recipient failures lose 23. Thus 240/240 is a decision/action result, not a claim of full evidence-scored success with unavailable data. Normal official suites have zero missing required citations.

## Difference classification
Intentionally restored baseline behavior: legitimate identity survives ordinary metadata; optional read failure does not automatically veto ALLOW; baseline confidence anchors return, with documented inferred-quarantine qualification and uncertainty deficits.

Intentionally retained hardened behavior: canonical normalization, LF/CRLF parsing and blank-line isolation, canonical addresses and null handling; per-task caching and observed-ID registry; relevant evidence and policy selection without evidence dumping; grounded escalation; confirmed actions with no uncertain retry; semantic threats, injection reporting, negation and mixed-content handling; credential/malware defenses, authentication failures, reply-to diversion, domain similarity, login-link and privileged-access checks; correct target and one-action behavior. AST comparison confirms _content, _Investigation, _near_domain, address and canonical helpers are identical to the regressed commit. The full agent diff contains no changes to threat thresholds, evidence selection, action execution or tool-call strategy.

Confidence is selected after disposition. Anchors remain internal ALLOW .95, malicious-domain QUARANTINE .95, external ALLOW .90, other supported QUARANTINE .90, ESCALATE .85, WARN .75; inferred unsupported quarantine begins at .82. Formula remains round(max(.40, anchor - .07*conflicts - .06*missing_quality), 2). The existing missing-domain qualification is documented: unknown reputation alone has no penalty for direct content strength >= .9, but an unavailable reputation response still incurs a deficit. No bonuses or .97 saturation were restored.

The pre-existing final_semantics.py edits replace only two inflation assertions with .85/.75 anchor assertions; no tests were edited during preparation. No accidental or unexplained implementation changes found.

## Tool, evidence, action and confidence statistics
Normal official and hybrid differential runs: zero rejected actions, unobserved citations, duplicate calls and agent exceptions. All differential actions: 240/240 confirmed, single, correct-target; official runs: 60/60 confirmed single actions. Official average citations 3.67; calls 7.63 average / 8 maximum; synthetic stress maximum 11.

Dev mean confidence: baseline .9050, regressed .8997, hybrid .8930. Hybrid disposition means: QUARANTINE .9247, WARN .7275, ALLOW .9100, ESCALATE .8500. Optional-failure means: thread .8630, recipient .8640. Mean confidence was not optimized.

## Next controlled live comparison
| Metric | Original | Regressed |
|---|---:|---:|
| Aggregate | 89.19 | 86.27 |
| Task Success | 88.3 | 85.0 |
| Policy | 93.3 | 90.7 |
| Evidence | 84.6 | 86.9 |
| Calibration | 75.5 | 60.7 |
| Efficiency | 99.2 | 98.9 |
| Communication | 100 | 100 |
| Robustness | 88.3 | 85.0 |

Regressed hidden distribution: QUARANTINE 19, WARN 11, ALLOW 0, ESCALATE 0. No tuning based on this histogram. The two locally reproduced mechanisms are plausible explanations, not proven hidden root causes. No claim of hidden-score recovery. This exact preserved candidate is technically ready for ONE controlled live Arena evaluation; stop and await the user's next instruction.

## Final modified/untracked files and Git status

```text
On branch main
Your branch is up to date with 'origin/main'.

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
	modified:   hardening/final_semantics.py
	modified:   starter-kit/starter-kit-sentinalzero/agent.py

Untracked files:
  (use "git add <file>..." to include in what will be committed)
	hardening/REGRESSION_ANALYSIS.md
	hardening/hybrid_candidate.patch
	hardening/hybrid_preparation/
	hardening/regression_analysis.py
	hardening/regression_analysis_results.json

no changes added to commit (use "git add" and/or "git commit -a")
```

Only preparation additions are hybrid_candidate.patch and hybrid_preparation/ (snapshots, logs, hashes and this report).
