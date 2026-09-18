# SentinelZero-X regression analysis and hybrid candidate

This report supersedes the earlier readiness recommendations where they conflict. The user reports a repeatable live regression: 89.19% -> 86.27% aggregate, reproduced twice. No live Arena access, hidden-task inspection, commit or push was performed during this analysis.

## 1. Recovered baseline and provenance

The exact preserved pre-hardening source is `hardening/baseline_agent.py` (385 lines).

- SHA-256: `dc6118c38b0127cda831098438ee0a547b3256d9ac75d8a9ca2c48a712e86985`
- It equals commit `a895b28a38e39254c871c9f3b0d0141ac0e1afcf` plus the 21-line Arena customer_message parser that was uncommitted when the first hardening pass began.
- Commit `a895b28` alone is NOT the complete live-compatible baseline. The snapshot includes that parser and the working escalation-policy lookup.
- `hardening/pre_final_agent.py` is the first hardened candidate, not the 89.19% baseline. Its SHA-256 is `3f51a982681fc2b3618442ba45dacc15f4d635451fe9c70a22db4d32003f7f83`.
- The regressed final candidate is recoverable unchanged from commit `04e25a610ec2824a3ecc0b1029ac18deab3e8bed`; agent SHA-256 before this analysis was `4f01c4b853b105767aa2572ac35cc764d959b13465364d75ee74f668a2075b7e`.

Git history, reflog, prior diffs and preserved agent snapshots were inspected. The baseline snapshot has continuous provenance from the first read-only audit and is the source associated with the user's reported 89.19%. There is no independent live-run manifest binding that score to a source hash; the score attribution comes from the user's original baseline report, not a newly verified live artifact.

## 2. What the reported scores establish

| Metric | Original live | Hardened live | Difference, percentage points |
| --- | ---: | ---: | ---: |
| Aggregate | 89.19 | 86.27 | -2.92 |
| Task Success | 88.3 | 85.0 | -3.3 |
| Policy | 93.3 | 90.7 | -2.6 |
| Evidence | 84.6 | 86.9 | +2.3 |
| Calibration | 75.5 | 60.7 | -14.8 |
| Efficiency | 99.2 | 98.9 | -0.3 |
| Communication | 100 | 100 | 0 |
| Robustness | 88.3 | 85.0 | -3.3 |

Current reported hidden distribution: 19 QUARANTINE, 11 WARN, zero ALLOW, zero ESCALATE. Treat the regression as real. These aggregates do not identify specific incorrect tasks, rejected actions, per-task confidence, or expected dispositions. The previous hidden disposition histogram is unavailable, so zero ALLOW/ESCALATE alone cannot prove which individual decisions changed.

## 3. Confirmed local regressions

### Header parsing can remove sender identity

The original parser scanned the formatted input for recognized headers. Hardening changed it to stop at the first unrecognized header. Consequently an ordinary `Date:` after `Message-ID:` but before `From:` leaves message_id present but sender_email empty. Domain reputation and directory lookup then receive empty identifiers. The agent retains enough content to quarantine threats or warn, but cannot establish internal/external legitimacy or internal compromise.

This defect exists in the first hardened snapshot and final candidate. The existing Arena-style regression only generated recognized headers, so it never exercised the failure.

Differential replay on all 30 public development tasks:

| Local variant | Original baseline decisions | Regressed decisions | Hybrid decisions |
| --- | ---: | ---: | ---: |
| Structured input | 30/30 | 30/30 | 30/30 |
| Added Date header, LF | 30/30 | 23/30 | 30/30 |
| Added Date header, CRLF | 25/30 | 23/30 | 30/30 |
| Unknown header before Message-ID, CRLF | 25/30 | 0/30, 30 exceptions | 30/30 |
| Folded MIME header, CRLF | 25/30 | 23/30 | 30/30 |
| Optional thread lookup unavailable | 30/30 | 24/30 | 30/30 |
| Optional recipient lookup unavailable | 30/30 | 24/30 | 30/30 |
| Fake headers appended inside body | 4/30; wrong target in all 30 | 30/30 | 30/30 |

With the added Date header, the regressed distribution becomes **20 QUARANTINE / 10 WARN / zero ALLOW / zero ESCALATE**. This reproduces the structural pattern, not the exact hidden counts, and was not tuned to match those counts.

The old baseline's CRLF weakness is separate: its body split requires LF-LF. A wholesale revert would restore that bug. It also reads fake From/Message-ID lines in the body as headers, changing the action target. The hybrid retains the hardened blank-line boundary and CRLF normalization.

### Optional-tool failure vetoes legitimate delivery

Both hardened versions require `not inv.failures` for ALLOW. A failed thread lookup or recipient-directory lookup therefore demotes every otherwise legitimate message to WARN, even when sender identity, headers, approved domains and reputation are available and benign. In the failure replay, all six local ALLOW decisions become WARN. This gate is stricter than the original baseline and is unrelated to the content's risk.

The hybrid requires successful core checks but does not use optional failures as an unconditional ALLOW veto. Such failures remain disclosed and reduce confidence. Missing required evidence is never fabricated to compensate.

### Limits on attributing the hidden regression

These are demonstrated bugs and plausible causes of lost ALLOW/ESCALATE paths. We do NOT know whether hidden inputs contain these exact headers or optional-tool failures. Broad header loss also removes many citations in local replay, whereas reported hidden evidence improved; this is a reason NOT to present header loss as a proven explanation for the whole hidden run. The actual hidden root cause remains unconfirmed without a run trace. No new hidden trace was requested or retrieved.

## 4. Decision-policy comparison

| Area | Original 89.19%-associated source | Regressed hardened source | Hybrid |
| --- | --- | --- | --- |
| Benign trusted external | Allows despite optional read failures | Any read failure vetoes ALLOW | Restores tolerance of optional failures; core failures still prevent ALLOW |
| Benign verified internal | ALLOW | Can lose identity during parsing or be vetoed by optional failure | Restores usable identity and optional-failure tolerance |
| Internal hostile behavior | Financial+urgent/injection can escalate | Broader compromise signals, but requires intact identity | Retains broader checks and grounded review, repairs identity loss |
| Trusted sender with direct credential/malware/injection | May allow due to early trust branch | Blocks/escalates based on content | Retained; returning to unconditional trust would reintroduce demonstrated misses |
| Routine financial language | Broad keywords can quarantine | Receipt/invoice/negation handling is narrower | Retained |
| Financial authorizations/account changes | Broad risk rules | More content-based blocking, including trusted senders | Retained under published policy; hidden false-positive contribution cannot be isolated from aggregates |
| Weak identity mismatch | Often quarantines automatically | Can warn without corroborating threat | Retained |
| Authentication failures | Limited fusion | Explicit failure/alignment handling | Retained |
| Action outcome | Errors can be swallowed | Requires confirmed status and no uncertain retry | Retained |

Other hardened additions—similarity-based lookalikes, reply-to diversion, high-score conflicts, privileged-access requests and suspicious login links—can move borderline legitimate mail toward WARN/QUARANTINE. They remain possible contributors to hidden errors. They were not broadly relaxed without task-level evidence. The original baseline still passes only 18/44 of the current core adversarial suite; the hybrid preserves 44/44. This is a targeted restoration of proven benign-path behavior, not a wholesale decision-engine revert.

## 5. Confidence forensics and hybrid formula

Confidence is computed AFTER resolution selection. Changing caps/margins cannot directly cause zero ALLOW or zero ESCALATE. Moreover, an escalation confidence cap cannot directly affect a run containing no escalations.

The regression is not simply uniform inflation: the final hardening pass raised strong-threat/escalation confidence but reduced WARN confidence in the existing dev replay. Wrong dispositions with high confidence can hurt calibration, but replacing legitimate ALLOWs with uncertain WARNs and losing required escalations can also lower the reported calibration metric. The published problem statement also couples calibration to escalation correctness. Hidden per-task scores are unavailable, so these contributions cannot be separated.

### Original baseline

Fixed confidence anchors:
- Malicious-domain QUARANTINE: 0.95.
- Verified internal ALLOW: 0.95.
- Safe/trusted external ALLOW: 0.90.
- Other QUARANTINE: 0.90.
- ESCALATE: 0.85.
- WARN: 0.75.

### Regressed final candidate

`raw = 0.55 + 0.24 * strongest_family + 0.055 * sum(other_families) + 0.06 * decision_margin`

`confidence = round(clamp(min(0.97, raw) - 0.07 * conflicts - 0.06 * missing_quality, 0.40, 0.97), 2)`

Problems: policy retrieval can inflate confidence despite providing no independent threat observation; hand-assigned margins add another unvalidated boost; multiple correlated identity/auth/domain signals can saturate at 0.97; the earlier cap-removal tests measured an implementation preference rather than empirical calibration.

The intermediate pre_final snapshot used `0.68 + 0.085*min(4,support) - 0.07*conflicts - 0.04*min(3,missing)`, with WARN capped at 0.84 and ESCALATE at 0.87. It shares the parser/optional-veto bugs and is not the appropriate behavioral rollback target.

### Hybrid

Restores the original anchors above, with two qualifications:
- An inferred quarantine without malicious reputation, direct high-strength content or corroborating identity evidence starts at **0.82**, not 0.90.
- Apply explicit deficits: `round(max(0.40, anchor - 0.07*conflicts - 0.06*missing_quality), 2)`.

No summed-support bonus, no policy-retrieval bonus, no decision-margin bonus, and no 0.97 saturation. Maximum is 0.95; WARN cannot exceed 0.75 and ESCALATE cannot exceed 0.85. Unknown reputation alone does not reduce confidence in a direct high-strength attack; an unavailable reputation response still does. Optional failures lower confidence without automatically changing benign disposition.

| Dev mean confidence | Original baseline | Regressed final | Hybrid |
| --- | ---: | ---: | ---: |
| ALLOW (6 tasks) | 0.9500 internal / 0.9000 external | 0.8600 combined | 0.9100 combined |
| WARN (4 tasks) | 0.7500 | 0.7425 | 0.7275 |
| QUARANTINE (19 tasks) | 0.95 malicious / 0.90 other | 0.9416 | 0.9247 |
| ESCALATE (1 task) | 0.8500 | 0.9700 | 0.8500 |
| Overall | **0.9050** | **0.8997** | **0.8930** |

The objective is not to maximize the easy dev mean or simply reduce every confidence. Legitimate ALLOW mean rises relative to the regressed implementation. These estimates remain heuristic; no hidden recovery or probabilistic calibration improvement is claimed.

## 6. What was reverted and retained

Reverted/repaired:
1. Terminating header parsing on ordinary unrecognized headers.
2. Blanket optional-failure veto on ALLOW.
3. Additive family/margin/policy confidence inflation and universal 0.97 ceiling.
4. The two tests that mandated removal of WARN/ESCALATE bounds.

Retained unchanged in substance:
- Canonical input normalization, address parsing, null handling and body/header isolation.
- Per-task read cache and observed-ID provenance registry.
- Relevant evidence selection and policy citations; no evidence dumping.
- Grounded escalation before action execution.
- Status confirmation and no uncertain action retry.
- Prompt-injection reporting, negation and mixed-content distinctions.
- Existing direct-threat detection, thread/context checks and bounded URL lookups.

The observed hidden evidence gain is consistent with provenance and relevance improvements, but aggregates cannot establish which specific evidence change caused +2.3 points. Retaining these mechanisms avoids an unnecessary rollback of the one improved dimension.

## 7. Local validation

| Suite | Hybrid result |
| --- | ---: |
| Official local simulator, structured input | **30/30** |
| Official local simulator, Arena-style local input | **30/30** |
| Core adversarial | **44/44** |
| Additional boundary cases | **13/13** |
| Existing mutation suite | **197/197** |
| Contract/fault checks | **15/15** |
| Semantic decisions | **55/55** |
| Confidence ordering | **7/7** |
| Updated confidence checks | **7/7** |
| New differential replay, 8 variants x 30 tasks | **240/240 decisions** |

Test change disclosure: before updating tests, the unchanged semantic suite passed all 55 decisions and seven orderings but only **5/7 confidence checks**. `escalation_not_capped` and `warn_not_capped` explicitly required the behavior the user requested reconsidering. They were replaced with checks for the restored 0.85/0.75 anchors. No security scenario labels or disposition expectations were changed.

Official local calls remain **7.63 average / 8 maximum**; existing synthetic stress maximum **11**. Average dev citations remain **3.67**, with no missing required dev citations on the normal full regressions. Zero rejected actions/escalations, unobserved hybrid citations, duplicate hybrid calls, and normal-run exceptions. Escalation still reaches `escalated_to_soc`. Action target and exactly one successful action are verified in the differential replay as well as disposition.

Failure-replay caveat: withholding thread history makes three required thread citations unavailable; withholding recipient lookup makes 23 required recipient citations unavailable. The hybrid deliberately omits those IDs and reports uncertainty. Therefore the 240/240 number measures disposition/escalation correctness, NOT full evidence-scored passes for the deliberately unavailable-evidence variants. The normal official regressions remain fully scored 30/30.

The differential replay also verifies why a complete baseline revert is unsafe: body-injected headers cause the old snapshot to use the wrong action target in all 30 such cases; the hybrid preserves the correct target in all 30.

## 8. Expected recovery, limits and files

The hybrid is expected to improve resilience against the demonstrated conditions that eliminate legitimate disposition paths: recognized headers survive ordinary metadata, and optional-tool failures cannot veto a well-supported benign decision. It restores the original confidence anchors without surrendering the hardened evidence and action safeguards. This is a causal repair of local defects, not a prediction that the next hidden score will equal or exceed 89.19%.

Remaining uncertainty: the hidden input/schema/tool failure profile is unknown; other hardened threat heuristics can still cause false positives; the old baseline is not itself a perfect security oracle; aggregate scores cannot validate confidence weights. No further generic tuning was performed.

Modified:
- `starter-kit/starter-kit-sentinalzero/agent.py`: targeted hybrid.
- `hardening/final_semantics.py`: two disclosed confidence assertions.

Added:
- `hardening/regression_analysis.py`: offline differential harness.
- `hardening/regression_analysis_results.json`: observed local replay results.
- `hardening/REGRESSION_ANALYSIS.md`: this report.

Official infrastructure, SDK, policies and datasets were not changed. The original baseline and both historical hardened versions remain recoverable. HEAD remains `04e25a610ec2824a3ecc0b1029ac18deab3e8bed`; the hybrid is an uncommitted working-tree candidate. No push, commit or live request was made.

Reproduce using the existing regression/adversarial/boundary/semantic commands, plus:

```powershell
python -B hardening/regression_analysis.py
```

The official ASGI regressions use fresh temporary databases and no network; their existing Windows temporary-directory permission requirement still applies.
