# Final targeted hardening pass — SentinelZero-X

Local-only validation, 2026-09-18. This report supersedes the calibration and current-result sections of READINESS.md; that report remains the history of the first hardening pass. No live Arena calls, endpoint probes, submissions, commits or pushes occurred.

## 1. Read-only calibration audit

Before editing, inspected the current agent, existing local harnesses, policy definitions and working-tree state. Measured the frozen candidate through the official simulator functions without loading secrets or contacting any service.

Old calculation:

`0.68 + 0.085 * min(4, supporting families) - 0.07 * conflicts - 0.04 * min(3, missing items)`

Floor 0.40; ceiling 0.97; extra ceilings WARN 0.84 and ESCALATE 0.87.

Problems:
- Any hostile content counted as a single boolean regardless of strength. Direct password theft and a weak suspicious-link inference could contribute equally.
- Identity/authentication support was discarded for escalation; the conflict that justified review then reduced confidence in review. The dev escalation scored only 0.70.
- Retrieved policy evidence did not affect action certainty.
- WARN used an almost constant supporting count, without a decision-margin assessment. Weak suspicion could score higher than clear BEC (0.84 versus 0.81 in the new suite).
- Unknown reputation and a failed reputation lookup could both penalize the same evidence gap; partial authentication gaps were inconsistently represented.
- Clear internal mail was already relatively confident, but some safe external cases with incomplete authentication scored 0.72. Merely raising all legitimate scores would be unjustified.

The initial 47-case semantic suite found nine disposition defects before editing: defensive quoted/negated injection, spaced-out injection, security-filter override alone, short gift-card requests, two receipt-query forms, confidential-payment commands, and a benign new email-account announcement.

## 2. Exact targeted changes

The existing architecture, investigation workflow, disposition fusion, evidence selection, escalation lookup and action execution are preserved. Agent diff against the frozen hardened candidate: **65 lines added, 15 removed**.

### Confidence

`_confidence` now accepts one strength (0–1) per independent evidence family. Production families are identity, authentication, domain reputation, content, thread/context and retrieved policy where applicable. Multiple keywords in the same family do not multiply support.

The calculation is:

`raw = 0.55 + 0.24 * strongest_family + 0.055 * sum(other_families) + 0.06 * decision_margin`

`confidence = round(clamp(min(0.97, raw) - 0.07 * contradictions - 0.06 * missing_quality, 0.40, 0.97), 2)`

- Strong direct credential/injection/malware evidence receives greater content strength than inferred risky-link or privilege signals.
- Authenticated ownership does not count as proof of benign intent for external BEC/phishing.
- Clear impersonation plus a financial request receives identity support even when authentication passes.
- Relevant retrieved policy supports the chosen action, not an independent claim that the sender is malicious.
- Verified internal identity plus hostile behavior supports escalation. It no longer mechanically penalizes certainty that human review is required.
- Margin is a rule-derived assessment of how clearly the action is supported: decisive content, malicious reputation, corroborated impersonation, or verified internal compromise have larger margins than weak-link/unknown-sender boundaries. It is not a fitted competing-class probability.
- Missing families are counted once, with a smaller penalty for an unknown reputation than an unavailable tool result. Critical missing headers remain a material deficit. Deficits are applied after the ceiling, so saturation cannot hide missing evidence.
- All actions share the same 0.97 ceiling. A clear WARN or ESCALATE is no longer capped simply because of its name. Floor remains 0.40.

### Semantics

- Normalize recognizable letter-spaced `i g n o r e` before quotation analysis.
- Recognize quoted examples introduced by `say`, defensive instructions not to obey messages, and indirect security-filter override directives.
- Stop defensive exemptions at clause boundaries so a following active instruction remains visible.
- Distinguish a transfer receipt/question from a fresh payment request. The receipt exemption accepts only a narrow transaction noun phrase, preventing unrelated receipt wording from swallowing an active transfer instruction.
- Detect short `need ... gift cards` and `process ... payment` requests.
- Treat payment-account changes as financial signals, while leaving a new email/login account announcement alone. Include account-number changes explicitly tied to future payments.
- Exclude a narrowly negated gift-card need, preserving subsequent transfer/purchase instructions.

An established finance thread does not authorize a new wire request under the official policy. The legitimate cases are expected-payment status/receipt messages, not instructions to transfer money through email alone.

## 3. Confidence before and after

The baseline here is the hardened candidate at the start of this pass, not the original competition agent.

| Dev disposition | Tasks | Before | After |
| --- | ---: | ---: | ---: |
| ALLOW | 6 | 0.8300 | 0.8600 |
| WARN | 4 | 0.8175 | 0.7425 |
| QUARANTINE | 19 | 0.8737 | 0.9416 |
| ESCALATE | 1 | 0.7000 | 0.9700 |
| Overall | 30 | **0.8517** | **0.8997** |

No expected dev outcomes are read by the agent or used to fit these weights. Increased average confidence is a measured consequence, not the optimization target. WARN decreased because unresolved cases no longer inherit a nearly fixed strong support count. This decrease is a local score trade-off for those correct warnings; overall confidence alignment on the all-correct dev set increased.

These remain heuristic confidence estimates. Passing ordering tests and improving an easy local mean do not establish probabilistic calibration or a hidden-benchmark improvement. Independent labeled data would be needed for reliability curves/Brier validation.

## 4. Validation

| Suite | Result |
| --- | ---: |
| Official local simulator, development payload | **30/30** |
| Official local simulator, Arena-style local input | **30/30** |
| Existing core adversarial | **44/44** |
| Existing additional boundary scenarios | **13/13** |
| Existing non-identical mutation suite | **197/197** |
| Existing contract/fault checks | **15/15** |
| New targeted semantic cases | **55/55** |
| New confidence ordering checks | **7/7** |
| New confidence quality checks | **7/7** |

Both official regressions were rerun after the final agent edit. They assert actual world state, one successful action, required evidence, citation provenance and no enforcement rejection. Escalation still reaches `escalated_to_soc`. No rejected actions, fabricated evidence or runtime exceptions occurred on valid benchmark/synthetic cases. Existing injected infrastructure-fault tests retain their intentional sanitized-stop behavior.

New semantics cover all seven requested injection forms, mixed/negated/quoted variants, receipt-versus-payment ambiguity, gift-card and confidential-payment requests, benign account announcements, established finance context, sender/account changes, all requested authentication conflicts, new/unknown sender cases and clean-domain social engineering. Additional guards ensure negative advice and receipt claims cannot hide later attacks.

Confidence comparisons:

| Stronger case | Confidence | Weaker case | Confidence |
| --- | ---: | --- | ---: |
| Clear phishing | 0.97 | Ambiguous phishing | 0.75 |
| Clear internal legitimate | 0.97 | Unknown benign authenticated external | 0.70 |
| Clear BEC despite passing auth | 0.94 | Suspicious domain, benign content | 0.72 |
| Complete credential evidence | 0.97 | Missing headers and reputation | 0.76 |
| Consistent credential evidence | 0.97 | Conflicting trusted reputation | 0.90 |
| Clear internal legitimate | 0.97 | Internal identity, headers unavailable | 0.82 |
| Clear grounded escalation | 0.97 | Weak suspicion | 0.72 |

Quality checks also verify justified high confidence for clear phishing/internal/BEC, escalation above the old cap, no WARN-specific cap, moderate unknown-external confidence and a material critical-missing-data reduction.

## 5. Efficiency and evidence

Unchanged on dev: **7.63 average / 8 maximum tool calls**, **3.67 average evidence IDs**, zero invalid citations, zero rejected escalations. Existing synthetic stress maximum remains **11**, safely below 40. New semantic suite averages **6.76**, maximum **8**. No new investigation calls were introduced by calibration. Existing and new synthetic suites assert no duplicate lookups.

Evidence selection and action confirmation were not changed. Policy retrieval still occurs before escalation; only observed IDs can be cited.

## 6. Keep/revert decisions and risks

| Change | Recommendation | Reason |
| --- | --- | --- |
| Family strength and policy contribution | **KEEP** | Distinguishes strong direct evidence from weak inference without counting repeated keywords |
| Decision margin | **KEEP** | Separates clear action boundaries from genuine ambiguity |
| Action-centric escalation confidence | **KEEP** | Uncertain cause can coexist with a clear need for review |
| Remove WARN/ESCALATE caps | **KEEP** | Confidence should follow evidence, not severity or disposition label |
| Missing-family accounting and post-ceiling penalties | **KEEP** | Prevents double penalties and ensures deficits remain visible |
| Scoped semantic corrections | **KEEP** | Fixes reproduced defects while preserving all prior tests |

No observed correctness, evidence, escalation or efficiency regression remains. No major change is recommended for reversion. The candidate should be retained for user review; this does not authorize a live run.

Remaining risks: English regex semantics are incomplete; complex quotations, tense, negation, multilingual/encoded attacks and unusually worded financial instructions may still be misread. Decision margins and strength weights are not empirically fitted probabilities. The unchanged limited-link inspection and critical-infrastructure-failure behavior documented in READINESS.md still apply.

## 7. Files and reproduction

Only `starter-kit/starter-kit-sentinalzero/agent.py` changed within the starter kit. No official infrastructure or dataset changed. The local regression harness now reports mean confidence by disposition. New files are `hardening/pre_final_agent.py` (exact frozen input candidate), `hardening/final_semantics.py`, and this report.

`git diff --check` passed; no tracked secret files or dataset shortcut markers were found. No `.env` contents were read or printed. No commit or push was performed.

```powershell
python -B hardening/regression.py --pre-final
python -B hardening/regression.py
python -B hardening/regression.py --live-format
python -B hardening/adversarial.py
python -B hardening/adversarial.py --mutations
python -B hardening/boundaries.py
python -B hardening/final_semantics.py
```

The simulator runs through an in-process ASGI client with a temporary SQLite database and no network. The official local regression needed the already approved Windows temporary-directory permission escalation.
