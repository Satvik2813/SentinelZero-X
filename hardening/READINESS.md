# SentinelZero-X hardening readiness report

Local-only validation, 2026-09-18. No Arena endpoint was contacted; no live submission, commit, or push was performed.

## Audit and diagnosis

The working tree initially contained an uncommitted live-input parser. Its functionality was preserved and extended; a complete copy of the original working agent is in `hardening/baseline_agent.py`.

Reviewed the agent, runtime, SDK, simulator tool implementations, action validation, evidence registry, grading paths, instructions, policies, sample datasets, mock JSON data, and Git history/diff. No preexisting test or benchmark scripts were found. The authoritative problem statement and executable SDK/server take precedence over the stale README: the README describes different actions and a 100-call budget; the actual constraint is 40.

The original agent independently reproduced 30/30 development passes with zero action rejections. Its generalization weaknesses were early allow decisions on safe/trusted reputation, unused thread context, narrow content patterns, broad financial keywords, fuzzy directory hits treated as proof of impersonation, global reporting exemptions, unconditional input-ID citations, fixed confidence, and swallowed action failures.

The simulator correlates authentication with domain reputation, masking conflicts that independent synthetic fixtures exercise. Its CSV and JSON evidence requirements differ (CSV includes additional policies). The actual simulator JSON requirements were preserved unchanged. Its server evidence registry also omits core SOC read response IDs when validating escalation; a policy search result remains necessary. The aggregate live score supplied by the user cannot identify exact hidden failures, and no hidden examples were accessed.

## Changes and recommendations

| Change | Generalization benefit | Recommendation |
| --- | --- | --- |
| Canonical defensive input parser | Handles both payload formats, display addresses, CRLF, case/order/spacing changes, partial/null data; body headers cannot overwrite message identity | Keep |
| Independent content, identity, authentication, domain and thread signals | Trusted reputation cannot bypass credential, fraud, malware or injection checks; weak identity anomalies alone do not force quarantine | Keep |
| Conflict-aware disposition | Authenticated internal compromise escalates; DMARC-failed official mail is blocked; SPF-only forwarding with aligned DKIM/DMARC can remain legitimate | Keep |
| Thread and bounded URL investigation | Recognizes sender switches/payment changes; checks at most two unique sensitive-link hosts; authenticated established correspondence can support unknown senders | Keep; URL coverage cap is explicit |
| Scoped injection reporting/negation handling | Distinguishes quoted examples and defensive advice from subsequent active instructions; normalizes Unicode and whitespace | Keep, with regex limitations below |
| Evidence registry and selective citations | Uses only observed IDs; omits empty thread references and irrelevant recipient matches; adds one relevant retrieved policy for applicable blocked cases | Keep; hidden evidence F1 is unmeasured |
| Evidence-quality confidence and uncertainties | Counts independent supporting families, discounts conflicts/missing data, caps ambiguity; no fit to ground truth | Keep provisionally; empirical calibration still needs independent labeled data |
| Confirmed single action | Checks delivery status; never retries an uncertain action and never reports unconfirmed success | Keep; infrastructure failure behavior is explicit |

All competition logic remains in `starter-kit/starter-kit-sentinalzero/agent.py`. No fixed task IDs, benchmark sender/domain shortcuts, policy ID literals, or expected-resolution mappings occur in it. Security policy categories and generic security patterns are used instead.

## Validation results

| Suite | Result | Average / maximum tool calls |
| --- | --- | --- |
| Original agent, official local simulator | 30/30 | 7.03 / 8 |
| Hardened agent, official local simulator, development payload | 30/30 | 7.63 / 8 |
| Hardened agent, official local simulator, Arena-style formatted input | 30/30 | 7.63 / 8 |
| Core independent adversarial matrix | 44/44 | 6.68 / 8 |
| Additional boundary scenarios | 13/13 | 6.23 / 8 |
| Non-identical mutation variants | 197/197 | 6.72 / 8 |
| Contract/fault/calibration-order checks | 15/15 | Stress maximum 11 |

The original agent passed 18/44 in the initial core matrix. These synthetic results measure the stated policy expectations, not hidden benchmark accuracy. Cases discovered during testing were fixed and retained as regression coverage; this is not a held-out statistical evaluation.

Official regressions use the unchanged FastAPI app through its in-process TestClient and the real SDK, with a fresh temporary SQLite database. They assert required evidence, exactly one action, actual delivery state, zero rejections, and observed-ID provenance. No `.env` is loaded and no network connection is made. The only runtime configuration substitution is the temporary database path.

Mutation variants change capitalization, whitespace, amounts, attack paraphrases, Unicode presentation, header formatting/order, names and domains with their world relationships preserved. Variants with no effective input change were removed from the final count (197, superseding the earlier 308 generated variants).

Prompt-injection checks cover direct override commands, semantic security-agent directives, subject injection, quoted examples, awareness discussion, reported suspicious samples, negated advice, and reporting text followed by an actual attack. Both the disposition and injection flag are asserted throughout the core and mutation suites.

## Evidence and confidence

Average dev evidence list size: 4.03 before, 3.67 after, with 100% required dev evidence recall and zero unobserved citations. The intermediate implementation without additional policy citations averaged 3.03. Policy IDs are selected by retrieved policy category, never constructed. Escalation remains grounded and reaches `escalated_to_soc` with zero rejected escalations.

Confidence starts at 0.68, adds 0.085 per independent supporting family (maximum four), subtracts 0.07 per conflict and 0.04 per missing-evidence category (maximum three). Caps are 0.97 for clear dispositions, 0.87 for escalation and 0.84 for warning; floor 0.40. Unit checks establish that missing/conflicting evidence reduces confidence. This is an interpretable heuristic, not a probability model fitted or validated on hidden outcomes.

Mean dev confidence changed from 0.905 to 0.852. Since all dev decisions are correct, the problem statement's confidence-based calibration component would be lower on these easy cases. This is an intentional caution trade-off, not a claim of a measured calibration improvement. Average investigation cost increased by 0.60 calls; no dev correctness, input compatibility, escalation, evidence-validity or action-state regression was observed. No complete seven-dimension local score is claimed.

## Remaining risks

- Pattern-based reasoning still misses obfuscated, multilingual, image-only or novel semantic attacks; it can misread nuanced quotation/negation or benign financial language.
- Domain similarity and the high-score conflict threshold are conservative heuristics, not public-suffix-aware brand verification or calibrated threat-intelligence fusion.
- Only two sensitive URL hosts are inspected; attachments and redirect chains cannot be analyzed with the available tools. Reports disclose additional uninvestigated hosts.
- Retrieved thread history supports consistency, not proof against a compromised conversation. Thread order and unusual tool schemas remain potential edge cases.
- If the action target is missing, escalation policy evidence is unavailable, or an action is rejected/unconfirmed, the agent raises a sanitized error rather than fabricating a successful disposition or attempting a second action. These injected infrastructure faults intentionally do not complete as successful tasks. The official regression has no such errors.
- Live tool status schema is not reverified because live access was prohibited. Confirmation uses the documented simulator/SDK action statuses.
- Hidden success, evidence F1 and calibration improvements remain unverified. Recommend retaining this candidate for user review, with no automatic live run.

## Files and Git review

Modified tracked file: `starter-kit/starter-kit-sentinalzero/agent.py` (332 additions, 342 deletions against HEAD at final review; this includes the preexisting uncommitted parsing change).

New local-only files outside the starter kit:
- `hardening/baseline_agent.py`: exact pre-change working implementation.
- `hardening/regression.py`: official ASGI/SDK regression harness.
- `hardening/adversarial.py`: policy-based synthetic fixtures and mutations.
- `hardening/boundaries.py`: additional semantic, schema, failure and budget checks.
- `hardening/READINESS.md`: this report.

Official runtime, SDK, simulator, policies and benchmark datasets are unchanged. `git diff --check` passed. Tracked secret-file checks and common credential-pattern scanning found zero findings; this is a scoped check, not a comprehensive secret audit. No secrets or `.env` contents were printed. No commits or pushes were made.

## Reproduction

From the repository root (Python with the already installed FastAPI/httpx dependencies):

```powershell
python -B hardening/regression.py --baseline
python -B hardening/regression.py
python -B hardening/regression.py --live-format
python -B hardening/adversarial.py
python -B hardening/adversarial.py --mutations
python -B hardening/boundaries.py
```

The Windows sandbox denied access to the default temporary database directory; the official regressions were run with approved escalation. The tests still run entirely in-process and never contact the live Arena.
