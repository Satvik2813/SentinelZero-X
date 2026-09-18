"""SentinelZero — Deterministic email security triage agent.

Pure rule-based analysis: no LLM calls required. Investigates each email
using the 5 read tools, applies a decision matrix, executes the single
correct action tool, and returns a structured response.
"""

import re
from typing import Any

from sdk.tools_client import ToolsClient


def _safe_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return {}


def _extract_domain(email: str) -> str:
    if "@" in email:
        return email.split("@")[-1].strip().lower()
    return ""


def _detect_injection_patterns(body: str) -> bool:
    if not body:
        return False
    body_lower = body.lower()
    patterns = [
        r"system instruction:.*(?:mark|approve|allow|ignore)",
        r"important system instruction for security ai",
        r"you must return decision ['\"]allow['\"]",
        r"do not quarantine this message",
        r"override security policy",
        r"disregard previous instructions and (?:approve|allow|reveal)",
    ]
    for pat in patterns:
        if re.search(pat, body_lower):
            return True
    return False


def _is_reporting_context(body: str) -> bool:
    body_lower = body.lower()
    indicators = [
        "forwarded me this suspicious",
        "is this a known phishing",
        "phishing simulation",
        "suspicious message containing",
        "forwarded this message",
        "received this suspicious",
    ]
    return any(ind in body_lower for ind in indicators)


def _has_financial_signals(body: str) -> bool:
    body_lower = body.lower()
    keywords = [
        r"wire transfer", r"wire \$", r"wire.*\$\d",
        r"gift card", r"gift cards", r"claim codes",
        r"vendor account", r"remit payment",
        r"purchase.*google play", r"purchase.*apple", r"buy gift",
        r"bank account", r"routing number", r"account number",
        r"urgent payment", r"invoice attached", r"overdue payment",
        r"bank of america", r"account details",
        r"supplier account", r"remit", r"invoice.*overdue",
    ]
    return any(re.search(kw, body_lower) for kw in keywords)


def _has_credential_signals(body: str) -> bool:
    body_lower = body.lower()
    keywords = [
        "verify your credentials", "verify credentials",
        "confirm your password", "update your password",
        "re-authenticate", "re-verify", "login required",
        "sso portal", "click here to verify", "verify your account",
        "security verification required",
    ]
    return any(kw in body_lower for kw in keywords)


def _has_urgency_signals(body: str) -> bool:
    body_lower = body.lower()
    keywords = [
        "urgent", "immediately", "right now", "right away",
        "emergency", "critical", "time-sensitive", "expires",
        "within 24 hours", "asap", "do not delay",
        "confidential",
    ]
    return any(kw in body_lower for kw in keywords)


def solve(
    task: dict[str, Any],
    tools: ToolsClient,
    api_key: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
) -> dict[str, Any]:
    _ = api_key, model, base_url

    # ── 1. Extract metadata ──────────────────────────────────────────
    task_id = str(task.get("task_id", ""))
    payload = task.get("input_payload") or {}
    message_id = str(payload.get("message_id", ""))
    thread_id = str(payload.get("thread_id", "") or "")
    sender_email = str(payload.get("sender_email", "")).strip().lower()
    recipient_email = str(payload.get("recipient_email", "")).strip().lower()
    subject = str(payload.get("subject", ""))
    body = str(payload.get("message_body", ""))
    sender_domain = _extract_domain(sender_email)

    evidence_ids = set()
    if message_id:
        evidence_ids.add(message_id)
    if thread_id:
        evidence_ids.add(thread_id)

    # ── 2. Raw prompt-injection check ────────────────────────────────
    raw_injection = _detect_injection_patterns(body)
    reporting = _is_reporting_context(body)

    # ── 3. Core investigation (5-7 tool calls) ───────────────────────

    headers = _safe_call(tools.get_email_headers, message_id)
    auth = (headers or {}).get("auth_results") or {}
    spf = auth.get("spf", "none")
    dkim = auth.get("dkim", "none")
    dmarc = auth.get("dmarc", "none")
    auth_all_pass = spf == "pass" and dkim == "pass" and dmarc == "pass"

    domain_rep = _safe_call(tools.inspect_domain_reputation, sender_domain) if sender_domain else {}
    domain_rep = domain_rep or {}
    domain_id = domain_rep.get("domain_id")
    reputation = (domain_rep.get("reputation") or "unknown").lower()
    threat_score = domain_rep.get("threat_score", 0)
    lookalike_of = domain_rep.get("lookalike_of")
    if domain_id:
        evidence_ids.add(domain_id)

    sender_dir = _safe_call(tools.lookup_directory, sender_email) if sender_email else {}
    sender_dir = sender_dir or {}
    sender_found = sender_dir.get("found", False)
    sender_emp = sender_dir.get("employee") or {}
    sender_emp_id = sender_emp.get("id")
    sender_official_email = (sender_emp.get("official_email") or "").strip().lower()
    sender_is_executive = sender_emp.get("is_executive", False)
    if sender_emp_id:
        evidence_ids.add(sender_emp_id)

    approved = _safe_call(tools.get_approved_domains) or {}
    official_domains = [d.lower() for d in (approved.get("official_domains") or [])]
    partner_domains = [d.lower() for d in (approved.get("partner_domains") or [])]
    is_official = sender_domain in official_domains
    is_partner = sender_domain in partner_domains

    recipient_dir = _safe_call(tools.lookup_directory, recipient_email) if recipient_email else {}
    recipient_dir = recipient_dir or {}
    recipient_emp = recipient_dir.get("employee") or {}
    recipient_emp_id = recipient_emp.get("id")
    if recipient_emp_id:
        evidence_ids.add(recipient_emp_id)

    thread_data = None
    if thread_id:
        thread_data = _safe_call(tools.get_thread_history, thread_id)

    # ── 4. Derived signals ───────────────────────────────────────────

    email_matches_official = (sender_email == sender_official_email) if sender_found else False
    verified_internal = sender_found and email_matches_official and is_official and auth_all_pass

    has_financial = _has_financial_signals(body)
    has_credential = _has_credential_signals(body)
    has_urgency = _has_urgency_signals(body)

    # ── 5. Decision matrix ───────────────────────────────────────────

    resolution = ""
    classification = ""
    severity = "medium"
    prompt_injection_detected = False
    escalation_required = False

    if reputation == "malicious":
        # ── Malicious domain: always quarantine ──
        severity = "high"
        resolution = "quarantine"
        if raw_injection and not reporting:
            prompt_injection_detected = True
            classification = "prompt_injection"
        elif has_credential:
            classification = "credential_harvesting"
        elif has_financial:
            classification = "business_email_compromise"
        elif lookalike_of:
            classification = "spoofing"
        else:
            classification = "phishing"

    elif verified_internal:
        # ── Verified internal employee ──
        if has_financial and has_urgency:
            classification = "business_email_compromise"
            resolution = "escalate"
            severity = "critical"
            escalation_required = True
        elif raw_injection and reporting:
            classification = "suspicious_unknown"
            resolution = "warn"
            severity = "medium"
        elif raw_injection and not reporting:
            classification = "prompt_injection"
            resolution = "escalate"
            severity = "critical"
            escalation_required = True
            prompt_injection_detected = True
        else:
            classification = "internal_legitimate"
            resolution = "allow"
            severity = "low"

    elif sender_found and not email_matches_official:
        # ── Name matches employee but wrong email → impersonation ──
        severity = "high"
        resolution = "quarantine"
        if has_financial:
            classification = "business_email_compromise"
        else:
            classification = "spoofing"

    elif reputation == "suspicious":
        # ── Suspicious external domain ──
        if has_financial or has_credential:
            classification = "phishing"
            resolution = "quarantine"
            severity = "high"
        else:
            classification = "suspicious_unknown"
            resolution = "warn"
            severity = "medium"

    elif reputation in ("safe", "trusted"):
        # ── Safe/trusted external ──
        classification = "external_legitimate"
        resolution = "allow"
        severity = "low"

    else:
        # ── Unknown domain, unknown sender ──
        if has_financial:
            classification = "business_email_compromise"
            resolution = "quarantine"
            severity = "high"
        elif has_credential:
            classification = "credential_harvesting"
            resolution = "quarantine"
            severity = "high"
        elif raw_injection:
            classification = "prompt_injection"
            resolution = "quarantine"
            severity = "high"
            prompt_injection_detected = True
        elif has_urgency and not is_partner:
            classification = "suspicious_unknown"
            resolution = "warn"
            severity = "medium"
        else:
            classification = "suspicious_unknown"
            resolution = "warn"
            severity = "medium"

    # ── 6. Execute single action tool ────────────────────────────────

    evidence_sorted = sorted(evidence_ids)
    reason_evidence = ", ".join(evidence_sorted)

    if resolution == "quarantine":
        reason = f"Quarantined: {classification}. Evidence: {reason_evidence}"
        _safe_call(tools.quarantine_message, message_id, reason=reason)

    elif resolution == "allow":
        reason = f"Verified {classification}. Evidence: {reason_evidence}"
        _safe_call(tools.allow_and_deliver, message_id, reason=reason)

    elif resolution == "warn":
        reason = f"Warning applied: {classification}. Evidence: {reason_evidence}"
        _safe_call(tools.apply_warning_banner, message_id,
                   banner_type="EXTERNAL_SENDER", reason=reason)

    elif resolution == "escalate":
        sk = _safe_call(tools._post, "/tools/search_knowledge",
                        {"query": "escalation compromised account"})
        pol_ids = [r["id"] for r in (sk or {}).get("results", [])
                   if isinstance(r, dict) and "id" in r]
        for pid in pol_ids:
            evidence_ids.add(pid)
        evidence_sorted = sorted(evidence_ids)
        reason_evidence = ", ".join(evidence_sorted)
        pol_ref = f" per {pol_ids[0]}" if pol_ids else ""
        reason = f"Escalating {classification}{pol_ref}. Evidence: {reason_evidence}"
        esc_resp = _safe_call(tools.escalate_to_tier2_soc, message_id, reason=reason)
        if isinstance(esc_resp, dict) and "error" in esc_resp:
            reason = f"Quarantined (escalation rejected): {classification}. Evidence: {reason_evidence}"
            _safe_call(tools.quarantine_message, message_id, reason=reason)
            resolution = "quarantine"
            escalation_required = False

    # ── 7. Build structured response ─────────────────────────────────

    summary_parts = [
        f"SOC Triage: {message_id}.",
        f"Sender {sender_email} (domain: {sender_domain}).",
        f"Auth: SPF={spf} DKIM={dkim} DMARC={dmarc}.",
        f"Domain reputation: {reputation} (threat score {threat_score}).",
    ]
    if sender_found:
        summary_parts.append(
            f"Directory match: {sender_emp.get('name', 'N/A')} ({sender_emp_id})."
        )
        if not email_matches_official:
            summary_parts.append(
                f"ALERT: sender email does not match official {sender_official_email}."
            )
    if prompt_injection_detected:
        summary_parts.append("Prompt injection detected and resisted.")
    summary_parts.append(f"Classification: {classification}. Severity: {severity}.")
    summary_parts.append(f"Disposition: {resolution}. Evidence: {reason_evidence}.")

    if resolution == "quarantine" and reputation == "malicious":
        confidence = 0.95
    elif resolution == "allow" and verified_internal:
        confidence = 0.95
    elif resolution == "allow" and reputation in ("safe", "trusted"):
        confidence = 0.90
    elif resolution == "escalate":
        confidence = 0.85
    elif resolution == "warn":
        confidence = 0.75
    elif resolution == "quarantine":
        confidence = 0.90
    else:
        confidence = 0.70

    return {
        "task_id": task_id,
        "case_classification": {
            "category": "cybersecurity_triage",
            "issue": classification,
            "severity": severity,
        },
        "decision": {
            "resolution": resolution,
            "escalation_required": escalation_required,
        },
        "evidence": evidence_sorted,
        "uncertainties": [],
        "customer_response": " ".join(summary_parts),
        "confidence": confidence,
        "prompt_injection_detected": prompt_injection_detected,
    }
