"""Deterministic SOC triage. Email text is data, never executable instructions.

Only tool-returned evidence is cited. Independent signals are fused before a
single disposition; authenticated internal compromise requires grounded review.
"""
import html
import json
import re
import unicodedata
from email.utils import parseaddr
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urlsplit

from sdk.tools_client import ToolsClient


def _text(value):
    return value.strip() if isinstance(value, str) else ""


def _dict(value):
    return value if isinstance(value, dict) else {}


def _items(value):
    return value if isinstance(value, list) else []


def _canonical(value):
    value = unicodedata.normalize("NFKC", html.unescape(_text(value)))
    value = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", value)
    return re.sub(r"\s+", " ", value).casefold()


def _address(value):
    value = _text(value)
    try:
        name, address = parseaddr(value)
    except (ValueError, TypeError):
        return "", ""
    address = address.lower().strip()
    if not re.fullmatch(r"[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+", address):
        return name, ""
    local, domain = address.rsplit("@", 1)
    try:
        domain = domain.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return name, ""
    return name, local + "@" + domain


def _extract_domain(value):
    return _address(value)[1].partition("@")[2]


def _normalize(task):
    payload = task.get("input_payload")
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (ValueError, TypeError):
            payload = {}
    payload = _dict(payload)
    raw = _text(task.get("customer_message")).replace("\r\n", "\n").replace("\r", "\n")
    aliases = {"message-id": "message_id", "message_id": "message_id", "thread-id": "thread_id",
               "thread_id": "thread_id", "from": "sender_email", "to": "recipient_email",
               "subject": "subject", "sender-ip": "sender_ip", "references": "references"}
    parsed = {}
    lines = raw.split("\n")
    body_start = len(lines)
    last = None
    for i, line in enumerate(lines):
        if not line.strip():
            body_start = i + 1
            break
        match = re.match(r"^\s*([\w-]+)\s*:\s*(.*)$", line)
        if match:
            # Date, Received and MIME headers do not terminate the header block.
            # Still stop at the blank line: body text cannot overwrite identity.
            last = aliases.get(match[1].lower())
            if last:
                parsed.setdefault(last, match[2].strip())
        elif line[:1].isspace() and i > 0:
            if last:
                parsed[last] += " " + line.strip()
        else:
            body_start = i
            break
    parsed["body"] = "\n".join(lines[body_start:]).strip()
    result = {key: _text(payload.get(key)) or _text(parsed.get(key))
              for key in ("message_id", "thread_id", "sender_email", "recipient_email", "subject", "sender_ip")}
    result["body"] = _text(payload.get("message_body")) or _text(payload.get("body")) or parsed["body"]
    # References normally contains message IDs, not an API thread identifier.
    if not result["thread_id"] and re.fullmatch(r"THR-[\w-]+", parsed.get("references", "")):
        result["thread_id"] = parsed["references"]
    result["display_name"], result["sender_email"] = _address(result["sender_email"])
    result["recipient_email"] = _address(result["recipient_email"])[1] or _text(task.get("customer_id"))
    return result


class _Investigation:
    """Per-task cache and provenance registry. Read failures remain visible."""
    def __init__(self, tools):
        self.tools = tools
        self.cache = {}
        self.registry = {}
        self.failures = []

    def read(self, name, *args):
        key = (name, args)
        if key in self.cache:
            return self.cache[key]
        try:
            if name == "search_knowledge":
                result = self.tools._post("/tools/search_knowledge", {"query": args[0], "top_k": 3})
            else:
                result = getattr(self.tools, name)(*args)
            if not isinstance(result, dict) or result.get("error"):
                raise ValueError("Unavailable tool response")
        except Exception:
            # Do not echo exceptions: transports can include credentials or URLs.
            result = {}
            self.failures.append(name)
        self.cache[key] = result
        self._register(result, key)
        return result

    def _register(self, value, source):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ("id", "domain_id", "message_id", "thread_id", "log_id", "policy_ref") and _text(item):
                    self.registry.setdefault(item, set()).add(source)
                elif isinstance(item, (dict, list)):
                    self._register(item, source)
        elif isinstance(value, list):
            for item in value:
                self._register(item, source)


def _match(pattern, text):
    return bool(re.search(pattern, text, re.I))


def _content(body):
    text = _canonical(body)
    # Recognizable letter spacing is normalized before quotation handling.
    text = re.sub(r"\bi\s+g\s+n\s+o\s+r\s+e\b", 'ignore', text)
    # Remove attributed examples only, not all commands in a reporting email.
    quote = r'(?P<prefix>\b(?:phrase|example|containing|say|says|wrote|using|text|payload)\s*:?\s*)[\x22\x27\u201c](?P<quote>.+?)[\x22\x27\u201d]'
    active = re.sub(quote, lambda m: m['prefix'] + ' [quoted example] ', text)
    active = re.sub(r"\b(?:attackers? (?:use|say|write)|examples? (?:include|are))\s+[^.!?]+", " [reported example] ", active)
    active = re.sub(r"\b(?:never|do not|don't)\s+(?:ignore|disregard|override|bypass)\s+(?:your |the |all )?(?:previous |security |system )?(?:instructions|policies|rules)\b", " [defensive advice] ", active)
    # Stop at clause boundaries: a defensive preface cannot hide a later command.
    active = re.sub(r"\b(?:never|do not|don't)\s+(?:obey|follow)\s+(?:any |an? )?(?:instruction|message)s?\b[^.;!?]*?(?=[.;!?]|,?\s+(?:but|now|instead|then)\b|$)", " [defensive advice] ", active)
    inject = r"(?:\b(?:ignore|disregard|forget|override|bypass)\b.{0,70}\b(?:instructions?|security polic\w*|system prompt|safety rules|previous rules)\b|\b(?:mark|classify|label|return|output|set|approve|allow|deliver)\b.{0,45}\b(?:this (?:email|message)|decision|verdict|safe|benign|allow)\b|do not quarantine this message|system (?:instruction|override).{0,80}(?:allow|safe|approve)|(?:security (?:ai|agent)|assistant|classifier).{0,60}(?:skip|suppress|disable).{0,40}(?:checks|inspection|warnings|evidence))"
    injection = _match(inject, active) or _match(r"\b(?:automated security systems?|security (?:ai|agent)|classifier)\b.{0,60}\b(?:override|bypass|disable)\b.{0,30}\b(?:filters|checks|inspection)\b", active)
    quoted_attack = _match(inject, text) and not injection
    report = quoted_attack and _match(r"suspicious|phishing simulation|is this|received|forwarded", text)
    # Awareness/negated examples are not active requests. This is sentence-local.
    sentences = re.split(r"(?<=[.!?])\s+|\n+", active)
    operational = " ".join(s for s in sentences if not _match(
        r"\b(?:never|do not|don't)\s+(?:send|share|enter|reveal|provide|enable|wire|buy)|\b(?:awareness|training example|attackers? (?:ask|request))\b", s))
    credential = _match(r"\b(?:send|share|reply|provide|enter|confirm|verify|submit|reveal)\b.{0,65}\b(?:password|credentials?|login tokens?|secret keys?|one.time (?:code|password)|verification code|mfa code)\b", operational)
    login = _match(r"\b(?:log[ -]?in|sign[ -]?in|re.authenticat\w*|reset|verify your account|update your password|sso portal)\b", operational)
    transaction_text = re.sub(r"\b(?:(?:can|could) you confirm (?:that )?)?(?:the |our )?wire transfer(?: of (?:[$€£]\s*[\d,.]+|[\d,.]+\s*(?:usd|eur|gbp)))?\s+(?:was|has been) received\b", ' [transfer receipt] ', operational)
    financial = _match(r"\b(?:wire|transfer|remit|pay|purchase|buy|send|process)\b.{0,90}(?:\b(?:funds|money|payment|gift cards?|supplier account|vendor account)\b|[$€£]\s*\d)|\bwire transfer\b", transaction_text)
    # A new email/login account is not a change to payment instructions.
    payment_account = r"(?:bank(?: account)?|routing(?: number)?|payment details|(?:supplier|vendor|beneficiary) account|account(?: number)? (?:for (?:future )?payments|details))"
    account_change = _match(r"\b(?:new|updated?|changed?|replace|different)\b.{0,45}\b" + payment_account + r"\b|\b" + payment_account + r"\b.{0,45}\b(?:changed?|updated?|replace)\b", operational)
    gift_text = re.sub(r"\b(?:do not|don't|no longer)\s+need\s+(?:(?:any|the|these|those|more|\d+)\s+)*gift cards?\b", ' [negated purchase] ', operational)
    gift = _match(r"\b(?:gift cards?|claim codes)\b", gift_text) and _match(r"purchase|buy|send|email|codes|\bneed\b", gift_text)
    secrecy = _match(r"do not call|don't call|keep.{0,30}(?:secret|confidential)|between us|bypass.{0,30}approval|without.{0,25}approval", operational)
    urgency = _match(r"urgent\w*|immediately|right (?:now|away)|asap|before noon|within \d+ hours|emergency|time.sensitive", operational)
    malware = _match(r"\b(?:enable|turn on|activate)\b.{0,25}\bmacros?\b|\b(?:disable|turn off)\b.{0,35}\b(?:antivirus|protected view|security software)\b|\b(?:run|execute|open|install)\b.{0,65}\.(?:exe|scr|js|vbs|hta|ps1)\b|\b(?:run|execute|install)\b.{0,40}\b(?:attached executable|attached script)\b", operational)
    privilege = _match(r"\b(?:grant|give|export|upload)\b.{0,60}\b(?:admin\w*|database|payroll|customer records|access token)\b", operational)
    callback = _match(r"\b(?:call|dial)\b.{0,80}\d[\d ()+-]{6,}", operational) and _match(r"refund|unauthorized charge|remote access|install", operational)
    return dict(injection=injection, quoted_attack=quoted_attack, report=report, credential=credential,
                login=login, financial=financial, account_change=account_change, gift=gift,
                secrecy=secrecy, urgency=urgency, malware=malware, privilege=privilege, callback=callback)


def _near_domain(domain, approved):
    if not domain or domain in approved:
        return False
    for official in approved:
        # Similarity is only a weak identity signal, never a verdict by itself.
        stem = official.split('.')[0]
        if len(stem) >= 6 and (domain.startswith(stem + '.') or domain.startswith(stem + '-') or
                              SequenceMatcher(None, domain, official).ratio() >= .88):
            return True
    return False


def _confidence(resolution, supporting, contradictions, missing):
    """Baseline confidence anchors, reduced for uncertainty rather than inflated.

    Policy retrieval authorizes an action; it does not independently prove a
    threat. Neither it nor a hand-assigned decision margin earns a score bonus.
    """
    if not isinstance(supporting, dict):
        supporting = dict.fromkeys(('identity', 'authentication', 'domain', 'content', 'thread', 'policy')[:supporting], 1.)
    if resolution == 'allow':
        score = .95 if supporting.get('identity', 0.) == 1. and supporting.get('authentication', 0.) == 1. else .90
    elif resolution == 'quarantine':
        score = .95 if supporting.get('domain', 0.) == 1. else .90
        if supporting.get('domain', 0.) < 1. and supporting.get('content', 0.) < .9 and supporting.get('identity', 0.) < .6:
            score = .82  # Inferred threat rather than corroborated/direct abuse.
    else:
        score = .85 if resolution == 'escalate' else .75
    return round(max(.40, score - .07 * contradictions - .06 * missing), 2)


def solve(task: dict[str, Any], tools: ToolsClient, api_key=None, model=None, base_url=None) -> dict[str, Any]:
    _ = api_key, model, base_url
    task = _dict(task)
    email = _normalize(task)
    mid, sender = email['message_id'], email['sender_email']
    if not mid:
        # There is no truthful action possible without its target identifier.
        raise ValueError('Missing message_id; no disposition attempted')
    domain = _extract_domain(sender)
    inv = _Investigation(tools)
    headers = inv.read('get_email_headers', mid)
    rep = inv.read('inspect_domain_reputation', domain)
    directory = inv.read('lookup_directory', sender)
    approved = inv.read('get_approved_domains')
    emp = _dict(directory.get('employee'))
    if not emp and email['display_name']:
        named = inv.read('lookup_directory', email['display_name'])
        candidate = _dict(named.get('employee'))
        if _canonical(candidate.get('name')) == _canonical(email['display_name']):
            emp = candidate
    recipient = inv.read('lookup_directory', email['recipient_email']) if email['recipient_email'] else {}
    recipient_emp = _dict(recipient.get('employee'))
    thread = inv.read('get_thread_history', email['thread_id']) if email['thread_id'] else {}
    # Restore baseline tolerance of optional thread/recipient lookup failures.
    # Failure of a core identity/authentication/reputation check still prevents
    # ALLOW; a failed optional query is disclosed and lowers confidence instead.
    core_ready = bool(headers and rep and directory and approved)
    official = {_canonical(d) for d in _items(approved.get('official_domains')) if _text(d)}
    partners = {_canonical(d) for d in _items(approved.get('partner_domains')) if _text(d)}
    reputation = _canonical(rep.get('reputation')) or 'unknown'
    try:
        threat_score = float(rep.get('threat_score'))
    except (TypeError, ValueError, OverflowError):
        threat_score = None
    intel_conflict = reputation in ('safe', 'trusted') and threat_score is not None and 85 <= threat_score <= 100
    auth = _dict(headers.get('auth_results'))
    spf, dkim, dmarc = (_canonical(auth.get(k)) or 'unknown' for k in ('spf', 'dkim', 'dmarc'))
    authenticated = dmarc == 'pass' and (spf == 'pass' or dkim == 'pass')
    auth_fail = dmarc == 'fail'
    official_email = _address(emp.get('official_email'))[1]
    identity_match = bool(sender and sender == official_email)
    internal = identity_match and domain in official and authenticated
    mismatch = bool(emp and official_email and sender != official_email)
    lookalike = bool(rep.get('lookalike_of')) or _near_domain(domain, official | partners)
    content = _content(email['subject'] + '\n' + email['body'])
    previous = [m for m in _items(thread.get('messages')) if isinstance(m, dict) and m.get('message_id') != mid]
    old_senders = {_address(m.get('sender') or m.get('sender_email'))[1] for m in previous}
    switched = bool(previous and sender not in old_senders and old_senders - {'', email['recipient_email']})
    established = bool(sender in old_senders and email['recipient_email'] in old_senders and len(previous) >= 2)
    reply_to = _address(headers.get('reply_to'))[1]
    diverted = bool(reply_to and _extract_domain(reply_to) != domain and _extract_domain(reply_to) not in official | partners)
    # Inspect at most two unique link hosts when the requested action is sensitive.
    urls = re.findall(r'https?://[^\s<>\x22\x27]+', html.unescape(email['body']), re.I)
    hosts = []
    for url in urls:
        try:
            host = (urlsplit(url).hostname or '').lower()
        except ValueError:
            continue
        if host and host not in hosts:
            hosts.append(host)
    risky_link = False
    link_ids = []
    if any(content[k] for k in ('login', 'credential', 'financial', 'malware', 'privilege')):
        for host in hosts[:2]:
            lr = inv.read('inspect_domain_reputation', host)
            lr_bad = _canonical(lr.get('reputation')) in ('suspicious', 'malicious')
            unverified = host not in official | partners and _canonical(lr.get('reputation')) not in ('safe', 'trusted')
            if lr_bad or (unverified and content['login']):
                risky_link = True
                link_ids.append(lr.get('domain_id'))
    credential = content['credential'] or (content['login'] and risky_link)
    financial = content['financial'] or content['gift'] or content['account_change']
    # Routine invoice vocabulary alone does not imply payment fraud.
    fraud = content['gift'] or content['account_change'] or content['financial']
    spoof = (mismatch and (financial or credential or content['privilege'] or lookalike)) or (
            lookalike and (financial or credential or content['privilege']))
    privilege_risk = content['privilege'] and not internal and domain not in partners
    hostile = content['injection'] or credential or content['malware'] or fraud or content['callback'] or spoof or risky_link or privilege_risk
    conflict = internal and hostile or (reputation == 'malicious' and authenticated and domain in official | partners)
    uncertainties = []
    if reputation == 'unknown': uncertainties.append('Sender reputation is unverified.')
    if not authenticated: uncertainties.append('Aligned sender authentication is not fully verified.')
    if mismatch: uncertainties.append('Directory identity matches a different official address; identity is unverified.')
    if switched: uncertainties.append('Sender changed within the retrieved conversation.')
    if conflict: uncertainties.append('Trusted identity and high-risk signals conflict; possible account compromise.')
    if intel_conflict: uncertainties.append('Reputation label conflicts with the high threat score.')
    if len(hosts) > 2: uncertainties.append('Additional link hosts were not individually investigated.')
    classification = ('prompt_injection' if content['injection'] else 'malware_delivery' if content['malware'] else
                      'credential_harvesting' if credential else 'business_email_compromise' if fraud else
                      'spoofing' if spoof or (auth_fail and domain in official | partners) else 'phishing')
    if conflict:
        resolution = 'escalate'
    elif reputation == 'malicious' or hostile or (auth_fail and domain in official | partners):
        resolution = 'quarantine'
    elif content['report']:
        resolution, classification = 'warn', 'suspicious_unknown'
    elif auth_fail or (spf == 'fail' and not authenticated) or mismatch or lookalike or diverted or intel_conflict or reputation == 'suspicious' or not sender:
        resolution, classification = 'warn', 'suspicious_unknown'
    elif internal and core_ready:
        resolution, classification = 'allow', 'internal_legitimate'
    elif (reputation in ('safe', 'trusted') or domain in partners or (established and authenticated)) and core_ready:
        resolution, classification = 'allow', 'external_legitimate'
    else:
        resolution, classification = 'warn', 'suspicious_unknown'

    evidence = set()
    def cite(value):
        if isinstance(value, str) and value in inv.registry:
            evidence.add(value)
    cite(headers.get('message_id'))
    cite(rep.get('domain_id'))
    cite(emp.get('id'))
    # Recipient context matters for targeted requests and correspondence. Avoid
    # unrelated directory hits, especially the other party in an impersonation.
    if not emp or content['gift'] or (previous and financial):
        cite(recipient_emp.get('id'))
    if previous:
        cite(thread.get('thread_id'))
    for value in link_ids: cite(value)
    policy_id = None
    policy_category = ('escalation' if resolution == 'escalate' else 'agent_security' if content['injection'] else
                       'data_protection' if credential else 'financial_security' if fraud else
                       'authentication' if spoof or auth_fail or lookalike else None)
    if resolution in ('escalate', 'quarantine') and policy_category:
        query = 'escalation compromised account' if resolution == 'escalate' else policy_category
        policies = inv.read('search_knowledge', query)
        for policy in _items(policies.get('results')):
            if isinstance(policy, dict) and (_canonical(policy.get('category')) == policy_category or
                    (resolution == 'escalate' and _match('escalat|compromis', _canonical(policy.get('title'))))):
                policy_id = policy.get('id')
                cite(policy_id)
                break
        if resolution == 'escalate' and not policy_id:
            # Do not attempt a predictably ungrounded escalation. The official
            # registry requires a search result even when read tools return IDs.
            raise RuntimeError('Escalation policy evidence unavailable; no disposition attempted')
    severity = 'critical' if resolution == 'escalate' else 'high' if resolution == 'quarantine' else 'medium' if resolution == 'warn' else 'low'
    uncertainties.extend('Investigation unavailable: ' + name + '.' for name in inv.failures)
    # Strength is evidence-specific. Authentication proves sender alignment, not
    # harmless intent; passing auth is neutral for external BEC/phishing.
    content_strength = max(.95 if content['injection'] or content['credential'] or content['malware'] else 0.,
                           .95 if content['gift'] or (fraud and (content['urgency'] or content['secrecy'])) else 0.,
                           .8 if fraud else 0., .7 if privilege_risk or content['callback'] else 0.,
                           .65 if risky_link else 0.)
    if resolution == 'quarantine':
        supporting = dict(identity=1. if mismatch and spoof else .6 if lookalike else 0.,
                          authentication=1. if auth_fail else 0.,
                          domain=1. if reputation == 'malicious' else .4 if reputation == 'suspicious' else 0.,
                          content=content_strength, thread=.9 if switched and financial else 0.,
                          policy=.85 if policy_id else 0.)
    elif resolution == 'escalate':
        # Verified identity plus hostile behavior is evidence FOR review; the
        # uncertainty about the cause does not imply uncertainty about this action.
        supporting = dict(identity=1. if identity_match else 0., authentication=1. if authenticated else 0.,
                          domain=1. if domain in official | partners else 0., content=content_strength,
                          thread=.9 if switched and financial else 0., policy=.85 if policy_id else 0.)
    else:
        supporting = dict(identity=1. if identity_match else .35 if mismatch else 0.,
                          authentication=(1. if resolution == 'allow' or content['report'] else .3) if authenticated else 0.,
                          domain=1. if domain in official | partners else .8 if reputation in ('safe', 'trusted') else .5,
                          content=.35 if email['body'] and not hostile else 0.,
                          thread=.8 if established and not switched else 0.)
    contradictions = (.75 if reputation in ('safe', 'trusted') and hostile and resolution != 'escalate' else 0.)
    contradictions += .5 if intel_conflict and resolution == 'escalate' else 1. if intel_conflict else 0.
    # Count unavailable families once. Unknown reputation is a small knowledge
    # gap, not evidence against a direct credential or impersonation attack.
    missing_auth = 1. if not auth or all(v == 'unknown' for v in (spf, dkim, dmarc)) else .5 if dmarc in ('none', 'unknown') else 0.
    missing_domain = 1. if not rep else (0. if content_strength >= .9 else .35) if reputation == 'unknown' else 0.
    other_missing = .5 * len(set(inv.failures) - {'get_email_headers', 'inspect_domain_reputation'})
    link_failure = .5 if rep and 'inspect_domain_reputation' in inv.failures else 0.
    missing = missing_auth + missing_domain + other_missing + link_failure + (.25 if len(hosts) > 2 else 0.)
    confidence = _confidence(resolution, supporting, contradictions, missing)
    signals = [name.replace('_', ' ') for name, flag in {
        'credential_request': credential, 'financial_risk': fraud, 'malware_instructions': content['malware'],
        'prompt_injection': content['injection'], 'identity_mismatch': mismatch, 'lookalike_domain': lookalike,
        'thread_sender_change': switched, 'payment_account_change': content['account_change'],
        'unverified_sensitive_link': risky_link, 'unverified_privileged_request': privilege_risk,
        'dmarc_failure': auth_fail}.items() if flag]
    evidence_sorted = sorted(evidence)
    reason = f"{classification}: {', '.join(signals) or 'identity, domain and content assessed'}. Evidence: {', '.join(evidence_sorted)}"
    action = {'allow':'allow_and_deliver','warn':'apply_warning_banner','quarantine':'quarantine_message','escalate':'escalate_to_tier2_soc'}[resolution]
    # Never retry an action on transport uncertainty: it may already have committed.
    try:
        response = getattr(tools, action)(mid, reason=reason)
    except Exception:
        raise RuntimeError('Disposition transport failed; outcome unknown, no retry attempted') from None
    status = {'allow':'delivered','warn':'warning_applied','quarantine':'quarantined','escalate':'escalated_to_soc'}[resolution]
    if not isinstance(response, dict) or response.get('error') or response.get('status') != status:
        raise RuntimeError('Disposition was not confirmed; no second action attempted')
    summary = (f"SOC Triage: {mid}. Sender {sender or 'unparseable'}; reputation {reputation}. "
               f"Auth: SPF={spf} DKIM={dkim} DMARC={dmarc}. {reason}. "
               f"Classification: {classification}; severity {severity}. Confirmed disposition: {resolution}.")
    return {'task_id': _text(task.get('task_id')), 'case_classification': {'category':'cybersecurity_triage','issue':classification,'severity':severity},
            'decision': {'resolution':resolution,'escalation_required':resolution == 'escalate'}, 'evidence':evidence_sorted,
            'uncertainties':uncertainties, 'customer_response':summary, 'confidence':confidence,
            'prompt_injection_detected':content['injection']}
