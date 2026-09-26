"""GRC (Governance, Risk & Compliance) module — Indian legal & regulatory mapping.

Maps the technical evidence of an e-mail to the provisions it likely
violates (acts by the sender) and to the obligations it triggers for the
receiving organisation (reporting, breach notification, control gaps).

IMPORTANT: this is an indicative, evidence-linked mapping to support legal
review and incident reporting. It is not a legal opinion; every item lists
the exact evidence that triggered it so counsel can verify.
"""
from __future__ import annotations

import re
from typing import Dict, List

GOV_ENTITIES = r"(income ?tax|it department|uidai|aadhaar|epfo|provident fund|gst(n| council)?|customs|cbi|enforcement directorate|\bed\b notice|narcotics|ncb|cyber ?(crime|cell|police)|police|high court|supreme court|ministry|government of india|govt\.? of india|meity|cert-in|rbi|reserve bank|sebi|trai|dot\b|department of telecommunications|passport seva|election commission|nic\b|digilocker|india post|pm kisan|parivahan|rto)"
GOV_DOMAIN_OK = (".gov.in", ".nic.in", ".gov", "rbi.org.in", "sebi.gov.in", "cert-in.org.in", "uidai.gov.in", "incometax.gov.in", "indiapost.gov.in")
BANKS = r"(state bank|\bsbi\b|hdfc|icici|axis bank|kotak|punjab national|\bpnb\b|bank of baroda|canara|union bank|yes bank|indusind|idfc|paytm|phonepe|google pay|bhim|\bupi\b|npci)"
BANK_DOMAINS = ("sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "hdfcbank.net", "icicibank.com", "axisbank.com", "kotak.com", "pnb.co.in",
                "bankofbaroda.in", "bankofbaroda.com", "canarabank.com", "unionbankofindia.co.in", "yesbank.in", "indusind.com",
                "idfcfirstbank.com", "paytm.com", "phonepe.com", "npci.org.in", "google.com")
PII = r"(\bkyc\b|aadhaa?r( number| no\.?| card)?|\bpan( card| number)?\b|\botp\b|one[- ]time password|\bcvv\b|card number|debit card|credit card|atm pin|upi pin|\bmpin\b|net ?banking (password|credentials)|bank account (number|details)|ifsc|date of birth|passport number|voter id|biometric)"
INVEST = r"(guaranteed (returns|profit)|double your (money|investment)|stock tips?|crypto (investment|trading) (plan|scheme)|forex|ipo allotment|trading group|multibagger|\d+% (daily|weekly|monthly) returns?)"


def _has(rx: str, text: str) -> str:
    m = re.search(rx, text or "", re.I)
    return m.group(0) if m else ""


def _item(rule_id, framework, provision, title, kind, severity, description, evidence, actions):
    return {"rule_id": rule_id, "framework": framework, "provision": provision, "title": title, "type": kind,
            "severity": severity, "description": description, "evidence": [e for e in evidence if e][:6], "actions": actions}


def evaluate_grc(sig: Dict) -> dict:
    """`sig` is the flat signal dict built by the pipeline (see pipeline._signals)."""
    text = " ".join([sig.get("subject", ""), sig.get("display_name", ""), sig.get("body", "")])
    sender_dom = (sig.get("sender_domain") or "").lower()
    it = set(sig.get("indicator_types") or [])
    spoofed = bool(sig.get("auth_fail") or sig.get("lookalikes") or sig.get("reply_to_mismatch"))
    cred = bool(it & {"credential_harvesting", "credential_request", "account_verification", "password_reset_pressure", "phishing_social_engineering"}) \
        or sig.get("sandbox_cred_form")
    fin = bool(it & {"payment_fraud", "payment_request", "invoice_payment_diversion"})
    exec_imp = "executive_impersonation" in it
    extortion = bool(it & {"blackmail_extortion", "explicit_threat", "fear_threat", "harassment_intimidation"})
    malware = sig.get("sandbox_verdict") == "MALICIOUS" and bool(sig.get("sandbox_malicious_files"))
    gov_claim = _has(GOV_ENTITIES, text)
    gov_imp = bool(gov_claim) and not sender_dom.endswith(GOV_DOMAIN_OK) and (spoofed or cred or fin or sig.get("risky"))
    bank_claim = _has(BANKS, text)
    bank_imp = bool(bank_claim) and not any(sender_dom == d or sender_dom.endswith("." + d) for d in BANK_DOMAINS) and (cred or fin or spoofed)
    pii = _has(PII, text)
    invest = _has(INVEST, text)
    risky = sig.get("risky", False)
    items: List[dict] = []
    ev_spoof = [sig.get("auth_summary"), ("Look-alike: " + ", ".join(sig["lookalikes"])) if sig.get("lookalikes") else "",
                "From/Reply-To mismatch" if sig.get("reply_to_mismatch") else ""]

    if cred and (spoofed or risky):
        items.append(_item("GRC-ITA-66C", "Information Technology Act, 2000", "Section 66C",
                           "Identity theft — fraudulent use of password / unique identification", "VIOLATION", "HIGH",
                           "The e-mail attempts to obtain passwords/credentials or other unique identification features of the recipient by deception.",
                           [sig.get("indicator_evidence", {}).get("credential_harvesting"), sig.get("sandbox_cred_form")] + ev_spoof,
                           ["Preserve the e-mail + ledger anchor as electronic evidence (Sec. 65B Indian Evidence Act / Sec. 63 BSA 2023).",
                            "Reset any credential that may have been entered; enforce MFA."]))
    if (spoofed or exec_imp or gov_imp or bank_imp) and (cred or fin or risky):
        items.append(_item("GRC-ITA-66D", "Information Technology Act, 2000", "Section 66D",
                           "Cheating by personation using a computer resource", "VIOLATION", "HIGH",
                           "The sender personates another person/organisation through a spoofed, look-alike or mismatched identity to deceive the recipient.",
                           ev_spoof + [f"Claims to be: {gov_claim or bank_claim}" if (gov_imp or bank_imp) else "",
                                       "Executive impersonation language" if exec_imp else ""],
                           ["Report on the National Cyber Crime Reporting Portal (cybercrime.gov.in) / helpline 1930.",
                            "Block sender domain and infrastructure at the gateway."]))
    if malware:
        items.append(_item("GRC-ITA-43", "Information Technology Act, 2000", "Sections 43(c) & 66",
                           "Introduction of computer contaminant / virus", "VIOLATION", "CRITICAL",
                           "The e-mail delivers a file the isolated sandbox classified as malicious (computer contaminant).",
                           [f"{f}" for f in sig.get("sandbox_malicious_files", [])[:4]],
                           ["Block file hashes on all endpoints (EDR) and mail gateway.", "Hunt for the hash across mailboxes."]))
    if fin or (exec_imp and risky):
        items.append(_item("GRC-BNS-318", "Bharatiya Nyaya Sanhita, 2023", "Section 318 (cheating) / 319 (cheating by personation)",
                           "Cheating and dishonest inducement to deliver property", "VIOLATION", "HIGH",
                           "Payment-diversion / invoice / urgent-transfer request designed to induce delivery of money.",
                           [sig.get("indicator_evidence", {}).get(k) for k in ("payment_fraud", "invoice_payment_diversion", "payment_request")] + ev_spoof,
                           ["Verify any payment request out-of-band before release.",
                            "If money was transferred, report within the 'golden hour' to 1930 so the bank can freeze funds."]))
    if spoofed and (sig.get("header_forgery") or sig.get("auth_fail")):
        items.append(_item("GRC-BNS-336", "Bharatiya Nyaya Sanhita, 2023", "Sections 336 & 340",
                           "Forgery of electronic record / using forged electronic record as genuine", "VIOLATION", "MEDIUM",
                           "Header fields and sender identity were forged so the message appears to come from a party that did not send it.",
                           ev_spoof + list(sig.get("header_forgery") or [])[:3],
                           ["Retain full headers and the SHA-256 evidence hash for prosecution."]))
    if extortion:
        items.append(_item("GRC-BNS-308", "Bharatiya Nyaya Sanhita, 2023", "Section 308 (extortion) / 351 (criminal intimidation)",
                           "Extortion / criminal intimidation", "VIOLATION", "HIGH",
                           "The e-mail threatens harm, exposure or legal action to coerce the recipient.",
                           [sig.get("indicator_evidence", {}).get(k) for k in ("blackmail_extortion", "explicit_threat", "fear_threat")],
                           ["Do not pay or reply; escalate to cyber police with the preserved evidence."]))
    if gov_imp:
        items.append(_item("GRC-GOI-EMAIL", "Government of India E-mail Policy (MeitY, 2015)", "Official communication via gov.in / nic.in",
                           "Impersonation of a Government authority", "VIOLATION", "CRITICAL",
                           f"The message claims to be from '{gov_claim}' but was sent from '{sender_dom or 'unknown'}', not an official "
                           "gov.in / nic.in domain. Government notices must originate from NIC-managed domains.",
                           [f"Claimed authority: {gov_claim}", f"Actual sender domain: {sender_dom}"] + ev_spoof,
                           ["Warn users; report to CERT-In (incident@cert-in.org.in) and the impersonated department."]))
    if bank_imp:
        items.append(_item("GRC-RBI-FRAUD", "RBI Master Direction on Digital Payment Security Controls (2021) & RBI customer-liability circular (2017)",
                           "Bank / payment-system impersonation", "Banking & UPI impersonation fraud", "VIOLATION", "HIGH",
                           f"Uses the identity of '{bank_claim}' from a non-bank domain to obtain credentials or payments.",
                           [f"Claimed institution: {bank_claim}", f"Sender domain: {sender_dom}"],
                           ["Report to the impersonated bank's fraud desk and 1930; customers' liability is limited if reported within 3 working days."]))
    if invest:
        items.append(_item("GRC-SEBI-IA", "SEBI (Investment Advisers) Regulations, 2013", "Unregistered investment advice / assured returns",
                           "Investment-scam solicitation", "VIOLATION", "MEDIUM",
                           "Promises assured or abnormal returns — typical of unregistered advisory / trading-group frauds.",
                           [invest], ["Verify SEBI registration; report on SEBI SCORES / cybercrime portal."]))
    if pii and (risky or spoofed):
        items.append(_item("GRC-DPDP-2023", "Digital Personal Data Protection Act, 2023", "Sections 4, 6 & 8(6)",
                           "Unlawful collection of personal data by deception", "VIOLATION", "HIGH",
                           "Solicits personal data without a lawful purpose or valid consent (consent obtained by deception is not valid). "
                           "If any recipient supplied data, the Data Fiduciary must notify the Data Protection Board and affected Data Principals.",
                           [f"Requested data: {pii}"],
                           ["Check whether any user responded; if yes, trigger the personal-data-breach notification workflow."]))
    if risky and (cred or fin or malware or spoofed or gov_imp or bank_imp):
        items.append(_item("GRC-CERTIN-2022", "CERT-In Directions No. 20(3)/2022-CERT-In (28 Apr 2022)", "Para (ii) — 6-hour incident reporting",
                           "Reportable cyber-security incident", "OBLIGATION", "HIGH",
                           "Phishing, identity theft, spoofing and malicious-code attacks are reportable incident types. Service providers, "
                           "intermediaries, data centres, body corporates and Government organisations must report to CERT-In within 6 hours of noticing.",
                           [f"Incident type: {', '.join(k for k, v in (('phishing', cred), ('spoofing', spoofed), ('malicious code', malware), ('financial fraud', fin)) if v)}"],
                           ["File the CERT-In incident report (incident@cert-in.org.in) within 6 hours.",
                            "Retain logs for 180 days within Indian jurisdiction as required by the same Directions."]))
    if sig.get("sender_no_dmarc") or sig.get("dmarc_policy_weak"):
        items.append(_item("GRC-CTRL-EMAILAUTH", "CERT-In e-mail security advisories / ISO/IEC 27001:2022 A.5.14 & A.8.21",
                           "Sender domain e-mail authentication", "Sender domain lacks DMARC enforcement", "CONTROL_GAP", "MEDIUM",
                           "Without SPF/DKIM/DMARC with p=quarantine|reject a domain can be spoofed freely.",
                           [sig.get("auth_summary")], ["Owner of the domain should publish DMARC p=reject; receivers should enforce it."]))
    if sig.get("delivered_despite_fail"):
        items.append(_item("GRC-CTRL-GATEWAY", "ISO/IEC 27001:2022 A.8.7 (protection against malware) & A.8.23",
                           "Receiving mail gateway", "Gateway delivered a message that failed authentication", "CONTROL_GAP", "MEDIUM",
                           "The message reached the mailbox even though SPF/DKIM/DMARC failed — inbound policy is not enforcing authentication results.",
                           [sig.get("auth_summary")], ["Enforce DMARC results inbound; quarantine auth-failed mail from external senders."]))

    viol = [i for i in items if i["type"] == "VIOLATION"]
    obl = [i for i in items if i["type"] == "OBLIGATION"]
    status = "NON_COMPLIANT_THREAT" if viol else ("REPORTABLE" if obl else ("CONTROL_GAPS" if items else "NO_VIOLATION_FOUND"))
    return {
        "status": status,
        "violations": len(viol),
        "obligations": len(obl),
        "control_gaps": len([i for i in items if i["type"] == "CONTROL_GAP"]),
        "items": items,
        "reporting_channels": [
            {"name": "National Cyber Crime Reporting Portal", "contact": "https://cybercrime.gov.in", "when": "Any fraud / impersonation"},
            {"name": "Cyber fraud helpline", "contact": "1930", "when": "Financial loss — call immediately"},
            {"name": "CERT-In incident reporting", "contact": "incident@cert-in.org.in", "when": "Within 6 hours of noticing"},
        ] if items else [],
        "disclaimer": "Indicative, evidence-linked mapping to support legal/compliance review. Not legal advice; "
                      "final determination rests with the organisation's legal counsel and competent authorities.",
    }
