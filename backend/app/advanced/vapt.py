"""VAPT-style assessment of a single e-mail attack.

Answers the three questions an assessor asks after a phishing attempt:
  1. What was the attacker trying to achieve?        -> intent (with confidence + evidence)
  2. How did the attack progress / what would it do? -> kill-chain + MITRE ATT&CK path
  3. Which weakness did it exploit, and where?       -> weaknesses located in sender DNS,
                                                        the receiving gateway, endpoints,
                                                        identity controls or people,
                                                        each with a risk rating + fix.
Derived purely from evidence already collected (forensics, ML, sandbox,
AI-security, GRC) — no active scanning of third-party systems is performed.
"""
from __future__ import annotations

from typing import Dict, List

LIKELIHOOD = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _risk(likelihood: str, impact: str) -> dict:
    s = LIKELIHOOD[likelihood] * LIKELIHOOD[impact]
    rating = "CRITICAL" if s >= 12 else "HIGH" if s >= 8 else "MEDIUM" if s >= 4 else "LOW"
    return {"likelihood": likelihood, "impact": impact, "score": s, "rating": rating}


def assess_vapt(sig: Dict, sandbox: Dict | None, ai_sec: Dict | None) -> dict:
    it = set(sig.get("indicator_types") or [])
    sb = sandbox or {}
    sb_mitre = set(sb.get("mitre_techniques") or [])
    sb_files = sb.get("files") or []
    risky_files = [f for f in sb_files if f.get("verdict") != "SAFE"]
    bad_urls = [u for u in (sb.get("urls") or []) if u.get("verdict") != "SAFE"]
    cred_form = bool(sig.get("sandbox_cred_form"))

    intents: List[dict] = []

    def add_intent(key, label, conf, evidence, objective):
        intents.append({"intent": key, "label": label, "confidence": round(min(0.99, conf), 2),
                        "evidence": [e for e in evidence if e][:5], "attacker_objective": objective})

    cred_sig = it & {"credential_harvesting", "credential_request", "account_verification", "password_reset_pressure", "phishing_social_engineering"}
    if cred_sig or cred_form or any("login" in (u.get("url") or "").lower() for u in bad_urls):
        add_intent("CREDENTIAL_THEFT", "Steal login credentials / account takeover",
                   0.55 + 0.15 * len(cred_sig) + (0.25 if cred_form else 0) + (0.1 if bad_urls else 0),
                   [f"indicator: {t}" for t in cred_sig] + (["sandbox: credential-harvest form"] if cred_form else [])
                   + [f"suspicious link: {u['url'][:80]}" for u in bad_urls[:2]],
                   "Obtain the victim's password/OTP to take over mailbox, bank or cloud accounts.")
    fin_sig = it & {"payment_fraud", "payment_request", "invoice_payment_diversion"}
    if fin_sig:
        add_intent("FINANCIAL_FRAUD", "Financial fraud / Business E-mail Compromise", 0.6 + 0.15 * len(fin_sig)
                   + (0.15 if "executive_impersonation" in it else 0),
                   [f"indicator: {t}" for t in fin_sig] + (["executive impersonation"] if "executive_impersonation" in it else []),
                   "Divert a payment or induce a transfer to an attacker-controlled account.")
    if risky_files or any(t.startswith(("T1204", "T1059", "T1105")) for t in sb_mitre):
        mal = [f for f in risky_files if f.get("verdict") == "MALICIOUS"]
        add_intent("MALWARE_DELIVERY", "Deliver malware / gain initial access", 0.6 + (0.3 if mal else 0.1),
                   [f"{f['filename']} → {f['verdict']} ({f['detected_type']})" for f in risky_files[:3]],
                   "Execute code on the endpoint to install a loader, RAT, info-stealer or ransomware.")
    if sig.get("pii_requested"):
        add_intent("DATA_HARVESTING", "Harvest personal / KYC data", 0.6,
                   [f"requests: {sig['pii_requested']}"], "Collect Aadhaar/PAN/card/OTP data for identity fraud.")
    if it & {"blackmail_extortion", "explicit_threat", "harassment_intimidation"}:
        add_intent("EXTORTION", "Extortion / intimidation", 0.75, [f"indicator: {t}" for t in it & {"blackmail_extortion", "explicit_threat"}],
                   "Coerce payment or action through threats.")
    if sig.get("gov_or_brand_claim") and (sig.get("auth_fail") or sig.get("lookalikes")):
        add_intent("IMPERSONATION", "Brand / authority impersonation", 0.7,
                   [f"claims: {sig['gov_or_brand_claim']}"] + (["look-alike: " + ", ".join(sig["lookalikes"])] if sig.get("lookalikes") else []),
                   "Borrow the trust of a bank/government/brand to make the lure believable.")
    if (ai_sec or {}).get("verdict") in ("MANIPULATION_DETECTED", "SUSPICIOUS"):
        add_intent("AI_EVASION", "Evade / manipulate AI defences", 0.5 + (ai_sec.get("score", 0) / 200),
                   [f["title"] for f in ai_sec.get("findings", [])[:3]], "Slip past ML filters or hijack AI mail assistants.")
    if not intents and sig.get("risky"):
        add_intent("RECONNAISSANCE", "Reconnaissance / list validation", 0.4,
                   ["suspicious but payload-free message"], "Confirm the mailbox is live and the user responsive before a targeted attack.")
    if "spam_bulk" in it and not intents:
        add_intent("SPAM", "Unsolicited bulk / marketing", 0.5, ["bulk-mail indicators"], "Advertising; low direct harm.")
    intents.sort(key=lambda x: x["confidence"], reverse=True)
    primary = intents[0] if intents else {"intent": "NONE", "label": "No malicious intent identified", "confidence": 0.0,
                                          "evidence": [], "attacker_objective": "—"}

    # ── kill chain ───────────────────────────────────────────────────────────
    kc = []

    def stage(name, observed, evidence, tech=None):
        kc.append({"stage": name, "observed": observed, "evidence": evidence, "mitre": tech})

    stage("Reconnaissance", bool(sig.get("gov_or_brand_claim") or "executive_impersonation" in it),
          "Attacker researched a trusted identity to impersonate" if sig.get("gov_or_brand_claim") else "Not evident", "T1589 / T1593")
    weap = (["look-alike domain " + ", ".join(sig["lookalikes"])] if sig.get("lookalikes") else []) \
        + [f"weaponised file {f['filename']}" for f in risky_files[:2]] + [f"malicious link {u['url'][:60]}" for u in bad_urls[:1]]
    stage("Weaponization", bool(weap), "; ".join(weap) or "Not evident", "T1583.001 / T1587")
    stage("Delivery", bool(sig.get("risky")), "Phishing e-mail delivered" + (" with attachment" if sb_files else "")
          + (" with link" if sig.get("url_count") else ""),
          "T1566.001" if sb_files else ("T1566.002" if sig.get("url_count") else "T1566"))
    stage("Exploitation", bool(risky_files or cred_form or it & {"urgency", "fear_threat"}),
          ("Human exploitation: " + ", ".join(sorted(it & {"urgency", "fear_threat", "executive_impersonation", "suspicious_call_to_action"})))
          if it & {"urgency", "fear_threat", "executive_impersonation", "suspicious_call_to_action"} else
          ("Technical: " + ", ".join(sorted(sb_mitre))[:120] if sb_mitre else "Not evident"), "T1204")
    stage("Installation", any(t.startswith(("T1547", "T1105", "T1053")) for t in sb_mitre),
          "Payload downloads / persists (sandbox-predicted)" if sb_mitre & {"T1105", "T1547.001"} else "Not evident", "T1105 / T1547")
    stage("Command & Control", any(t.startswith(("T1567", "T1071")) for t in sb_mitre) or bool(sig.get("c2_hint")),
          "Exfiltration channel found in artefact" if "T1567" in sb_mitre else "Not evident", "T1071 / T1567")
    stage("Actions on Objectives", bool(intents and intents[0]["intent"] not in ("SPAM", "RECONNAISSANCE")),
          primary["attacker_objective"], None)

    techniques = sorted(set(sb_mitre) | {k["mitre"] for k in kc if k["observed"] and k["mitre"]} |
                        ({"T1656"} if sig.get("gov_or_brand_claim") or "executive_impersonation" in it else set()) |
                        ({"T1598.003"} if cred_sig else set()))

    # ── weaknesses (where) ───────────────────────────────────────────────────
    weak: List[dict] = []

    def wk(wid, location, title, desc, evidence, fix, likelihood, impact, owner):
        weak.append({"id": wid, "location": location, "title": title, "description": desc,
                     "evidence": [e for e in evidence if e][:4], "remediation": fix, "owner": owner, **_risk(likelihood, impact)})

    if sig.get("auth_fail") or sig.get("sender_no_dmarc"):
        wk("VULN-EMAIL-AUTH", "Sender domain DNS (SPF / DKIM / DMARC)", "Spoofable sender identity",
           "Authentication did not prove the sender; the domain either lacks DMARC enforcement or the message failed SPF/DKIM.",
           [sig.get("auth_summary")], "Publish SPF (-all), sign with DKIM, deploy DMARC p=reject with rua reporting.",
           "HIGH", "HIGH", "Domain owner / sender")
    if sig.get("delivered_despite_fail"):
        wk("VULN-GATEWAY-DMARC", "Receiving mail gateway", "Authentication results not enforced inbound",
           "A message that failed SPF/DKIM/DMARC still reached the inbox.", [sig.get("auth_summary")],
           "Enforce DMARC reject/quarantine for external mail; add an external-sender warning banner.", "HIGH", "HIGH", "Your mail admin")
    if sig.get("lookalikes"):
        wk("VULN-BRAND-LOOKALIKE", "Brand / domain portfolio", "Look-alike domain not monitored or taken down",
           "Attacker registered a domain visually similar to a trusted one.", ["Look-alike: " + ", ".join(sig["lookalikes"])],
           "Monitor new registrations (typosquat feeds), pre-register common variants, request takedown.", "MEDIUM", "HIGH", "Brand owner")
    if sig.get("reply_to_mismatch"):
        wk("VULN-REPLYTO", "Mail client / user interface", "Hidden Reply-To redirection",
           "Replies silently go to a different domain than the visible sender.", ["From vs Reply-To domains differ"],
           "Flag Reply-To mismatch in the client; train users to check the reply address on payment threads.", "MEDIUM", "HIGH", "Your mail admin")
    dangerous = [f for f in sb_files if f.get("verdict") != "SAFE" or f.get("detected_type") in ("PE executable", "Windows shortcut (LNK)", "ISO disk image")]
    if dangerous:
        wk("VULN-ATTACH-POLICY", "Mail gateway attachment policy", "Dangerous attachment types allowed",
           "Executable, script, macro, disk-image or archive payloads were allowed to reach the user.",
           [f"{f['filename']} ({f['detected_type']})" for f in dangerous[:3]],
           "Block executables/scripts/ISO/LNK and password-protected archives at the gateway; strip macros from external Office files.",
           "HIGH", "CRITICAL" if any(f.get("verdict") == "MALICIOUS" for f in dangerous) else "HIGH", "Your mail admin")
    if any(any(x.get("category") == "macro" for x in f.get("findings", [])) for f in sb_files):
        wk("VULN-ENDPOINT-MACRO", "Endpoint (Office)", "Macros from the internet can run",
           "The document relies on the user enabling macros / external content.", [f["filename"] for f in sb_files][:2],
           "Enforce 'Block macros from the Internet' GPO and Microsoft Defender ASR rules for Office child processes.",
           "MEDIUM", "CRITICAL", "Endpoint team")
    if bad_urls or sig.get("url_risky"):
        wk("VULN-URL-PROTECTION", "Web / URL filtering", "No time-of-click URL protection",
           "Malicious or deceptive links can be opened directly from the mail.", [u["url"][:80] for u in bad_urls[:3]],
           "Enable URL rewriting / time-of-click sandboxing and DNS filtering for newly registered domains.", "HIGH", "HIGH", "Security team")
    if cred_sig or cred_form:
        wk("VULN-IDENTITY-MFA", "Identity & access (IAM)", "Password-only or phishable MFA",
           "If the user submits credentials, accounts without phishing-resistant MFA are immediately taken over.",
           [f"indicator: {t}" for t in cred_sig][:2], "Enforce phishing-resistant MFA (FIDO2/passkeys), conditional access, impossible-travel alerts.",
           "HIGH", "CRITICAL", "IAM team")
    if fin_sig:
        wk("VULN-PAYMENT-PROCESS", "Finance process", "No out-of-band payment verification",
           "Payment instructions received by e-mail can be acted on without a call-back check.", [f"indicator: {t}" for t in fin_sig],
           "Mandate call-back verification on a known number for any new/changed bank details; dual approval.", "HIGH", "CRITICAL", "Finance")
    human = it & {"urgency", "fear_threat", "executive_impersonation", "suspicious_call_to_action", "credential_harvesting"}
    if human:
        wk("VULN-HUMAN", "People (security awareness)", "Susceptibility to social engineering",
           "The lure exploits urgency, fear or authority to bypass the user's judgement.", [f"indicator: {t}" for t in sorted(human)][:3],
           "Targeted awareness + phishing simulation on this exact lure; one-click 'Report phishing' button.", "MEDIUM", "HIGH", "HR / Security awareness")
    if (ai_sec or {}).get("findings"):
        wk("VULN-AI-ASSISTANT", "AI mail assistants / ML filters", "AI components exposed to adversarial content",
           "Hidden text, prompt injection or token-splitting targets AI summarisers and classifiers.",
           [f["title"] for f in ai_sec["findings"][:3]], "Strip hidden content before AI processing; treat e-mail as untrusted data in all LLM prompts.",
           "MEDIUM", "HIGH", "AI / platform team")
    weak.sort(key=lambda w: w["score"], reverse=True)

    exploit = max([w["score"] for w in weak] + [0]) / 16 * 100
    return {
        "primary_intent": primary,
        "intents": intents,
        "kill_chain": kc,
        "mitre_attack": techniques,
        "weaknesses": weak,
        "exploitability_score": round(exploit, 1),
        "attack_path": " → ".join([s["stage"] + (f" ({s['evidence'][:70]})" if s["evidence"] and s["evidence"] != "Not evident" else "")
                                   for s in kc if s["observed"]]) or "No attack path observed.",
        "scope_note": "Passive assessment derived from the e-mail's own evidence; no active scanning of third-party systems was performed.",
    }
