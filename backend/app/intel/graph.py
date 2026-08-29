"""
Attack relationship graph builder.

Visualizes relationships between entities extracted from an analyzed email:
  Email -> Sender
  Email -> Reply-To (with mismatch relation if spoofed)
  Email -> Source IP / Relay IPs
  Email -> Domains (with Suspicious / Lookalike labels)
  Email -> URLs (with Suspicious URL labels)
  Email -> Authentication Results (SPF, DKIM, DMARC)
  Email -> Threat Indicators (Urgency, Credential Harvesting, Extortion, etc.)
  Email -> Threat Category (Phishing, BEC, Blackmail, Spam, etc.)
  Email -> Risk Level (LOW, MEDIUM, HIGH, CRITICAL)
"""
from __future__ import annotations

from typing import Dict, List, Any
import networkx as nx
from app.forensic.engine import ForensicAnalysisResult


def build_attack_graph(
    result: ForensicAnalysisResult,
    case_id: str,
    overall_score: float | None = None,
    classification: str | None = None,
) -> Dict[str, Any]:
    g = nx.DiGraph()

    score = overall_score if overall_score is not None else result.threat_score.overall_score
    risk_level = classification or result.threat_score.classification or "LOW"

    # 1. Root Email Node
    email_label = f"Threat Email ({case_id})" if risk_level in ("HIGH", "CRITICAL") else f"Email ({case_id})"
    email_node_id = f"EMAIL:{case_id}"
    g.add_node(
        email_node_id,
        id=email_node_id,
        type="EMAIL",
        label=email_label,
        value=case_id,
        risk_score=score,
        classification=risk_level,
    )

    # 2. Sender Node
    sender = result.parsed_email.from_address
    if sender:
        sender_node_id = f"SENDER:{sender}"
        g.add_node(
            sender_node_id,
            id=sender_node_id,
            type="IDENTITY",
            label=f"Sender: {sender}",
            value=sender,
        )
        g.add_edge(email_node_id, sender_node_id, relation="SENT_BY", label="Sender")

    # 3. Reply-To Node & Mismatch relation
    reply_to = result.parsed_email.reply_to
    if reply_to and reply_to != sender:
        reply_node_id = f"REPLY_TO:{reply_to}"
        is_mismatch = (result.authentication.from_reply_to_aligned is False)
        g.add_node(
            reply_node_id,
            id=reply_node_id,
            type="IDENTITY",
            label=f"Reply-To: {reply_to}" + (" [MISMATCH]" if is_mismatch else ""),
            value=reply_to,
            risk_score=75 if is_mismatch else 0,
        )
        rel_label = "REPLY_TO_MISMATCH" if is_mismatch else "REPLY_TO"
        g.add_edge(email_node_id, reply_node_id, relation=rel_label, label="Mismatch" if is_mismatch else "Reply-To")
        if sender:
            g.add_edge(f"SENDER:{sender}", reply_node_id, relation="MISALIGNED_WITH" if is_mismatch else "ROUTES_TO", label="Differs from" if is_mismatch else "Routes to")

    # 4. Source IP / Hop IPs
    for ip in result.ip_findings:
        ip_node_id = f"IP:{ip.ip_address}"
        ip_label = f"Source IP: {ip.ip_address}" if ip.source == "received_hop" else f"IP: {ip.ip_address}"
        g.add_node(
            ip_node_id,
            id=ip_node_id,
            type="IP",
            label=ip_label,
            value=ip.ip_address,
            is_private=ip.is_private,
        )
        g.add_edge(email_node_id, ip_node_id, relation="RELAYED_VIA", label="Source IP" if ip.source == "received_hop" else "Observed IP")

    # 5. Domains
    for d in result.domain_findings:
        dom_node_id = f"DOMAIN:{d.domain}"
        is_suspicious = (d.risk_score > 30) or bool(d.lookalike_of) or bool(d.suspicious_tld) or bool(d.is_punycode)
        dom_label = f"Suspicious Domain: {d.domain}" if is_suspicious else f"Domain: {d.domain}"
        g.add_node(
            dom_node_id,
            id=dom_node_id,
            type="DOMAIN",
            label=dom_label,
            value=d.domain,
            risk_score=d.risk_score,
            lookalike_of=d.lookalike_of,
        )
        if d.role == "sender" and sender:
            g.add_edge(f"SENDER:{sender}", dom_node_id, relation="USES_DOMAIN", label="Sender Domain")
        else:
            g.add_edge(email_node_id, dom_node_id, relation="REFERENCES_DOMAIN", label="Suspicious Domain" if is_suspicious else "Domain")

    # 6. URLs (real URLs only, no fake nodes)
    for u in result.url_findings:
        short_url = u.url if len(u.url) <= 35 else u.url[:32] + "..."
        url_node_id = f"URL:{u.url[:60]}"
        is_suspicious_url = (u.risk_score > 30) or u.is_ip_based or u.is_shortened or u.has_suspicious_tld or u.anchor_text_mismatch
        url_label = f"Suspicious URL: {short_url}" if is_suspicious_url else f"URL: {short_url}"
        g.add_node(
            url_node_id,
            id=url_node_id,
            type="URL",
            label=url_label,
            value=u.url,
            risk_score=u.risk_score,
            is_suspicious=is_suspicious_url,
        )
        g.add_edge(email_node_id, url_node_id, relation="CONTAINS_URL", label="Phishing Link" if is_suspicious_url else "Link")
        if u.hostname:
            dom_node_id = f"DOMAIN:{u.hostname}"
            if dom_node_id not in g:
                g.add_node(dom_node_id, id=dom_node_id, type="DOMAIN", label=f"Domain: {u.hostname}", value=u.hostname)
            g.add_edge(url_node_id, dom_node_id, relation="RESOLVES_TO", label="Host")

    # 7. Authentication Nodes (SPF, DKIM, DMARC)
    auth = result.authentication
    if auth.source != "INSUFFICIENT_DATA":
        # SPF Node
        if auth.spf.result:
            spf_node_id = f"AUTH:SPF:{auth.spf.result}"
            spf_label = f"SPF {auth.spf.result}"
            g.add_node(
                spf_node_id,
                id=spf_node_id,
                type="AUTHENTICATION",
                label=spf_label,
                value=f"SPF: {auth.spf.result}",
                status=auth.spf.result,
                risk_score=80 if auth.spf.result in ("FAIL", "SOFTFAIL", "PERMERROR") else 0,
            )
            g.add_edge(email_node_id, spf_node_id, relation="SPF_STATUS", label=f"SPF {auth.spf.result}")

        # DKIM Node
        if auth.dkim.result:
            dkim_node_id = f"AUTH:DKIM:{auth.dkim.result}"
            dkim_label = f"DKIM {auth.dkim.result}"
            g.add_node(
                dkim_node_id,
                id=dkim_node_id,
                type="AUTHENTICATION",
                label=dkim_label,
                value=f"DKIM: {auth.dkim.result}",
                status=auth.dkim.result,
                risk_score=80 if auth.dkim.result == "FAIL" or (auth.dkim_domain_aligned is False) else 0,
            )
            g.add_edge(email_node_id, dkim_node_id, relation="DKIM_STATUS", label=f"DKIM {auth.dkim.result}")

        # DMARC Node
        if auth.dmarc.result:
            dmarc_node_id = f"AUTH:DMARC:{auth.dmarc.result}"
            dmarc_label = f"DMARC {auth.dmarc.result}"
            g.add_node(
                dmarc_node_id,
                id=dmarc_node_id,
                type="AUTHENTICATION",
                label=dmarc_label,
                value=f"DMARC: {auth.dmarc.result}",
                status=auth.dmarc.result,
                risk_score=85 if auth.dmarc.result == "FAIL" else 0,
            )
            g.add_edge(email_node_id, dmarc_node_id, relation="DMARC_STATUS", label=f"DMARC {auth.dmarc.result}")

    # 8. Threat Indicator Nodes
    for ind in result.social_engineering_indicators:
        ind_node_id = f"THREAT:{ind.indicator_type}"
        clean_name = ind.indicator_type.replace("_", " ").title()
        g.add_node(
            ind_node_id,
            id=ind_node_id,
            type="THREAT",
            label=f"Threat: {clean_name}",
            value=ind.matched_evidence,
            severity=ind.severity,
            risk_score=85 if ind.severity in ("HIGH", "CRITICAL") else 40,
        )
        g.add_edge(email_node_id, ind_node_id, relation="INDICATOR_DETECTED", label=clean_name)

    # 9. Threat Category Node
    # Infer category: Phishing, Blackmail / Extortion, BEC, Malware, Spam, or Benign
    ind_types = {i.indicator_type.lower() for i in result.social_engineering_indicators}
    if "explicit_threat" in ind_types:
        threat_cat = "Explicit Threat / Harassment"
    elif "blackmail_extortion" in ind_types:
        threat_cat = "Blackmail / Extortion"
    elif "credential_harvesting" in ind_types or "phishing_social_engineering" in ind_types:
        threat_cat = "Phishing Attack"
    elif "executive_impersonation" in ind_types or "payment_fraud" in ind_types:
        threat_cat = "Business Email Compromise (BEC)"
    elif len(result.url_findings) > 0 and any(u.risk_score > 40 for u in result.url_findings):
        threat_cat = "Phishing / Malicious Link"
    elif "spam_bulk" in ind_types:
        threat_cat = "Unsolicited Bulk Spam"
    elif score >= 50:
        threat_cat = "Suspicious Email Threat"
    else:
        threat_cat = "Legitimate / Low Risk"

    cat_node_id = f"THREAT_CAT:{threat_cat}"
    g.add_node(
        cat_node_id,
        id=cat_node_id,
        type="THREAT",
        label=f"Category: {threat_cat}",
        value=threat_cat,
        risk_score=score,
    )
    g.add_edge(email_node_id, cat_node_id, relation="CLASSIFIED_AS", label="Threat Type")

    # 10. Risk Level Node
    risk_node_id = f"RISK:{risk_level}"
    g.add_node(
        risk_node_id,
        id=risk_node_id,
        type="RISK",
        label=f"{risk_level} RISK ({score:.0f}/100)",
        value=f"Score: {score:.1f}",
        risk_score=score,
        classification=risk_level,
    )
    g.add_edge(email_node_id, risk_node_id, relation="RISK_EVALUATION", label=f"{risk_level} Risk")

    nodes = [{"id": n, **attrs} for n, attrs in g.nodes(data=True)]
    edges = [
        {
            "source": s,
            "target": t,
            "relation": attrs.get("relation", "RELATED_TO"),
            "label": attrs.get("label", attrs.get("relation", "RELATED_TO")),
        }
        for s, t, attrs in g.edges(data=True)
    ]

    return {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "case_id": case_id,
        "risk_level": risk_level,
        "risk_score": score,
        "threat_category": threat_cat,
    }
