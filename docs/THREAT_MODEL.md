# Threat Model — What This Platform Detects, and Its Limits

## In scope for Phase 1

The platform analyzes a single uploaded `.eml` file for indicators consistent with:

- **Sender spoofing** — From/Reply-To/Return-Path domain mismatches, display-name impersonation, SPF/DKIM/DMARC failures.
- **Phishing / credential harvesting** — suspicious URLs (IP-based hosts, shorteners, punycode, anchor-text mismatch, credential-flow query parameters), urgency/fear language, credential-request phrasing.
- **Business Email Compromise (BEC)** — executive-impersonation display names sent from freemail domains, invoice/payment-diversion language, secrecy-framed conversational phrasing.
- **Lookalike / typosquat domains** — via a reusable Levenshtein-based similarity function compared against configured trusted organizational domains.
- **Header/relay anomalies** — missing or inconsistent Received chains, missing Message-ID, multiple unrelated domains referenced across sender headers.

Every detection is a **deterministic, explainable rule** with a rule ID, severity, evidence, and confidence — nothing is a black-box classification.

## Explicitly out of scope / not claimed

Per the project's non-negotiable rules, this platform **never**:

- Claims the earliest Received-header IP is the confirmed attacker's location — it is reported as "earliest **observed** sending infrastructure," because headers can be forged, and legitimate relay infrastructure is common.
- Performs IP geolocation and presents it as a physical attacker location.
- Actively visits, fetches, or renders any URL found in an analyzed email.
- Opens, executes, or renders any attachment — only filename/MIME-type/SHA-256 are extracted.
- Cryptographically verifies DKIM signatures (requires DNS lookups of the signing domain — deferred).
- Declares a domain "malicious" — domain findings report similarity/evidence/confidence, not a verdict.
- Uses a black-box ML model for the social-engineering detector in Phase 1 (by design, for auditability); this is intentionally swappable for a real classifier in Phase 2 without changing the calling interface.

## Adversary assumptions

- The uploaded `.eml` is assumed **fully attacker-controlled** — headers, body, and attachments may all be crafted to exploit the parser or evade detection. See `SECURITY.md` for platform-hardening controls against this.
- The platform does not assume the presence of any particular header (e.g. `Authentication-Results`) — its absence is reported as `INSUFFICIENT_DATA`, not silently treated as pass or fail.
- Received headers may be partially or fully forged by anything after the true point of origin; the chain is reconstructed and displayed, but attribution claims are deliberately hedged.

## Confidence semantics

Every score (finding-level `confidence`, overall `threat_score.confidence`) reflects how much *observable evidence* backed the conclusion — not how "bad" the message is. A message with no Authentication-Results header, no URLs, and no received chain will have a **low-confidence** score even if that score happens to be numerically low, because there simply wasn't much to analyze. This distinction is surfaced in the UI and the JSON report.
