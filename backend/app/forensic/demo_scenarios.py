"""
Realistic Demonstration Threat Scenarios for SIH Problem Statement 26106.

Provides 10 distinct, fully-formed forensic test cases across diverse threat families:
1.  CREDENTIAL_PHISHING — Microsoft 365 Account Suspension Warning
2.  BANKING_IMPERSONATION — HDFC NetBanking Unauthorized Debit Alert
3.  BEC_WIRE_FRAUD — Executive Confidential Wire Transfer Directive
4.  INVOICE_FRAUD — Overdue Vendor Remittance with Altered Bank Routing
5.  DELIVERY_SCAM — India Post / DHL Consignment Hold Surcharge
6.  JOB_OFFER_SCAM — Amazon / Google Remote Consultant Offer
7.  GOVERNMENT_TAX_SCAM — Income Tax Department Refund Validation Notice
8.  MALWARE_ATTACHMENT — Purchase Order Receipt with Macro-Enabled Payload
9.  PRIZE_LOTTERY_SCAM — Global Consumer Sweepstakes Award
10. LEGITIMATE_SAFE — Corporate SOC Security Digest (Clean Authentication)
"""
from __future__ import annotations

from typing import Any, Dict, List

DEMO_SCENARIOS: List[Dict[str, Any]] = [
    {
        "id": "scenario-cred-phish",
        "title": "Microsoft 365 — Critical Security Alert: Account Termination",
        "threat_class": "CREDENTIAL_PHISHING",
        "severity": "CRITICAL",
        "expected_score": 88,
        "sender": "security-update@micros0ft-support-portal.net",
        "subject": "ACTION REQUIRED: Microsoft 365 Password Expiration in 2 Hours",
        "description": "Targeted credential harvesting lure utilizing typosquatted domain, fake auth portals, and urgency cues.",
        "eml_content": """From: "Microsoft 365 Security Team" <security-update@micros0ft-support-portal.net>
To: target-analyst@enterprise-corp.org
Subject: ACTION REQUIRED: Microsoft 365 Password Expiration in 2 Hours
Date: Wed, 09 Sep 2026 14:15:00 +0000
Message-ID: <m365-alert-99124@micros0ft-support-portal.net>
Reply-To: support-login@credential-redirect-gw.com
Received: from mail-relay.micros0ft-support-portal.net (mail-relay.micros0ft-support-portal.net [185.220.101.5])
    by mx.enterprise-corp.org with ESMTP id m365_001; Wed, 09 Sep 2026 14:15:03 +0000
Received: from vps-node-44.cloud-hoster-ru.net (vps-node-44.cloud-hoster-ru.net [194.26.29.112])
    by mail-relay.micros0ft-support-portal.net with ESMTP id m365_orig; Wed, 09 Sep 2026 14:14:58 +0000
Authentication-Results: mx.enterprise-corp.org;
    spf=fail (sender IP 185.220.101.5 is not allowed by domain micros0ft-support-portal.net);
    dkim=fail reason="signature verification failed" header.d=micros0ft-support-portal.net;
    dmarc=fail (p=reject) header.from=micros0ft-support-portal.net
Content-Type: text/html; charset="UTF-8"

<div style="font-family: Arial, sans-serif;">
<h2>Microsoft Security Operations</h2>
<p>Dear Valued User,</p>
<p style="color:red; font-weight:bold;">Your Microsoft 365 password expires in 2 hours. Access to Exchange, OneDrive, and Teams will be terminated immediately unless verified.</p>
<p>Please re-authenticate your corporate credentials to prevent account lockout:</p>
<p><a href="https://login.micros0ft-auth-session.com/common/oauth2/authorize?client_id=corporate-sso"><strong>Keep My Current Password & Verify Identity</strong></a></p>
<p>Microsoft Cyber Defense Operations Center</p>
</div>
""",
    },
    {
        "id": "scenario-bank-impersonation",
        "title": "HDFC NetBanking — Unauthorized ₹48,500 Debit Alert",
        "threat_class": "BANKING_IMPERSONATION",
        "severity": "CRITICAL",
        "expected_score": 92,
        "sender": "alerts@hdfc-security-verification.co.in",
        "subject": "URGENT: Transaction of INR 48,500 Debited to VPA merchant.pay@upi",
        "description": "High-urgency financial lure designed to panic victims into submitting OTPs and banking credentials on a fake mirror site.",
        "eml_content": """From: "HDFC Bank Alert Desk" <alerts@hdfc-security-verification.co.in>
To: account-holder@company.in
Subject: URGENT: Transaction of INR 48,500 Debited to VPA merchant.pay@upi
Date: Wed, 09 Sep 2026 11:20:00 +0530
Message-ID: <hdfc-tx-9921@hdfc-security-verification.co.in>
Reply-To: dispute-center@hdfc-verification-gateway.in
Received: from mail.hdfc-security-verification.co.in (mail.hdfc-security-verification.co.in [45.142.214.88])
    by mx.company.in with ESMTP id hdfc_relay; Wed, 09 Sep 2026 11:20:05 +0530
Authentication-Results: mx.company.in;
    spf=softfail (domain hdfc-security-verification.co.in does not authorize 45.142.214.88);
    dkim=none;
    dmarc=fail (p=none)
Content-Type: text/html; charset="UTF-8"

<div>
<h3>HDFC Bank Security Alerts</h3>
<p>Dear Customer, an online transaction of <b>INR 48,500.00</b> was approved on your NetBanking account to beneficiary <code>merchant.pay@upi</code> on 09-Sep-2026 11:18:22 IST.</p>
<p>If you did <b>NOT</b> authorize this transfer, dispute it immediately within 15 minutes to initiate reversal:</p>
<p><a href="http://hdfc-dispute-cancellation-portal.in/dispute/reversal?ref=99281"><strong>Cancel & Dispute Transfer Now</strong></a></p>
</div>
""",
    },
    {
        "id": "scenario-bec-wire",
        "title": "CEO Direct Order — Confidential Project Apollo Acquisition Wire",
        "threat_class": "BUSINESS_EMAIL_COMPROMISE",
        "severity": "HIGH",
        "expected_score": 79,
        "sender": "ceo.rajesh.sharma@corp-executives-desk.com",
        "subject": "CONFIDENTIAL: Urgent Wire Authorization - Project Apollo",
        "description": "Executive impersonation (CEO fraud) pressuring finance staff to execute an out-of-band wire transfer.",
        "eml_content": """From: "Rajesh Sharma, Group CEO" <ceo.rajesh.sharma@corp-executives-desk.com>
To: finance-controller@enterprise-corp.org
Subject: CONFIDENTIAL: Urgent Wire Authorization - Project Apollo
Date: Wed, 09 Sep 2026 09:40:00 +0000
Message-ID: <ceo-confidential-001@corp-executives-desk.com>
Reply-To: rajesh.sharma.privatedesk@gmail.com
Received: from outbound.cloud-relay-mail.net (outbound.cloud-relay-mail.net [104.244.76.13])
    by mx.enterprise-corp.org with ESMTP id bec_hop; Wed, 09 Sep 2026 09:40:04 +0000
Authentication-Results: mx.enterprise-corp.org;
    spf=neutral; dkim=none; dmarc=none
Content-Type: text/plain; charset="UTF-8"

Good morning,

I am currently in a board meeting regarding our confidential Project Apollo closing.
We need an immediate retainer wire transfer of $142,000 sent to our legal advisory partners before 1:00 PM today.

Please confirm you can handle this wire discreetly. Due to non-disclosure restrictions, do not discuss this over phone or Slack with the wider team. Reply directly to this email and I will supply the beneficiary escrow details.

Regards,
Rajesh Sharma
Group Chief Executive Officer
""",
    },
    {
        "id": "scenario-invoice-fraud",
        "title": "Vendor Account Update — Revised Remittance for Invoice #INV-2026-881",
        "threat_class": "FINANCIAL_FRAUD",
        "severity": "HIGH",
        "expected_score": 74,
        "sender": "billing@apex-logistics-solutions-in.com",
        "subject": "URGENT: Revised Banking Coordinates for Invoice #INV-2026-881",
        "description": "Supplier impersonation requesting routing number change prior to invoice settlement.",
        "eml_content": """From: "Apex Logistics Accounts" <billing@apex-logistics-solutions-in.com>
To: accounts-payable@enterprise-corp.org
Subject: URGENT: Revised Banking Coordinates for Invoice #INV-2026-881
Date: Wed, 09 Sep 2026 08:30:00 +0000
Message-ID: <apex-inv-881@apex-logistics-solutions-in.com>
Received: from relay02.vps-hosting-sg.com (relay02.vps-hosting-sg.com [139.180.201.44])
    by mx.enterprise-corp.org with ESMTP id inv_01; Wed, 09 Sep 2026 08:30:03 +0000
Authentication-Results: mx.enterprise-corp.org;
    spf=fail; dkim=none; dmarc=fail
Content-Type: text/html; charset="UTF-8"

<div>
<p>Dear Accounts Payable,</p>
<p>Please note that our primary banking partner is undergoing statutory audit. Effective immediately, all remittances for Invoice #INV-2026-881 (Total: $38,400.00) must be wired to our secondary escrow account.</p>
<p>Please download the updated remittance authorization voucher below:</p>
<p><a href="https://apex-documents-vault.s3.eu-central-1.amazonaws.com/Remittance_Voucher_INV-881.pdf.exe">Download Signed Bank Instruction Letter (.PDF)</a></p>
</div>
""",
    },
    {
        "id": "scenario-delivery-scam",
        "title": "India Post — Undeliverable Package Notice: Customs Duty Pending",
        "threat_class": "SOCIAL_ENGINEERING",
        "severity": "MEDIUM",
        "expected_score": 62,
        "sender": "tracking-dispatch@indiapost-consignment-notice.in",
        "subject": "Consignment #IN882910408 - Delivery Suspended: ₹48 Surcharge",
        "description": "Postal consignment lure asking victim to pay a small clearance fee on a fraudulent payment form.",
        "eml_content": """From: "India Post Speed Post Desk" <tracking-dispatch@indiapost-consignment-notice.in>
To: recipient@user-domain.in
Subject: Consignment #IN882910408 - Delivery Suspended: INR 48 Surcharge
Date: Wed, 09 Sep 2026 13:00:00 +0530
Message-ID: <post-dispatch-112@indiapost-consignment-notice.in>
Received: from smtp.indiapost-consignment-notice.in (smtp.indiapost-consignment-notice.in [103.145.12.90])
    by mx.user-domain.in with ESMTP id post_01; Wed, 09 Sep 2026 13:00:04 +0530
Authentication-Results: mx.user-domain.in;
    spf=fail; dkim=none; dmarc=none
Content-Type: text/html; charset="UTF-8"

<div>
<p><b>India Post Delivery Notification</b></p>
<p>Your international consignment #IN882910408 could not be delivered to your registered address due to an unpaid customs handling fee of INR 48.00.</p>
<p><a href="http://indiapost-parcel-re-dispatch.com/pay">Pay Clearance Surcharge (INR 48) to Release Parcel</a></p>
</div>
""",
    },
    {
        "id": "scenario-job-scam",
        "title": "Google India — Remote Cloud Security Specialist Appointment",
        "threat_class": "SOCIAL_ENGINEERING",
        "severity": "MEDIUM",
        "expected_score": 58,
        "sender": "careers@google-talent-recruitment-asia.com",
        "subject": "Selection Notice: Google Cloud Security Architect (Remote - INR 42 LPA)",
        "description": "Employment recruitment scam offering inflated compensation and directing applicant to pay onboarding background check fees.",
        "eml_content": """From: "Google Careers Team Asia" <careers@google-talent-recruitment-asia.com>
To: candidate@tech-talent.org
Subject: Selection Notice: Google Cloud Security Architect (Remote - INR 42 LPA)
Date: Wed, 09 Sep 2026 12:10:00 +0530
Message-ID: <google-job-offer-88@google-talent-recruitment-asia.com>
Received: from mail.google-talent-recruitment-asia.com (mail.google-talent-recruitment-asia.com [178.62.204.18])
    by mx.tech-talent.org with ESMTP id job_01; Wed, 09 Sep 2026 12:10:05 +0530
Authentication-Results: mx.tech-talent.org;
    spf=fail; dkim=none; dmarc=none
Content-Type: text/plain; charset="UTF-8"

Dear Candidate,

Congratulations! Following our review of your profile, the Google Cloud Infrastructure division is pleased to offer you the position of Senior Cloud Security Architect (Remote India).

Annual Compensation: INR 42,00,000 + Stock Options.

To confirm your acceptance and receive your encrypted equipment kit, submit your KYC verification and security deposit of INR 4,500 (fully refundable on day 1):
http://google-asia-candidate-portal.com/onboard?id=GGL-9921
""",
    },
    {
        "id": "scenario-gov-tax",
        "title": "Income Tax Department — Statutory Refund of ₹31,480 Approved",
        "threat_class": "IMPERSONATION",
        "severity": "HIGH",
        "expected_score": 82,
        "sender": "refund-processing@incometax-efiling-refund.gov-in.org",
        "subject": "Intimation U/S 143(1): Tax Refund of INR 31,480 Pending Bank Confirmation",
        "description": "Government authority impersonation demanding bank login verification to claim an alleged tax refund.",
        "eml_content": """From: "Income Tax Department e-Filing" <refund-processing@incometax-efiling-refund.gov-in.org>
To: taxpayer@citizen-inbox.in
Subject: Intimation U/S 143(1): Tax Refund of INR 31,480 Pending Bank Confirmation
Date: Wed, 09 Sep 2026 07:45:00 +0530
Message-ID: <it-refund-2026-99@incometax-efiling-refund.gov-in.org>
Received: from relay01.gov-in.org (relay01.gov-in.org [91.215.85.12])
    by mx.citizen-inbox.in with ESMTP id it_tax_01; Wed, 09 Sep 2026 07:45:03 +0530
Authentication-Results: mx.citizen-inbox.in;
    spf=fail; dkim=fail; dmarc=fail
Content-Type: text/html; charset="UTF-8"

<div>
<h3>Central Board of Direct Taxes — Refund Intimation</h3>
<p>An income tax refund amount of <b>INR 31,480.00</b> has been calculated for Assessment Year 2026-27.</p>
<p>Due to missing IFSC validation, disbursement failed. Re-validate your account credentials immediately:</p>
<p><a href="http://incometaxindiaefiling-refund-validate.in/login">Validate Bank Account & Claim INR 31,480</a></p>
</div>
""",
    },
    {
        "id": "scenario-malware",
        "title": "Apex Freight — Arrival Notice & Bill of Lading with Macro Payload",
        "threat_class": "MALICIOUS_ATTACHMENT",
        "severity": "CRITICAL",
        "expected_score": 95,
        "sender": "dispatch@freight-docs-oceanline.com",
        "subject": "Delivery Manifest & Bill of Lading #BOL-2026-99214.xlsm",
        "description": "Trojan / malware delivery disguised as shipping documentation with weaponized macro code.",
        "eml_content": """From: "Apex Maritime Operations" <dispatch@freight-docs-oceanline.com>
To: logistics-ops@enterprise-corp.org
Subject: Delivery Manifest & Bill of Lading #BOL-2026-99214.xlsm
Date: Wed, 09 Sep 2026 15:30:00 +0000
Message-ID: <apex-manifest-99214@freight-docs-oceanline.com>
Received: from mail-gateway-de.cloud-node.eu (mail-gateway-de.cloud-node.eu [193.106.191.22])
    by mx.enterprise-corp.org with ESMTP id malw_01; Wed, 09 Sep 2026 15:30:04 +0000
Authentication-Results: mx.enterprise-corp.org;
    spf=fail; dkim=none; dmarc=fail
Content-Type: multipart/mixed; boundary="----=_Part_99124_Apex"

------=_Part_99124_Apex
Content-Type: text/plain; charset="UTF-8"

Attached is the customs cleared Bill of Lading and port clearance manifest for your incoming container. Enable Excel macros when opening to calculate clearance tariff.

------=_Part_99124_Apex
Content-Type: application/vnd.ms-excel.sheet.macroEnabled.12; name="Bill_of_Lading_99214.xlsm"
Content-Disposition: attachment; filename="Bill_of_Lading_99214.xlsm"
Content-Transfer-Encoding: base64

UEsDBBQAAAAIAAAAAAAAAAAAAAAAAAAAAAAJAAAAeGwv...
------=_Part_99124_Apex--
""",
    },
    {
        "id": "scenario-prize-scam",
        "title": "Global Consumer Award — €1,250,000 Promotional Draw",
        "threat_class": "SOCIAL_ENGINEERING",
        "severity": "MEDIUM",
        "expected_score": 54,
        "sender": "claims-agent@international-lottery-awards-eu.com",
        "subject": "NOTIFICATION: Your Email Selected for 1,250,000 EUR Grand Prize",
        "description": "Advance fee fraud / lottery scam designed to elicit personal identity documents and advance clearance payments.",
        "eml_content": """From: "EuroMillions Consumer Lottery" <claims-agent@international-lottery-awards-eu.com>
To: recipient@worldwide-inbox.net
Subject: NOTIFICATION: Your Email Selected for 1,250,000 EUR Grand Prize
Date: Wed, 09 Sep 2026 10:15:00 +0000
Message-ID: <prize-claim-8812@international-lottery-awards-eu.com>
Received: from vps-mailer.offshore-bullet.com (vps-mailer.offshore-bullet.com [89.44.9.14])
    by mx.worldwide-inbox.net with ESMTP id prize_01; Wed, 09 Sep 2026 10:15:03 +0000
Authentication-Results: mx.worldwide-inbox.net;
    spf=fail; dkim=none; dmarc=none
Content-Type: text/plain; charset="UTF-8"

Official Award Notice:
We are pleased to notify you that your email address emerged as the 2nd category winner of 1,250,000 Euros in our international promotional lottery.
To initiate transfer to your domestic bank account, reply with your full legal name, passport copy, and residential address.
""",
    },
    {
        "id": "scenario-legit-safe",
        "title": "Enterprise Security — Monthly Cyber Awareness & Phishing Digest",
        "threat_class": "LEGITIMATE",
        "severity": "LOW",
        "expected_score": 4,
        "sender": "soc-alerts@security.enterprise-corp.org",
        "subject": "SOC Security Bulletin: Best Practices for Email Threat Defense",
        "description": "Genuine, authenticated corporate communication with valid SPF, DKIM, and DMARC passing all forensic rules.",
        "eml_content": """From: "Corporate Security Office" <soc-alerts@security.enterprise-corp.org>
To: all-staff@enterprise-corp.org
Subject: SOC Security Bulletin: Best Practices for Email Threat Defense
Date: Wed, 09 Sep 2026 09:00:00 +0000
Message-ID: <soc-bulletin-sep2026@security.enterprise-corp.org>
Received: from mail-out.security.enterprise-corp.org (mail-out.security.enterprise-corp.org [198.51.100.15])
    by mx.enterprise-corp.org with ESMTP id legit_01; Wed, 09 Sep 2026 09:00:02 +0000
Authentication-Results: mx.enterprise-corp.org;
    spf=pass (mail-out.security.enterprise-corp.org: 198.51.100.15 is authorized);
    dkim=pass header.d=security.enterprise-corp.org;
    dmarc=pass (p=reject) header.from=security.enterprise-corp.org
Content-Type: text/html; charset="UTF-8"

<div>
<h2>Enterprise Information Security Bulletin</h2>
<p>Dear Colleagues,</p>
<p>This month's cybersecurity focus highlights vigilance against executive impersonation and QR-code credential phishing.</p>
<p>Always verify unexpected requests for urgent financial transfers or credential verifications with your security team.</p>
<p>Report suspicious emails using the MailShield add-in button or forwarding to <code>phish-report@enterprise-corp.org</code>.</p>
<p>Enterprise SOC Operations</p>
</div>
""",
    },
]


def get_scenario_by_id(scenario_id: str) -> Optional[Dict[str, Any]]:
    for s in DEMO_SCENARIOS:
        if s["id"] == scenario_id:
            return s
    return None
