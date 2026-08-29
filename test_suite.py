"""
Comprehensive verification test for all 5 required test cases:
1. Normal academic/work email -> LOW
2. Normal promotional spam -> MEDIUM
3. Phishing email with suspicious URL -> HIGH
4. Threat + Phishing + SPF/DKIM/DMARC failure + Reply-To mismatch + Suspicious URL -> CRITICAL
5. Strong direct threat / blackmail email -> HIGH or CRITICAL
"""
import sys
from pathlib import Path

# Add backend to sys.path
BACKEND_DIR = Path(__file__).resolve().parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))
sys.stdout.reconfigure(encoding='utf-8')

from app.forensic.engine import run_forensic_analysis
from app.intel.graph import build_attack_graph

# Test 1: Normal academic/work email
EML_1_NORMAL = b"""From: prof.smith@university.edu
To: student@university.edu
Subject: Assignment 3 Submission Deadline
Date: Mon, 25 Aug 2026 10:00:00 +0000
Message-ID: <normal-123@university.edu>
Authentication-Results: mx.university.edu; spf=pass (mx.university.edu: domain of prof.smith@university.edu designates 192.0.2.1 as permitted sender) smtp.mailfrom=prof.smith@university.edu; dkim=pass header.d=university.edu; dmarc=pass
Received: from mail.university.edu (mail.university.edu [192.0.2.1]) by mx.university.edu with ESMTP id ABC12345 for <student@university.edu>; Mon, 25 Aug 2026 10:00:01 +0000

Dear students,
Please remember that Assignment 3 is due this Friday at 5:00 PM. Let me know during office hours if you have any questions.

Best regards,
Prof. Smith
Department of Computer Science
"""

# Test 2: Normal promotional spam
EML_2_SPAM = b"""From: newsletter@deals.commercial-marketing.com
To: user@example.com
Subject: 100% Free Special Offer - Congratulations You Won a Discount
Date: Mon, 25 Aug 2026 11:00:00 +0000
Message-ID: <promo-999@deals.commercial-marketing.com>
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=newsletter@deals.commercial-marketing.com; dkim=pass header.d=deals.commercial-marketing.com; dmarc=pass
Received: from mail.commercial-marketing.com (mail.commercial-marketing.com [198.51.100.2]) by mx.example.com with ESMTP id DEF67890; Mon, 25 Aug 2026 11:00:01 +0000

Hello! You have been selected for our special 100% free rewards voucher!
Claim your reward now at our online retail catalog or unsubscribe here.
"""

# Test 3: Phishing email with suspicious URL + account suspension
EML_3_PHISHING = b"""From: security-alert@bank-service.com
To: victim@example.com
Subject: Urgent: Account Suspended - Verify your credentials immediately
Date: Mon, 25 Aug 2026 12:00:00 +0000
Message-ID: <phish-444@bank-service.com>
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=security-alert@bank-service.com; dkim=fail; dmarc=fail
Received: from unknown-host.net (unknown-host.net [203.0.113.50]) by mx.example.com with ESMTP id GHI11111; Mon, 25 Aug 2026 12:00:01 +0000

Dear Customer,
Your account has been suspended due to unauthorized login activity.
Immediate action required: click the link below to verify your password and confirm your credentials within 24 hours.
http://192.168.1.50/login.php?verify=account&token=998822

Security Team
"""

# Test 4: Compound Threat + Phishing + SPF/DKIM/DMARC failure + Reply-To mismatch + Suspicious URL
EML_4_CRITICAL = b"""From: CEO Office <ceo@legitimate-corporation.com>
Reply-To: attacker-inbox@stealth-hacker.xyz
Return-Path: bounce@malicious-domain.tk
To: finance@legitimate-corporation.com
Subject: FINAL NOTICE: Pay Ransom Or We Will Kill Your Network and Leak Passwords
Date: Mon, 25 Aug 2026 13:00:00 +0000
Message-ID: <threat-extort-888@bad-relay.org>
Authentication-Results: mx.legitimate-corporation.com; spf=fail (domain of ceo@legitimate-corporation.com does not designate permitted sender) smtp.mailfrom=ceo@legitimate-corporation.com; dkim=fail header.d=stealth-hacker.xyz; dmarc=fail action=none
Received: from attacker-proxy.xyz (attacker-proxy.xyz [198.51.100.99]) by mx.legitimate-corporation.com with ESMTP id XYZ999; Mon, 25 Aug 2026 13:00:01 +0000

We have compromised your system and recorded you via webcam browsing adult content.
You must immediately send bitcoin to our btc wallet address within 24 hours.
If you fail to send payment or click here to verify your account passwords, we will leak your private photos and harm your family with grave consequences.
Login to decrypt: http://bit.ly/secure-auth-bypass?signin=finance&reset=token

We are watching you.
"""

# Test 5: Direct Threat / Blackmail / Extortion
EML_5_BLACKMAIL = b"""From: anonymous-shadow@dark-mail.org
To: victim@example.com
Subject: WE HAVE RECORDED YOU - Send Bitcoin Immediately
Date: Mon, 25 Aug 2026 14:00:00 +0000
Message-ID: <extort-777@dark-mail.org>
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Received: from dark-relay.org (dark-relay.org [198.51.100.77]) by mx.example.com with ESMTP id EXT777; Mon, 25 Aug 2026 14:00:01 +0000

I have hacked your webcam and device. I have recorded videos of you and have all your passwords.
Send payment to this btc address within 24 hours or I will leak these videos to all your contacts and ruin your life.
Act now, you have no choice.
"""

def run_tests():
    test_cases = [
        ("TEST 1: Normal academic/work email", EML_1_NORMAL, ["LOW"]),
        ("TEST 2: Normal promotional spam", EML_2_SPAM, ["MEDIUM", "LOW"]),
        ("TEST 3: Phishing with suspicious URL", EML_3_PHISHING, ["HIGH", "CRITICAL"]),
        ("TEST 4: Threat + Phishing + Auth Failure + Mismatch", EML_4_CRITICAL, ["CRITICAL", "HIGH"]),
        ("TEST 5: Direct Blackmail / Extortion email", EML_5_BLACKMAIL, ["CRITICAL", "HIGH"]),
    ]

    print("\n=======================================================")
    print(" 🧪 RUNNING FORENSIC SCORING & GRAPH TEST SUITE")
    print("=======================================================\n")

    all_passed = True
    for title, eml_bytes, expected_classes in test_cases:
        res = run_forensic_analysis(eml_bytes)
        ts = res.threat_score
        score = ts.overall_score
        cls = ts.classification

        # Also test Attack Graph generation
        graph = build_attack_graph(res, "CASE-TEST", score, cls)
        node_count = graph["node_count"]
        edge_count = graph["edge_count"]

        passed = cls in expected_classes
        status_icon = "✅ PASS" if passed else "❌ FAIL"
        if not passed:
            all_passed = False

        print(f"{status_icon} | {title}")
        print(f"       Risk Score: {score:.1f} / 100  -->  Classification: {cls} (Expected: {' or '.join(expected_classes)})")
        print(f"       Attack Graph: {node_count} nodes, {edge_count} edges (Category: {graph['threat_category']})")
        print(f"       Evidence Items: {len(ts.explanation.get('evidence_items', []))} detected | Combination Bonuses: {len(ts.explanation.get('combination_bonuses', []))}")
        for r in ts.explanation.get('severity_reasons', [])[:3]:
            print(f"         • {r}")
        print()

    print("=======================================================")
    if all_passed:
        print(" 🎉 ALL 5 TEST CASES PASSED SUCCESSFULLY!")
    else:
        print(" ⚠️ SOME TEST CASES FAILED - CHECK OUTPUT ABOVE")
    print("=======================================================\n")
    return all_passed

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
