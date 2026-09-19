import { Link } from "react-router-dom";
import { Shield } from "lucide-react";
import { PrivacyPage } from "./PrivacyPage";

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-lab-950 text-lab-100 px-4 py-10">
      <div className="max-w-4xl mx-auto">
        <Link to="/login" className="flex items-center gap-2 mb-6 text-white font-bold">
          <Shield className="w-5 h-5 text-phosphor-400" /> MAILSHIELD
        </Link>
        {children}
        <div className="mt-8 text-[11px] text-lab-500 flex gap-4">
          <Link to="/privacy-policy" className="hover:text-lab-300">Privacy Policy</Link>
          <Link to="/terms" className="hover:text-lab-300">Terms of Service</Link>
          <Link to="/login" className="hover:text-lab-300">Sign in</Link>
        </div>
      </div>
    </div>
  );
}

/** Public privacy policy (no login) — used as the Google OAuth consent-screen privacy link. */
export function PublicPrivacyPolicyPage() {
  return <Shell><PrivacyPage publicView /></Shell>;
}

/** Public terms of service (no login) — used as the Google OAuth consent-screen terms link. */
export function TermsPage() {
  const S = ({ t, children }: { t: string; children: React.ReactNode }) => (
    <div className="glass-section p-5">
      <h2 className="text-sm font-bold text-white mb-2">{t}</h2>
      <div className="text-xs text-lab-300 leading-relaxed space-y-2">{children}</div>
    </div>
  );
  return (
    <Shell>
      <div className="space-y-4">
        <h1 className="text-2xl font-bold text-white">Terms of Service</h1>
        <p className="text-xs text-lab-400">MailShield is a prototype developed for Smart India Hackathon 2026 (Problem Statement 26106, AICTE Cyber Security Cell).</p>
        <S t="1. Purpose">
          <p>MailShield analyses e-mails that you upload or that you authorise it to read from your own Gmail account, to detect phishing, spoofing and fraud and to produce forensic reports. It is a defensive security tool.</p>
        </S>
        <S t="2. Acceptable use">
          <p>You may only analyse e-mails and mailboxes you own or are authorised to access. You must not use MailShield to access other people's accounts, attack or probe third-party systems, track or identify individuals, or for any unlawful purpose.</p>
        </S>
        <S t="3. Google account access">
          <p>Gmail access is granted through Google OAuth and can be revoked at any time from the app or from your Google Account (Security → Third-party access). MailShield reads messages only to analyse them; it changes your mailbox only when you click Quarantine/Release. Use of data received from Google APIs follows the Google API Services User Data Policy, including the Limited Use requirements.</p>
        </S>
        <S t="4. Results are advisory">
          <p>Threat scores, classifications and IP geolocation are automated estimates and can be wrong. Geolocation describes network infrastructure, not the identity or physical location of a person. Verify important decisions (payments, credential resets, legal action) through independent channels.</p>
        </S>
        <S t="5. Data">
          <p>Data handling, retention and deletion are described in the <Link to="/privacy-policy" className="text-phosphor-400 underline">Privacy Policy</Link>. You can delete your data at any time.</p>
        </S>
        <S t="6. Availability & liability">
          <p>The service is provided "as is", without warranty, as a research prototype. The developers are not liable for losses arising from its use or unavailability.</p>
        </S>
        <S t="7. Contact">
          <p>baranidharanboopathy66@gmail.com</p>
        </S>
      </div>
    </Shell>
  );
}
