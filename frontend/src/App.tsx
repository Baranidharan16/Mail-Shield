import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/Layout";
import DashboardPage from "./pages/DashboardPage";
import UploadPage from "./pages/UploadPage";
import HistoryPage from "./pages/HistoryPage";
import InvestigationDetailPage from "./pages/InvestigationDetailPage";
import AlertsPage from "./pages/AlertsPage";
import EvidenceVaultPage from "./pages/EvidenceVaultPage";
import IntegrityLedgerPage from "./pages/IntegrityLedgerPage";
import { CampaignsPage } from "./pages/CampaignsPage";
import { PerformancePage } from "./pages/PerformancePage";
import { PrivacyPage } from "./pages/PrivacyPage";
import LoginPage from "./pages/LoginPage";
import RegisterPage from "./pages/RegisterPage";
import ProfilePage from "./pages/ProfilePage";
import ProtectedRoute from "./components/ProtectedRoute";
import { ChatProvider } from "./context/ChatContext";
import { AuthProvider } from "./context/AuthContext";

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <ChatProvider>
          <Routes>
            {/* Public Authentication Routes */}
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />

            {/* Protected MailShield Workspaces */}
            <Route element={<ProtectedRoute />}>
              <Route element={<Layout />}>
                {/* Core */}
                <Route path="/" element={<DashboardPage />} />
                <Route path="/dashboard" element={<DashboardPage />} />
                <Route path="/upload" element={<UploadPage />} />
                <Route path="/history" element={<HistoryPage />} />
                <Route path="/case-history" element={<HistoryPage />} />
                <Route path="/investigations" element={<HistoryPage />} />
                <Route path="/investigations/:id" element={<InvestigationDetailPage />} />

                {/* SOC Threat Center */}
                <Route path="/alerts" element={<AlertsPage />} />
                <Route path="/soc" element={<AlertsPage />} />
                <Route path="/campaigns" element={<CampaignsPage />} />

                {/* Evidence & Forensics */}
                <Route path="/evidence" element={<EvidenceVaultPage />} />
                <Route path="/evidence-vault" element={<EvidenceVaultPage />} />
                <Route path="/ledger" element={<IntegrityLedgerPage />} />
                <Route path="/privacy" element={<PrivacyPage />} />

                {/* User Profile & System Telemetry */}
                <Route path="/profile" element={<ProfilePage />} />
                <Route path="/system/performance" element={<PerformancePage />} />
                <Route path="/performance" element={<PerformancePage />} />
                <Route path="/reports" element={<HistoryPage />} />
                <Route path="/settings" element={<ProfilePage />} />

                {/* Fallback Catch-All */}
                <Route path="*" element={<Navigate to="/" replace />} />
              </Route>
            </Route>
          </Routes>
        </ChatProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
