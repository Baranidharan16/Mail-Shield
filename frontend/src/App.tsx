import { BrowserRouter, Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import DashboardPage from "./pages/DashboardPage";
import UploadPage from "./pages/UploadPage";
import HistoryPage from "./pages/HistoryPage";
import InvestigationDetailPage from "./pages/InvestigationDetailPage";
import AlertsPage from "./pages/AlertsPage";
import EvidenceVaultPage from "./pages/EvidenceVaultPage";
import IntegrityLedgerPage from "./pages/IntegrityLedgerPage";
import { ChatProvider } from "./context/ChatContext";

export default function App() {
  return (
    <BrowserRouter>
      <ChatProvider>
        <Routes>
          <Route element={<Layout />}>

          {/* Core */}
          <Route path="/" element={<DashboardPage />} />
          <Route path="/upload" element={<UploadPage />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/investigations/:id" element={<InvestigationDetailPage />} />
          {/* SOC */}
          <Route path="/alerts" element={<AlertsPage />} />
          {/* Evidence */}
          <Route path="/evidence-vault" element={<EvidenceVaultPage />} />
          <Route path="/ledger" element={<IntegrityLedgerPage />} />
          {/* Alias */}
          <Route path="/reports" element={<HistoryPage />} />
          <Route path="/settings" element={<DashboardPage />} />
        </Route>
      </Routes>
      </ChatProvider>
    </BrowserRouter>
  );
}
