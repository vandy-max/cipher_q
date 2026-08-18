import { useState } from "react";
import { useAuth } from "./hooks/useAuth";
import { MonitoringProvider } from "./context/MonitoringContext";
import AppShell from "./components/layout/AppShell";

import LandingPage from "./pages/LandingPage";
import LoginPage from "./pages/LoginPage";
import Dashboard from "./pages/Dashboard";
import CreateIntentPage from "./pages/CreateIntentPage";
import IntentHistoryPage from "./pages/IntentHistoryPage";
import BB84SimulationPage from "./pages/BB84SimulationPage";
import EncryptionPage from "./pages/EncryptionPage";
import DecryptionPage from "./pages/DecryptionPage";
import AuditLogsPage from "./pages/AuditLogsPage";
import PolicyManagementPage from "./pages/PolicyManagementPage";
import VisualizationPage from "./pages/VisualizationPage";
import ProfilePage from "./pages/ProfilePage";
import SettingsPage from "./pages/SettingsPage";
import FaceAuthTestPage from "./pages/FaceAuthTestPage";
import AdminDashboard from "./pages/AdminDashboard";

const PUBLIC_PAGES = ["landing", "login", "register"];

export default function App() {
  const { token, user, deviceId, sessionId, saveAuth, logout, isAuthenticated } = useAuth();
  const [page, setPage] = useState("landing");
  // Simple cross-page scratch state so e.g. Encrypt can hand off a
  // record_id to Decrypt, or Create Intent can hand off a CID.
  const [shared, setShared] = useState({});

  const navigate = (p, extra) => {
    if (!isAuthenticated && !PUBLIC_PAGES.includes(p)) {
      setPage("landing");
      return;
    }
    if (extra) setShared((prev) => ({ ...prev, ...extra }));
    setPage(p);
  };

  const showShell = isAuthenticated && !["landing", "login", "register"].includes(page);

  if (!showShell) {
    return (
      <div className="app-root">
        {page === "landing" && <LandingPage navigate={navigate} isAuthenticated={isAuthenticated} />}
        {(page === "login" || page === "register") && (
          <LoginPage
            mode={page}
            saveAuth={saveAuth}
            navigate={navigate}
            deviceId={deviceId}
            sessionId={sessionId}
          />
        )}
        {!PUBLIC_PAGES.includes(page) && (
          <LandingPage navigate={navigate} isAuthenticated={isAuthenticated} />
        )}
      </div>
    );
  }

  return (
    <MonitoringProvider user={user} deviceId={deviceId} sessionId={sessionId}>
      <AppShell page={page} navigate={navigate} user={user} logout={logout}>
        {page === "dashboard" && <Dashboard navigate={navigate} user={user} />}
        {page === "create-intent" && <CreateIntentPage navigate={navigate} shared={shared} />}
        {page === "intent-history" && <IntentHistoryPage navigate={navigate} shared={shared} />}
        {page === "bb84" && <BB84SimulationPage navigate={navigate} shared={shared} />}
        {page === "encrypt" && <EncryptionPage navigate={navigate} shared={shared} />}
        {page === "decrypt" && <DecryptionPage navigate={navigate} shared={shared} user={user} />}
        {page === "audit" && <AuditLogsPage navigate={navigate} />}
        {page === "policies" && <PolicyManagementPage navigate={navigate} />}
        {page === "visualize" && <VisualizationPage navigate={navigate} />}
        {page === "settings" && <SettingsPage navigate={navigate} user={user} />}
        {page === "profile" && <ProfilePage navigate={navigate} user={user} />}
        {page === "face-test" && <FaceAuthTestPage navigate={navigate} />}
        {page === "admin" && <AdminDashboard user={user} />}
      </AppShell>
    </MonitoringProvider>
  );
}
