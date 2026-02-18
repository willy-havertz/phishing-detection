import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { useState, useEffect, useRef } from "react";
import { AuthProvider, useAuth } from "./context/AuthContext";
import Header from "./components/Header";
import Footer from "./components/Footer";
import Scanner from "./pages/Scanner";
import Dashboard from "./pages/Dashboard";
import History from "./pages/History";
import Education from "./pages/Education";
import Login from "./pages/Login";
import { startSmsListener } from "./utils/smsListener";

// ---- SMS Toast Notification ----
function SmsToast({ toasts, onDismiss }) {
  if (!toasts.length) return null;
  const riskColor = { phishing: "#DC2626", suspicious: "#D97706", safe: "#059669" };
  const riskEmoji = { phishing: "🚨", suspicious: "⚠️", safe: "✅" };
  return (
    <div className="sms-toast-container">
      {toasts.map((t) => (
        <div key={t.id} className={`sms-toast sms-toast-${t.classification}`}>
          <div className="sms-toast-icon">{riskEmoji[t.classification] || "📱"}</div>
          <div className="sms-toast-body">
            <div className="sms-toast-title">
              New SMS {t.classification === "phishing" ? "THREAT" : t.classification === "suspicious" ? "WARNING" : "Scanned"}
            </div>
            <div className="sms-toast-from">From: {t.sender}</div>
            <div className="sms-toast-preview">{t.content_preview}</div>
          </div>
          <button className="sms-toast-close" onClick={() => onDismiss(t.id)}>✕</button>
          <div
            className="sms-toast-bar"
            style={{ background: riskColor[t.classification] || "#6B7280" }}
          />
        </div>
      ))}
    </div>
  );
}

// Protected Route Component
function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="loading-screen">
        <div className="loading-spinner"></div>
        <p>Loading...</p>
      </div>
    );
  }
  return user ? children : <Navigate to="/login" />;
}

// Public Route Component (redirect to home if already logged in)
function PublicRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="loading-screen">
        <div className="loading-spinner"></div>
        <p>Loading...</p>
      </div>
    );
  }
  return user ? <Navigate to="/" /> : children;
}

let toastIdCounter = 0;

function AppContent() {
  const { user } = useAuth();
  const [toasts, setToasts] = useState([]);
  const unsubRef = useRef(null);

  // Start SMS listener when user logs in, stop when logs out
  useEffect(() => {
    if (unsubRef.current) {
      unsubRef.current();
      unsubRef.current = null;
    }
    if (!user) return;

    unsubRef.current = startSmsListener(user.uid, (scan) => {
      const id = ++toastIdCounter;
      setToasts((prev) => [...prev, { ...scan, id }]);
      // Auto-dismiss after 8 seconds
      setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 8000);
    });

    return () => {
      if (unsubRef.current) unsubRef.current();
    };
  }, [user]);

  const dismissToast = (id) => setToasts((prev) => prev.filter((t) => t.id !== id));

  return (
    <div className="app">
      <Header />
      <main className="main-content">
        <Routes>
          <Route path="/login" element={<PublicRoute><Login /></PublicRoute>} />
          <Route path="/" element={<ProtectedRoute><Scanner /></ProtectedRoute>} />
          <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/history" element={<ProtectedRoute><History /></ProtectedRoute>} />
          <Route path="/education" element={<ProtectedRoute><Education /></ProtectedRoute>} />
        </Routes>
      </main>
      <Footer />
      <SmsToast toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
