import { NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

function Header() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      await logout();
      navigate("/login");
    } catch (error) {
      console.error("Logout failed:", error);
    }
  };

  return (
    <header className="header">
      <NavLink to="/" className="logo">
        <svg className="logo-icon" viewBox="0 0 24 24" fill="#ACC8A2">
          <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z" />
        </svg>
        <div className="logo-text-wrap">
          <span className="logo-text">Threat<span>Lens</span></span>
          <span className="logo-tagline">AI Phishing Detection</span>
        </div>
      </NavLink>

      {user && (
        <>
          <nav className="nav">
            <NavLink to="/" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
              <span className="nav-icon">🔍</span>
              <span className="nav-label">Scan</span>
            </NavLink>
            <NavLink to="/dashboard" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
              <span className="nav-icon">📊</span>
              <span className="nav-label">Dashboard</span>
            </NavLink>
            <NavLink to="/history" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
              <span className="nav-icon">📋</span>
              <span className="nav-label">History</span>
            </NavLink>
            <NavLink to="/education" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
              <span className="nav-icon">📚</span>
              <span className="nav-label">Learn</span>
            </NavLink>
          </nav>

          <div className="user-menu">
            <div className="user-info">
              <span className="user-icon">👤</span>
              <span className="user-name">{user.displayName || user.email}</span>
            </div>
            <button onClick={handleLogout} className="logout-btn">
              Logout
            </button>
          </div>
        </>
      )}
    </header>
  );
}

export default Header;
