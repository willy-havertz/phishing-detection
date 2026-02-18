import { useState, useEffect } from "react";
import { NavLink, useLocation } from "react-router-dom";
import ThemeToggle from "./ThemeToggle";

function Header() {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const location = useLocation();

  // Close sidebar on navigation
  useEffect(() => {
    setIsSidebarOpen(false);
  }, [location]);

  return (
    <>
      <header className="header">
        <NavLink to="/" className="logo">
          <img src="/logo.svg" alt="Phish Guard Logo" className="logo-img" style={{ width: '40px', height: '40px' }} />
          <div className="logo-text-wrap">
            <span className="logo-text">Phish <span>Guard</span></span>
            <span className="logo-tagline">AI Phishing Detection</span>
          </div>
        </NavLink>

        <nav className="nav desktop-nav">
          <NavLink to="/" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
            <i className="nav-icon fas fa-search"></i>
            <span className="nav-label">Scan</span>
          </NavLink>
          <NavLink to="/dashboard" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
            <i className="nav-icon fas fa-chart-pie"></i>
            <span className="nav-label">Dashboard</span>
          </NavLink>
          <NavLink to="/history" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
            <i className="nav-icon fas fa-history"></i>
            <span className="nav-label">History</span>
          </NavLink>
          <NavLink to="/education" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
            <i className="nav-icon fas fa-graduation-cap"></i>
            <span className="nav-label">Learn</span>
          </NavLink>
        </nav>

        <div className="header-actions">
          <ThemeToggle />
          <button className="menu-toggle" onClick={() => setIsSidebarOpen(true)}>
            <i className="fas fa-bars"></i>
          </button>
        </div>
      </header>

      {/* Mobile Sidebar Overlay */}
      <div className={`sidebar-overlay ${isSidebarOpen ? "open" : ""}`} onClick={() => setIsSidebarOpen(false)}></div>
      
      {/* Mobile Sidebar Content */}
      <aside className={`mobile-sidebar ${isSidebarOpen ? "open" : ""}`}>
        <div className="sidebar-header">
          <div className="logo sidebar-logo">
            <img src="/logo.svg" alt="Phish Guard Logo" style={{ width: '32px' }} />
            <span className="logo-text">Phish <span>Guard</span></span>
          </div>
          <button className="sidebar-close" onClick={() => setIsSidebarOpen(false)}>
            <i className="fas fa-times"></i>
          </button>
        </div>

        <nav className="mobile-nav">
          <NavLink to="/" className={({ isActive }) => `sidebar-link ${isActive ? "active" : ""}`}>
            <i className="fas fa-search"></i>
            <span>Scan Engine</span>
          </NavLink>
          <NavLink to="/dashboard" className={({ isActive }) => `sidebar-link ${isActive ? "active" : ""}`}>
            <i className="fas fa-chart-pie"></i>
            <span>Threat Dashboard</span>
          </NavLink>
          <NavLink to="/history" className={({ isActive }) => `sidebar-link ${isActive ? "active" : ""}`}>
            <i className="fas fa-history"></i>
            <span>Scan History</span>
          </NavLink>
          <NavLink to="/education" className={({ isActive }) => `sidebar-link ${isActive ? "active" : ""}`}>
            <i className="fas fa-graduation-cap"></i>
            <span>Education Hub</span>
          </NavLink>
        </nav>

        <div className="sidebar-footer">
          <p>Phish Guard v3.0</p>
          <p>Stay Safe & Vigilant</p>
        </div>
      </aside>
    </>
  );
}

export default Header;

