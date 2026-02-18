import { NavLink } from "react-router-dom";
import ThemeToggle from "./ThemeToggle";

function Header() {
  return (
    <header className="header">
      <NavLink to="/" className="logo">
        <img src="/logo.svg" alt="Phish Guard Logo" className="logo-img" style={{ width: '40px', height: '40px' }} />
        <div className="logo-text-wrap">
          <span className="logo-text">Phish <span>Guard</span></span>
          <span className="logo-tagline">AI Phishing Detection</span>
        </div>
      </NavLink>

      <nav className="nav">
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

      <ThemeToggle />
    </header>
  );
}

export default Header;
