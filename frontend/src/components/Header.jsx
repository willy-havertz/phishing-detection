import { NavLink } from "react-router-dom";

function Header() {
  return (
    <header className="header">
      <NavLink to="/" className="logo">
        <svg className="logo-icon" viewBox="0 0 24 24" fill="#ACC8A2">
          <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z" />
        </svg>
        <span className="logo-text">
          Threat<span>Lens</span>
        </span>
      </NavLink>

      <nav className="nav">
        <NavLink
          to="/"
          className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}
        >
          🔍 Scan
        </NavLink>
        <NavLink
          to="/dashboard"
          className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}
        >
          📊 Dashboard
        </NavLink>
        <NavLink
          to="/history"
          className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}
        >
          📋 History
        </NavLink>
        <NavLink
          to="/education"
          className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}
        >
          📚 Learn
        </NavLink>
      </nav>
    </header>
  );
}

export default Header;
