import React from 'react';
import { Link, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';

export const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, isAdmin, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="header-left">
          <Link to="/targets" className="brand-logo">
            <span className="brand-shield">🛡️</span>
            <span className="brand-name">Aegis-Web</span>
            <span className="brand-tag">Access-Control Testing</span>
          </Link>
          <nav className="header-nav">
            <NavLink
              to="/targets"
              className={({ isActive }) => (isActive ? 'nav-item active' : 'nav-item')}
            >
              Targets
            </NavLink>
            {isAdmin && (
              <NavLink
                to="/admin/audit-log"
                className={({ isActive }) => (isActive ? 'nav-item active' : 'nav-item')}
              >
                Audit Log
              </NavLink>
            )}
          </nav>
        </div>

        <div className="header-right">
          {user && (
            <div className="user-profile">
              <span className="user-email">{user.email}</span>
              <span className={`user-role-badge role-${user.role}`}>{user.role}</span>
              <button onClick={handleLogout} className="btn-logout">
                Logout
              </button>
            </div>
          )}
        </div>
      </header>

      <main className="app-main">{children}</main>

      <footer className="app-footer">
        <div className="footer-content">
          <span>Aegis-Web v1.0.0 &bull; OWASP A01:2021 Access-Control Automation</span>
          <span className="footer-warning">Test authorized targets only. Verified read-access testing.</span>
        </div>
      </footer>
    </div>
  );
};
