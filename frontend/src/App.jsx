import React, { useEffect, useState } from "react";
import { NavLink, Route, Routes, useLocation } from "react-router-dom";
import {
  Bell,
  Boxes,
  ChevronRight,
  Database as DatabaseIcon,
  FolderKanban,
  LayoutDashboard,
  Network,
  ShieldAlert,
  ShieldCheck,
  Table2,
  Terminal,
  Users as UsersIcon,
} from "lucide-react";
import api from "./services/api.js";
import Dashboard from "./pages/Dashboard.jsx";
import Projects from "./pages/Projects.jsx";
import ProjectDetail from "./pages/ProjectDetail.jsx";
import Packages from "./pages/Packages.jsx";
import Vulnerabilities from "./pages/Vulnerabilities.jsx";
import Alerts from "./pages/Alerts.jsx";
import Analytics from "./pages/Analytics.jsx";
import Database from "./pages/Database.jsx";
import Graph from "./pages/Graph.jsx";
import Users from "./pages/Users.jsx";
import Login from "./pages/Login.jsx";
import { useAuth } from "./context/AuthContext.jsx";

const monitoring = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/projects", label: "Projects", icon: FolderKanban },
  { to: "/packages", label: "Packages", icon: Boxes },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert },
  { to: "/alerts", label: "Alert center", icon: Bell },
];
const insights = [
  { to: "/analytics", label: "Analytics", icon: Table2 },
  { to: "/database", label: "Database", icon: DatabaseIcon },
];
const intelligence = [
  { to: "/graph", label: "Dependency graph", icon: Network },
];
const allNav = [...monitoring, ...intelligence, ...insights];

function NavGroup({ label, items }) {
  return (
    <>
      <div className="nav-label">{label}</div>
      <nav>
        {items.map(({ to, label: text, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}
          >
            <Icon size={17} />
            <span>{text}</span>
            {text === "Alert center" && (
              <span className="nav-arrow">
                <ChevronRight size={14} />
              </span>
            )}
          </NavLink>
        ))}
      </nav>
    </>
  );
}

export default function App() {
  const location = useLocation();
  const { user, loading: authLoading, logout } = useAuth();
  const [apiState, setApiState] = useState("checking");
  useEffect(() => {
    api
      .get("/health")
      .then(({ data }) =>
        setApiState(
          data.databases?.neo4j?.status === "connected"
            ? "connected"
            : "degraded",
        ),
      )
      .catch(() => setApiState("offline"));
  }, []);

  const visibleNav =
    user?.role === "admin"
      ? [...allNav, { to: "/users", label: "Users", icon: UsersIcon }]
      : allNav.filter((item) => item.to !== "/database");
  const visibleInsights =
    user?.role === "admin"
      ? insights
      : insights.filter((item) => item.to !== "/database");
  const current = visibleNav.find((n) =>
    n.end ? location.pathname === n.to : location.pathname.startsWith(n.to),
  );
  const pageTitle = current?.label || "Security console";

  if (authLoading) return <div className="auth-loading">Loading SDVIT…</div>;
  if (!user) return <Login />;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={23} />
          </div>
          <div>
            <strong>
              SDVIT<span>.</span>
            </strong>
            <small>SECURITY INTELLIGENCE</small>
          </div>
        </div>
        <div className="workspace-label">WORKSPACE</div>
        <div className="workspace-card">
          <div className="workspace-icon">
            <Terminal size={17} />
          </div>
          <div>
            <strong>Security operations</strong>
            <small>Dependency monitoring</small>
          </div>
          <span className="workspace-dot" />
        </div>
        <NavGroup label="MONITORING" items={monitoring} />
        <NavGroup label="INTELLIGENCE" items={intelligence} />
        <NavGroup label="INSIGHTS" items={visibleInsights} />
        {user.role === "admin" && (
          <NavGroup
            label="ADMINISTRATION"
            items={[{ to: "/users", label: "Users", icon: UsersIcon }]}
          />
        )}
        <div className="sidebar-bottom">
          <div className="system-status">
            <span className={`connection-dot ${apiState}`} />
            <div>
              <strong>
                {apiState === "connected"
                  ? "MySQL + Neo4j connected"
                  : apiState === "degraded"
                    ? "Neo4j unavailable"
                    : apiState === "offline"
                      ? "API unavailable"
                      : "Checking API"}
              </strong>
              <small>
                {apiState === "connected"
                  ? "Both database connections passed"
                  : "Check backend and database services"}
              </small>
            </div>
          </div>
          <div className="sidebar-foot">
            <ShieldCheck size={15} /> SDVIT Console <span>v2.0</span>
          </div>
        </div>
      </aside>
      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumbs">
            <span>SDVIT</span>
            <ChevronRight size={14} />
            <strong>{pageTitle}</strong>
          </div>
          <div className="topbar-right">
            <span className="environment">
              <span /> LOCAL ENVIRONMENT
            </span>
            <div className="topbar-divider" />
            <div className="topbar-user">
              <div className="avatar">
                {user.name.slice(0, 1).toUpperCase()}
              </div>
              <div className="topbar-identity">
                <strong>{user.name}</strong>
                <small>{user.role}</small>
              </div>
              <button
                className="button button-small button-secondary"
                onClick={logout}
              >
                Sign out
              </button>
            </div>
          </div>
        </header>
        <div className="page-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/projects" element={<Projects />} />
            <Route path="/projects/:id" element={<ProjectDetail />} />
            <Route path="/packages" element={<Packages />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/graph" element={<Graph />} />
            <Route
              path="/users"
              element={user.role === "admin" ? <Users /> : <Dashboard />}
            />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route
              path="/database"
              element={user.role === "admin" ? <Database /> : <Dashboard />}
            />
            <Route path="*" element={<Dashboard />} />
          </Routes>
          <footer className="footer">
            <span>
              SDVIT <span className="footer-dot">/</span> Software Dependency
              Vulnerability & Impact Tracking
            </span>
            <span>
              <span className="connection-dot connected" /> Local
              database-backed view
            </span>
          </footer>
        </div>
      </main>
    </div>
  );
}
