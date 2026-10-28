import { NavLink, Outlet } from "react-router-dom";

export default function Layout() {
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="mark">W</div>
          <div>
            <h1>WebSET</h1>
            <p>Local lab scanner</p>
          </div>
        </div>
        <nav>
          <NavLink to="/" end>
            Dashboard
          </NavLink>
          <NavLink to="/scan">New scan</NavLink>
          <NavLink to="/cases">Cases</NavLink>
          <NavLink to="/history">Scan history</NavLink>
        </nav>
        <div className="side-note">
          Scans are limited to authorised local targets (Juice Shop, DVWA, localhost).
          External URLs are rejected.
        </div>
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}

export function Severity({ value }) {
  return <span className={`badge ${value}`}>{value}</span>;
}

export function Status({ value }) {
  return <span className={`badge ${value}`}>{String(value).replaceAll("_", " ")}</span>;
}
