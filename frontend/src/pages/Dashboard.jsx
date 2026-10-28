import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { Severity, Status } from "../components/Layout";

const SEV = ["critical", "high", "medium", "low", "info"];

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.dashboard().then(setData).catch((err) => setError(err.message));
  }, []);

  if (error) return <p className="error">{error}</p>;
  if (!data) return <p className="lede">Loading dashboard…</p>;

  const maxSev = Math.max(1, ...SEV.map((k) => data.severity[k] || 0));
  const maxTrend = Math.max(1, ...data.trend.map((t) => t.total || 0));

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Security evaluation overview</h2>
          <p className="lede">
            Findings from authorised local labs, mapped to OWASP Top 10 with NIST and SANS references.
            Seeded history is already in the case database so the dashboard is useful before the first live scan.
          </p>
        </div>
        <Link className="btn" to="/scan">
          Run a scan
        </Link>
      </div>

      <section className="stats">
        <div className="stat">
          <span>Cases</span>
          <strong>{data.totals.cases}</strong>
        </div>
        <div className="stat">
          <span>Scans conducted</span>
          <strong>{data.totals.scans}</strong>
        </div>
        <div className="stat">
          <span>Findings stored</span>
          <strong>{data.totals.findings}</strong>
        </div>
        <div className="stat">
          <span>Critical</span>
          <strong>{data.totals.open_critical}</strong>
        </div>
      </section>

      <div className="grid-2">
        <section className="panel">
          <h3>Severity breakdown</h3>
          {SEV.map((level) => (
            <div className="bar-row" key={level}>
              <span>{level}</span>
              <div className={`bar ${level}`}>
                <i style={{ width: `${((data.severity[level] || 0) / maxSev) * 100}%` }} />
              </div>
              <b>{data.severity[level] || 0}</b>
            </div>
          ))}
        </section>
        <section className="panel">
          <h3>Finding trend</h3>
          <div className="trend">
            {data.trend.length === 0 && <p className="lede">No completed scans yet.</p>}
            {data.trend.map((point) => (
              <div
                className="col"
                key={point.scan_id}
                style={{ height: `${(point.total / maxTrend) * 100}%` }}
                title={`${point.target_name}: ${point.total} findings`}
              >
                <span>{point.total}</span>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="panel" style={{ marginTop: 14 }}>
        <h3>Most scanned stacks</h3>
        <div className="chips">
          {data.tech_stacks.map((stack) => (
            <div className="chip" key={stack.name}>
              {stack.name} · {stack.scans}
            </div>
          ))}
        </div>
      </section>

      <section className="panel" style={{ marginTop: 14 }}>
        <h3>OWASP category hits</h3>
        <div className="chips">
          {data.owasp.map((row) => (
            <div className="chip" key={row.id}>
              {row.id} · {row.count}
            </div>
          ))}
        </div>
      </section>

      <section className="panel" style={{ marginTop: 14 }}>
        <h3>Recent scans</h3>
        <table>
          <thead>
            <tr>
              <th>Scan</th>
              <th>Target</th>
              <th>Status</th>
              <th>Findings</th>
              <th>Critical</th>
            </tr>
          </thead>
          <tbody>
            {data.recent_scans.map((scan) => (
              <tr className="clickable" key={scan.scan_id}>
                <td>
                  <Link to={`/scans/${scan.scan_id}`}>{scan.scan_id}</Link>
                  <div className="mono">{scan.started_at}</div>
                </td>
                <td>{scan.target_name}</td>
                <td>
                  <Status value={scan.status} />
                </td>
                <td>{scan.summary?.total ?? "—"}</td>
                <td>
                  <Severity value="critical" /> {scan.summary?.critical ?? 0}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}
