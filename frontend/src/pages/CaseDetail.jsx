import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { Status } from "../components/Layout";

export default function CaseDetail() {
  const { caseId } = useParams();
  const [item, setItem] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.case(caseId).then(setItem).catch((err) => setError(err.message));
  }, [caseId]);

  if (error) return <p className="error">{error}</p>;
  if (!item) return <p className="lede">Loading case…</p>;

  const max = Math.max(1, ...item.scans.map((s) => s.summary?.total || 0));

  return (
    <>
      <div className="page-head">
        <div>
          <h2>{item.title}</h2>
          <p className="lede">
            {item.case_id} · Owner {item.owner.name} ({item.owner.email}) · {item.application}
          </p>
        </div>
        <Link className="btn" to="/scan">
          New scan
        </Link>
      </div>
      <p className="lede" style={{ marginBottom: 18 }}>
        {item.notes}
      </p>

      <section className="panel" style={{ marginBottom: 14 }}>
        <h3>Trend across scans in this case</h3>
        <div className="trend">
          {item.scans
            .slice()
            .reverse()
            .map((scan) => (
              <div
                className="col"
                key={scan.scan_id}
                style={{ height: `${((scan.summary?.total || 0) / max) * 100}%` }}
              >
                <span>{scan.summary?.total || 0}</span>
              </div>
            ))}
        </div>
      </section>

      <section className="panel">
        <h3>Scan history</h3>
        <table>
          <thead>
            <tr>
              <th>Scan ID</th>
              <th>Started</th>
              <th>Status</th>
              <th>Findings</th>
              <th>Critical</th>
            </tr>
          </thead>
          <tbody>
            {item.scans.map((scan) => (
              <tr key={scan.scan_id}>
                <td>
                  <Link to={`/scans/${scan.scan_id}`}>{scan.scan_id}</Link>
                </td>
                <td className="mono">{scan.started_at}</td>
                <td>
                  <Status value={scan.status} />
                </td>
                <td>{scan.summary?.total ?? "—"}</td>
                <td>{scan.summary?.critical ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}
