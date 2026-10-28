import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { Status } from "../components/Layout";

export default function History() {
  const [scans, setScans] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    api.scans().then((data) => setScans(data.scans)).catch((err) => setError(err.message));
  }, []);

  if (error) return <p className="error">{error}</p>;

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Scan history</h2>
          <p className="lede">Every scan stored in the case database, newest first.</p>
        </div>
      </div>
      <section className="panel">
        <table>
          <thead>
            <tr>
              <th>Scan ID</th>
              <th>Case</th>
              <th>Target</th>
              <th>Status</th>
              <th>Findings</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => (
              <tr key={scan.scan_id}>
                <td>
                  <Link to={`/scans/${scan.scan_id}`}>{scan.scan_id}</Link>
                  <div className="mono">{scan.started_at}</div>
                </td>
                <td>
                  <Link to={`/cases/${scan.case_id}`}>{scan.case_id}</Link>
                </td>
                <td>
                  {scan.target_name}
                  <div className="mono">{scan.target_url}</div>
                </td>
                <td>
                  <Status value={scan.status} />
                </td>
                <td>{scan.summary?.total ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}
