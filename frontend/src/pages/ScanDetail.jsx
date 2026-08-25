import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { Severity, Status } from "../components/Layout";

const SEV = ["critical", "high", "medium", "low", "info"];

export default function ScanDetail() {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("all");
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    let timer;
    let cancelled = false;

    async function load() {
      try {
        const data = await api.scan(scanId);
        if (cancelled) return;
        setScan(data);
        if (data.status === "queued" || data.status === "running") {
          timer = setTimeout(load, 700);
        }
      } catch (err) {
        if (!cancelled) setError(err.message);
      }
    }

    load();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [scanId]);

  const findings = scan?.findings || [];
  const visible = useMemo(
    () => (filter === "all" ? findings : findings.filter((f) => f.severity === filter)),
    [findings, filter]
  );

  if (error) return <p className="error">{error}</p>;
  if (!scan) return <p className="lede">Loading scan…</p>;

  const running = scan.status === "queued" || scan.status === "running";
  const summary = scan.summary || {};

  return (
    <>
      <div className="page-head">
        <div>
          <h2>{scan.target?.name || scan.target_name}</h2>
          <p className="lede">
            Scan <span className="mono">{scan.scan_id}</span> · Case{" "}
            <Link to={`/cases/${scan.case_id}`}>{scan.case_id}</Link> · {scan.target?.url || scan.target_url}
          </p>
        </div>
        <div className="actions">
          <a className="btn" href={api.reportHtmlUrl(scan.scan_id)}>
            Export HTML
          </a>
          <a className="btn secondary" href={api.reportJsonUrl(scan.scan_id)}>
            Export JSON
          </a>
        </div>
      </div>

      <div className="chips" style={{ marginBottom: 16 }}>
        <Status value={scan.status} />
        {(scan.scanner?.modes || []).map((mode) => (
          <span className="chip" key={mode}>
            {mode}
          </span>
        ))}
        {(scan.tech_stack || []).map((item) => (
          <span className="chip" key={item.name}>
            {item.name}
          </span>
        ))}
      </div>

      {running && (
        <section className="panel" style={{ marginBottom: 14 }}>
          <h3>{scan.message || "Running"}</h3>
          <div className="progress">
            <i style={{ width: `${scan.progress || 5}%` }} />
          </div>
          <div className="mono">{scan.progress || 0}%</div>
        </section>
      )}

      {scan.live_check && !scan.live_check.reachable && (
        <div className="warn">
          Live target was not reachable. Catalog findings for this lab profile were still recorded so
          the demo stays usable without Docker. Start Juice Shop / DVWA with docker compose to include
          live header evidence.
        </div>
      )}

      <section className="stats">
        {SEV.map((level) => (
          <div className="stat" key={level}>
            <span>{level}</span>
            <strong>{summary[level] ?? 0}</strong>
          </div>
        ))}
      </section>

      {scan.coverage?.owasp && (
        <section className="panel" style={{ marginBottom: 14 }}>
          <h3>OWASP Top 10 coverage</h3>
          <p className="lede" style={{ marginBottom: 12 }}>
            {scan.coverage.notes}
          </p>
          <div className="coverage">
            {scan.coverage.owasp.map((row) => (
              <div className="cov" key={row.id}>
                <small>{row.id}</small>
                <b>{row.name}</b>
                <span className={`pill ${row.status}`}>{row.status.replaceAll("_", " ")}</span>
              </div>
            ))}
          </div>
        </section>
      )}

      <section className="panel">
        <h3>Findings</h3>
        <div className="chips" style={{ marginBottom: 12 }}>
          <button className="btn secondary" type="button" onClick={() => setFilter("all")}>
            All
          </button>
          {SEV.map((level) => (
            <button className="btn secondary" type="button" key={level} onClick={() => setFilter(level)}>
              {level}
            </button>
          ))}
        </div>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Title</th>
              <th>Severity</th>
              <th>OWASP</th>
              <th>Type</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((finding) => (
              <tr className="clickable" key={finding.finding_id} onClick={() => setSelected(finding)}>
                <td className="mono">{finding.finding_id}</td>
                <td>{finding.title}</td>
                <td>
                  <Severity value={finding.severity} />
                </td>
                <td>
                  {finding.owasp.id}
                  <div className="mono">{finding.owasp.name}</div>
                </td>
                <td>{finding.detection_type}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {selected && (
        <div className="drawer-back" onClick={() => setSelected(null)}>
          <aside className="drawer" onClick={(event) => event.stopPropagation()}>
            <span className="mono">{selected.finding_id}</span>
            <h3>{selected.title}</h3>
            <Severity value={selected.severity} />
            <div className="kv">
              <span>OWASP</span>
              <b>
                {selected.owasp.id} {selected.owasp.name}
              </b>
              <span>NIST</span>
              <b>{selected.nist || "—"}</b>
              <span>SANS / CWE</span>
              <b>
                {selected.sans || "—"} · {selected.cwe || "—"}
              </b>
              <span>Location</span>
              <b>{selected.location || "—"}</b>
              <span>Confidence</span>
              <b>{selected.confidence}</b>
            </div>
            <p>{selected.description}</p>
            {selected.evidence && (
              <p>
                <b>Evidence.</b> {selected.evidence}
              </p>
            )}
            <p>
              <b>Recommendation.</b> {selected.recommendation}
            </p>
            <button className="btn secondary" onClick={() => setSelected(null)}>
              Close
            </button>
          </aside>
        </div>
      )}
    </>
  );
}
