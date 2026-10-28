import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

export default function Cases() {
  const [cases, setCases] = useState([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.cases().then((data) => setCases(data.cases)).catch((err) => setError(err.message));
  }, []);

  async function remove(item) {
    if (!window.confirm(`Delete case ${item.case_id} and all of its scans?`)) return;
    setBusy(true);
    setError("");
    try {
      await api.deleteCase(item.case_id);
      setCases((current) => current.filter((row) => row.case_id !== item.case_id));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  if (error && cases.length === 0) return <p className="error">{error}</p>;

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Case management</h2>
          <p className="lede">
            Each case groups scans of one application so you can compare runs over time. Edit or delete
            a case from its detail page or here.
          </p>
        </div>
        <Link className="btn" to="/scan">
          Scan into a case
        </Link>
      </div>

      {error && <div className="error">{error}</div>}

      <div className="grid-2">
        {cases.map((item) => (
          <article className="panel" key={item.case_id}>
            <Link to={`/cases/${item.case_id}`}>
              <h3>{item.case_id}</h3>
              <h2 style={{ fontFamily: "Newsreader, serif", fontSize: 28, margin: "0 0 8px" }}>
                {item.title}
              </h2>
              <p className="lede">
                {item.application} · {item.owner.name} ({item.owner.role}) · {item.scan_count} scans
              </p>
              <div className="chips">
                <span className="chip">Critical {item.totals.critical}</span>
                <span className="chip">High {item.totals.high}</span>
                <span className="chip">Total {item.totals.total}</span>
              </div>
            </Link>
            <div className="actions" style={{ marginTop: 14 }}>
              <Link className="btn secondary" to={`/cases/${item.case_id}`}>
                Open
              </Link>
              <button className="btn danger" type="button" disabled={busy} onClick={() => remove(item)}>
                Delete
              </button>
            </div>
          </article>
        ))}
      </div>
    </>
  );
}
