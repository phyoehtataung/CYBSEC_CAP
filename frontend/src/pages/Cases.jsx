import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

export default function Cases() {
  const [cases, setCases] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    api.cases().then((data) => setCases(data.cases)).catch((err) => setError(err.message));
  }, []);

  if (error) return <p className="error">{error}</p>;

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Case management</h2>
          <p className="lede">
            Each case groups scans of one application so you can compare runs over time. Profiles are
            stored with the case owner.
          </p>
        </div>
        <Link className="btn" to="/scan">
          Scan into a case
        </Link>
      </div>

      <div className="grid-2">
        {cases.map((item) => (
          <Link className="panel" to={`/cases/${item.case_id}`} key={item.case_id}>
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
        ))}
      </div>
    </>
  );
}
