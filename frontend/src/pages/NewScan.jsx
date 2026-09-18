import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";

export default function NewScan() {
  const navigate = useNavigate();
  const [cases, setCases] = useState([]);
  const [targets, setTargets] = useState([]);
  const [caseId, setCaseId] = useState("");
  const [target, setTarget] = useState(null);
  const [customUrl, setCustomUrl] = useState("http://localhost:3000");
  const [title, setTitle] = useState("");
  const [application, setApplication] = useState("OWASP Juice Shop");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    Promise.all([api.cases(), api.targets()])
      .then(([caseData, targetData]) => {
        setCases(caseData.cases);
        setTargets(targetData.targets);
        if (caseData.cases[0]) setCaseId(caseData.cases[0].case_id);
        if (targetData.targets[0]) setTarget(targetData.targets[0]);
      })
      .catch((err) => setError(err.message));
  }, []);

  async function createCase(event) {
    event.preventDefault();
    setError("");
    try {
      const created = await api.createCase({ title, application, notes: "Created from the demo UI" });
      setCases((current) => [created, ...current]);
      setCaseId(created.case_id);
      setCreating(false);
      setTitle("");
    } catch (err) {
      setError(err.message);
    }
  }

  async function start(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const selected = target;
      const payload = {
        case_id: caseId,
        target_id: selected?.id || null,
        target_name: selected?.name || "Local lab target",
        target_url: selected ? selected.url : customUrl,
      };
      if (!selected) payload.target_url = customUrl;
      const scan = await api.startScan(payload);
      navigate(`/scans/${scan.scan_id}`);
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h2>New evaluation scan</h2>
          <p className="lede">
            Choose a case, then point the engine at Juice Shop or DVWA. The scanner runs static analysis
            on cloned lab sources (when present) and a non-exploit crawl of the live local target.
          </p>
        </div>
      </div>

      <div className="warn">
        WebSET will refuse any host that is not localhost or a Docker lab name. Do not use this tool
        against systems you do not own or do not have written permission to test.
      </div>
      {error && <div className="error">{error}</div>}

      <form className="form" onSubmit={start}>
        <label>
          Case
          <select value={caseId} onChange={(e) => setCaseId(e.target.value)} required>
            {cases.map((item) => (
              <option key={item.case_id} value={item.case_id}>
                {item.case_id} — {item.title}
              </option>
            ))}
          </select>
        </label>
        <button type="button" className="btn secondary" onClick={() => setCreating((v) => !v)}>
          {creating ? "Cancel new case" : "Create another case"}
        </button>
        {creating && (
          <div className="panel">
            <label>
              Case title
              <input value={title} onChange={(e) => setTitle(e.target.value)} required />
            </label>
            <label>
              Application
              <input value={application} onChange={(e) => setApplication(e.target.value)} />
            </label>
            <button type="button" className="btn" onClick={createCase}>
              Save case
            </button>
          </div>
        )}

        <div className="targets">
          {targets.map((item) => (
            <button
              type="button"
              className={`target ${target?.id === item.id ? "selected" : ""}`}
              key={item.id}
              onClick={() => setTarget(item)}
            >
              <b>{item.name}</b>
              <span>
                {item.url} · {item.stack.join(", ")}
              </span>
            </button>
          ))}
          <button
            type="button"
            className={`target ${target === null ? "selected" : ""}`}
            onClick={() => setTarget(null)}
          >
            <b>Custom localhost URL</b>
            <span>Still must be an allow-listed local host and port</span>
          </button>
        </div>

        {target === null && (
          <label>
            Target URL
            <input value={customUrl} onChange={(e) => setCustomUrl(e.target.value)} />
          </label>
        )}

        <button className="btn" disabled={busy || !caseId}>
          {busy ? "Starting…" : "Start scan"}
        </button>
      </form>
    </>
  );
}
