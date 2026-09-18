import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api";
import { Status } from "../components/Layout";

export default function CaseDetail() {
  const { caseId } = useParams();
  const navigate = useNavigate();
  const [item, setItem] = useState(null);
  const [users, setUsers] = useState([]);
  const [error, setError] = useState("");
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ title: "", application: "", notes: "", owner_id: "" });

  useEffect(() => {
    Promise.all([api.case(caseId), api.users()])
      .then(([caseData, userData]) => {
        setItem(caseData);
        setUsers(userData.users || []);
        setForm({
          title: caseData.title,
          application: caseData.application,
          notes: caseData.notes || "",
          owner_id: caseData.owner.id,
        });
      })
      .catch((err) => setError(err.message));
  }, [caseId]);

  async function save(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const updated = await api.updateCase(caseId, form);
      setItem(updated);
      setEditing(false);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!window.confirm(`Delete case ${caseId} and all of its scans?`)) return;
    setBusy(true);
    try {
      await api.deleteCase(caseId);
      navigate("/cases");
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  }

  if (error && !item) return <p className="error">{error}</p>;
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
        <div className="actions">
          <button className="btn secondary" type="button" onClick={() => setEditing((value) => !value)}>
            {editing ? "Close editor" : "Edit case"}
          </button>
          <button className="btn danger" type="button" disabled={busy} onClick={remove}>
            Delete case
          </button>
          <Link className="btn" to="/scan">
            New scan
          </Link>
        </div>
      </div>
      {error && <div className="error">{error}</div>}
      <p className="lede" style={{ marginBottom: 18 }}>
        {item.notes}
      </p>

      {editing && (
        <form className="form panel" style={{ marginBottom: 14, maxWidth: "none" }} onSubmit={save}>
          <label>
            Title
            <input
              value={form.title}
              onChange={(event) => setForm((current) => ({ ...current, title: event.target.value }))}
              required
              minLength={3}
            />
          </label>
          <label>
            Application
            <input
              value={form.application}
              onChange={(event) => setForm((current) => ({ ...current, application: event.target.value }))}
              required
              minLength={2}
            />
          </label>
          <label>
            Owner
            <select
              value={form.owner_id}
              onChange={(event) => setForm((current) => ({ ...current, owner_id: event.target.value }))}
            >
              {users.map((user) => (
                <option key={user.id} value={user.id}>
                  {user.name} ({user.role})
                </option>
              ))}
            </select>
          </label>
          <label>
            Notes
            <textarea
              rows={4}
              value={form.notes}
              onChange={(event) => setForm((current) => ({ ...current, notes: event.target.value }))}
            />
          </label>
          <button className="btn" disabled={busy}>
            {busy ? "Saving…" : "Save changes"}
          </button>
        </form>
      )}

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
