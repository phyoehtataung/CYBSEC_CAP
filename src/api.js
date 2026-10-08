const API = "/api";

async function request(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    // Read the body ONCE as text, then try to parse it as JSON.
    // (Calling response.json() and then response.text() throws
    // "body stream already read" because a body can only be consumed once.)
    const raw = await response.text();
    let detail = raw || response.statusText;
    try {
      const body = JSON.parse(raw);
      detail = body.detail || JSON.stringify(body);
    } catch {
      // not JSON - keep the plain text
    }
    // The Vite dev proxy answers 500 with an empty body when the backend is down.
    if (response.status >= 500 && !raw) {
      detail = "Cannot reach the WebSET API on port 8000. Is the backend running?";
    }
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  if (response.status === 204) return null;
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

export const api = {
  dashboard: () => request("/dashboard"),
  targets: () => request("/targets"),
  users: () => request("/users"),
  cases: () => request("/cases"),
  case: (id) => request(`/cases/${id}`),
  createCase: (payload) =>
    request("/cases", { method: "POST", body: JSON.stringify(payload) }),
  updateCase: (id, payload) =>
    request(`/cases/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
  deleteCase: (id) => request(`/cases/${id}`, { method: "DELETE" }),
  scans: (caseId) => request(caseId ? `/scans?case_id=${caseId}` : "/scans"),
  scan: (id) => request(`/scans/${id}`),
  startScan: (payload) =>
    request("/scans", { method: "POST", body: JSON.stringify(payload) }),
  cancelScan: (id) => request(`/scans/${id}/cancel`, { method: "POST" }),
  deleteScan: (id) => request(`/scans/${id}`, { method: "DELETE" }),
  updateFinding: (scanId, findingId, payload) =>
    request(`/scans/${scanId}/findings/${encodeURIComponent(findingId)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  reportJsonUrl: (id) => `${API}/scans/${id}/report.json`,
  reportHtmlUrl: (id) => `${API}/scans/${id}/report.html`,
};
