const API = "/api";

async function request(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      detail = await response.text();
    }
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return response.json();
}

export const api = {
  dashboard: () => request("/dashboard"),
  targets: () => request("/targets"),
  users: () => request("/users"),
  cases: () => request("/cases"),
  case: (id) => request(`/cases/${id}`),
  createCase: (payload) =>
    request("/cases", { method: "POST", body: JSON.stringify(payload) }),
  scans: (caseId) => request(caseId ? `/scans?case_id=${caseId}` : "/scans"),
  scan: (id) => request(`/scans/${id}`),
  startScan: (payload) =>
    request("/scans", { method: "POST", body: JSON.stringify(payload) }),
  reportJsonUrl: (id) => `${API}/scans/${id}/report.json`,
  reportHtmlUrl: (id) => `${API}/scans/${id}/report.html`,
};
