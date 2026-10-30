"use strict";

// The dashboard is normally served by the Java server itself (same origin), so
// the API lives under the same host. Override here if you serve the static
// files separately (e.g. python3 -m http.server) and the API is elsewhere.
const API_BASE = "";

const REFRESH_MS = 4000;

const el = (id) => document.getElementById(id);
let timer = null;
let reportsById = new Map();

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

async function api(path) {
  const res = await fetch(API_BASE + path, {
    headers: { "Accept": "application/json" },
    signal: AbortSignal.timeout(3000),
  });
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

function relTime(iso) {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (isNaN(t)) return esc(iso);
  const diff = Math.round((Date.now() - t) / 1000);
  if (diff < 0) return "teraz";
  if (diff < 60) return diff + "s temu";
  if (diff < 3600) return Math.floor(diff / 60) + "m temu";
  if (diff < 86400) return Math.floor(diff / 3600) + "h temu";
  return Math.floor(diff / 86400) + "d temu";
}

function fmtTime(iso) {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (isNaN(t)) return esc(iso);
  return new Date(t).toLocaleString("pl-PL", { hour12: false });
}

function classificationClass(c) {
  const danger = ["authentication_failure", "file_change", "rename", "delete",
    "delete_during_downtime", "downtime_change"];
  const warn = ["tcp_connection", "samba_audit", "observation_gap", "authentication_success"];
  if (danger.includes(c)) return "cls-danger";
  if (warn.includes(c)) return "cls-warn";
  return "cls-info";
}

// A short, human summary of a report, tailored to its source/operation.
function summarize(r) {
  const path = r.path != null && r.path !== "" ? esc(r.path)
    : (r.path_base64 ? "<span class='sub'>(ścieżka binarna)</span>" : "");

  if (r.source === "network" && r.connection) {
    const c = r.connection;
    const peer = c.peer || {};
    let s = `<b>${esc(c.local_ip)}:${esc(c.local_port)}</b> ← ${esc(peer.ip)}:${esc(c.peer_port)}`;
    if (peer.mac) s += ` <span class="sub">MAC ${esc(peer.mac)}</span>`;
    else if (peer.mac_status) s += ` <span class="sub">(${esc(peer.mac_status)})</span>`;
    return s;
  }

  if (r.source === "system" && r.operation === "heartbeat") {
    return "<span class='sub'>heartbeat</span>";
  }

  if (r.operation === "rename") {
    const prev = r.previous_path != null ? esc(r.previous_path)
      : (r.previous_path_base64 ? "(binarna)" : "?");
    return `<span class="sub">${prev}</span> → ${path}`;
  }

  let s = path || "<span class='sub'>—</span>";
  const m = r.metadata;
  if (m && (m.old_size != null || m.new_size != null)) {
    s += ` <span class="sub">${m.old_size == null ? "∅" : esc(m.old_size)}→${m.new_size == null ? "∅" : esc(m.new_size)} B</span>`;
  }
  if (r.source === "log") {
    const ev = Array.isArray(r.evidence) ? r.evidence.length : 0;
    const eps = r.network_context && Array.isArray(r.network_context.endpoints)
      ? r.network_context.endpoints.length : 0;
    const bits = [];
    if (ev) bits.push(ev + " dowodów");
    if (eps) bits.push(eps + " IP");
    if (bits.length) s += ` <span class="sub">(${bits.join(", ")})</span>`;
  }
  return s;
}

function stateCell(r) {
  if (r.error) return `<span class="bad" title="${esc(r.error)}">✗ ${esc(r.error)}</span>`;
  if (r.complete === false) return `<span class="bad">✗ niekompletny</span>`;
  return `<span class="ok">✓</span>`;
}

function renderStats(s) {
  el("stat-agents-online").textContent = s.online_agents;
  el("stat-agents-total").textContent = s.total_agents;
  el("stat-events").textContent = s.total_events;
  const sources = s.by_source ? Object.keys(s.by_source).length : 0;
  el("stat-sources").textContent = sources;
}

function renderAgents(agents) {
  const box = el("agents");
  if (!agents.length) {
    box.innerHTML = "<p class='muted'>Brak agentów — żaden raport jeszcze nie dotarł.</p>";
  } else {
    box.innerHTML = agents.map((a) => `
      <div class="agent-card ${a.status === "online" ? "online" : "offline"}">
        <div class="agent-id">${esc(a.agent_id)}</div>
        <div class="agent-meta">
          Status: <span class="status-${esc(a.status)}">${a.status === "online" ? "ONLINE" : "OFFLINE"}</span><br>
          Ostatni raport: <b>${relTime(a.last_seen)}</b> <span class="sub">(${fmtTime(a.last_seen)})</span><br>
          Raporty: <b>${esc(a.total_reports)}</b><br>
          Ostatnio: <b>${esc(a.last_operation || "—")}</b> / ${esc(a.last_source || "—")}
          ${a.last_classification ? `<br>Klasyfikacja: <b>${esc(a.last_classification)}</b>` : ""}
        </div>
      </div>`).join("");
  }

  // Keep the agent filter in sync with discovered agents.
  const sel = el("filter-agent");
  const current = sel.value;
  const ids = agents.map((a) => a.agent_id);
  const key = ids.join("\n");
  if (sel.dataset.ids !== key) {
    sel.dataset.ids = key;
    sel.innerHTML = "<option value=''>wszyscy</option>" +
      ids.map((id) => `<option value="${esc(id)}">${esc(id)}</option>`).join("");
    if (ids.includes(current)) sel.value = current;
  }
}

function renderEvents(events) {
  reportsById = new Map();
  const tbody = el("events");
  if (!events.length) {
    tbody.innerHTML = "<tr><td colspan='7' class='muted'>Brak zdarzeń dla wybranych filtrów.</td></tr>";
    return;
  }
  tbody.innerHTML = events.map((r) => {
    reportsById.set(r.report_id, r);
    const cls = r.analysis ? r.analysis.classification : null;
    const when = r.observed_at || r.received_at;
    return `<tr class="clickable" data-id="${esc(r.report_id)}">
      <td title="${esc(when)}">${fmtTime(when)}</td>
      <td>${esc(r.agent_id)}</td>
      <td><span class="tag src-${esc(r.source)}">${esc(r.source)}</span></td>
      <td>${esc(r.operation)}</td>
      <td class="${classificationClass(cls)}">${esc(cls || "—")}</td>
      <td class="details">${summarize(r)}</td>
      <td>${stateCell(r)}</td>
    </tr>`;
  }).join("");

  tbody.querySelectorAll("tr.clickable").forEach((tr) => {
    tr.addEventListener("click", () => openDrawer(tr.getAttribute("data-id")));
  });
}

function openDrawer(id) {
  const r = reportsById.get(id);
  if (!r) return;
  el("drawer-title").textContent = `${r.source} / ${r.operation}`;
  el("drawer-body").textContent = JSON.stringify(r, null, 2);
  el("drawer").classList.remove("hidden");
}

function closeDrawer() {
  el("drawer").classList.add("hidden");
}

function setConn(ok, msg) {
  const b = el("conn-badge");
  b.className = "badge " + (ok ? "badge-ok" : "badge-error");
  b.textContent = msg;
}

let busy = false;

async function refresh() {
  if (busy) return;   // a slow server must not pile up requests
  busy = true;
  const source = el("filter-source").value;
  const agent = el("filter-agent").value;
  const limit = Number(el("filter-limit").value) || 100;
  const hideUnknown = el("hide-unknown").checked;
  const hideHeartbeat = el("hide-heartbeat").checked;
  // Przy ukrywaniu wierszy pobieramy więcej, żeby po odfiltrowaniu została pełna lista.
  const fetchLimit = (hideUnknown || hideHeartbeat) ? Math.min(limit * 5, 1000) : limit;
  const query = new URLSearchParams();
  if (source) query.set("source", source);
  if (agent) query.set("agent_id", agent);
  query.set("limit", fetchLimit);

  try {
    const [stats, agents, events] = await Promise.all([
      api("/api/v1/stats"),
      api("/api/v1/agents"),
      api("/api/v1/events?" + query.toString()),
    ]);
    if (!Array.isArray(agents) || !Array.isArray(events)) throw new Error("niepoprawna odpowiedź serwera");
    renderStats(stats);
    renderAgents(agents);
    let shown = events;
    if (hideUnknown || hideHeartbeat) {
      shown = events.filter((r) => {
        if (r.error || r.complete === false) return true;   // luki w obserwacji zawsze widoczne
        const c = r.analysis && r.analysis.classification;
        if (hideHeartbeat && c === "heartbeat") return false;
        if (hideUnknown && (!c || c === "unknown")) return false;
        return true;
      }).slice(0, limit);
    }
    renderEvents(shown);
    setConn(true, "Połączono");
    el("updated").textContent = "Aktualizacja: " + new Date().toLocaleTimeString("pl-PL", { hour12: false });
  } catch (e) {
    setConn(false, "Brak połączenia z serwerem");
    el("updated").textContent = String(e.message || e);
  } finally {
    busy = false;
  }
}

function scheduleAuto() {
  if (timer) clearInterval(timer);
  if (el("auto").checked) timer = setInterval(refresh, REFRESH_MS);
}

el("refresh").addEventListener("click", refresh);
el("filter-source").addEventListener("change", refresh);
el("filter-agent").addEventListener("change", refresh);
el("filter-limit").addEventListener("change", refresh);
el("hide-unknown").addEventListener("change", refresh);
el("hide-heartbeat").addEventListener("change", refresh);
el("auto").addEventListener("change", scheduleAuto);
el("drawer-close").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

refresh();
scheduleAuto();
