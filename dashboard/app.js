"use strict";

// The dashboard is normally served by the Java server itself (same origin), so
// the API lives under the same host. Override here if you serve the static
// files separately (e.g. python3 -m http.server) and the API is elsewhere.
const API_BASE = "";

const REFRESH_MS = 4000;
const HIGHLIGHT_MAX = 200000;   // bigger reports are shown as plain text

const el = (id) => document.getElementById(id);
let timer = null;
let reportsById = new Map();
let lastSignature = "";
let lastOk = "";
let currentJson = "";
let drawerOpener = null;

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

function clock(iso) {
  const t = Date.parse(iso);
  return isNaN(t) ? esc(iso) : new Date(t).toLocaleTimeString("pl-PL", { hour12: false });
}

function dayOf(iso) {
  const t = Date.parse(iso);
  return isNaN(t) ? "" : new Date(t).toLocaleDateString("pl-PL", { day: "numeric", month: "long", year: "numeric" });
}

function classTone(c) {
  const danger = ["authentication_failure", "file_change", "rename", "delete",
    "delete_during_downtime", "downtime_change"];
  const warn = ["tcp_connection", "samba_audit", "observation_gap", "authentication_success"];
  if (danger.includes(c)) return "danger";
  if (warn.includes(c)) return "warn";
  return "info";
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
  if (r.error) return `<span class="bad" title="${esc(r.error)}">! ${esc(r.error)}</span>`;
  if (r.complete === false) return `<span class="bad">! niekompletny</span>`;
  return `<span class="ok">ok</span>`;
}

// Text used by the search box: the fields an analyst usually looks for.
function haystack(r) {
  const parts = [r.agent_id, r.source, r.operation, r.path,
    r.analysis && r.analysis.classification,
    typeof r.content === "string" ? r.content.slice(0, 600) : ""];
  const peer = r.connection && r.connection.peer;
  if (peer) parts.push(peer.ip, peer.mac);
  const eps = r.network_context && r.network_context.endpoints;
  if (Array.isArray(eps)) eps.forEach((e) => parts.push(e.ip, e.mac));
  return parts.filter(Boolean).join(" ").toLowerCase();
}

function renderStats(s) {
  el("stat-agents-online").textContent = s.online_agents;
  el("stat-agents-total").textContent = s.total_agents;
  el("stat-events").textContent = s.total_events;
  el("stat-sources").textContent = s.by_source ? Object.keys(s.by_source).length : 0;
  const classes = Object.entries(s.by_classification || {}).sort((a, b) => b[1] - a[1]).slice(0, 6);
  el("stat-classes").innerHTML = classes
    .map(([name, n]) => `<span class="c-${classTone(name)}">${esc(name)} ${esc(n)}</span>`).join("");
}

function renderAgents(agents) {
  const body = el("agents");
  if (!agents.length) {
    body.innerHTML = "<tr><td colspan='5' class='empty'>Brak agentów: żaden raport jeszcze nie dotarł.</td></tr>";
  } else {
    body.innerHTML = agents.map((a) => {
      const up = a.status === "online";
      const last = [a.last_operation, a.last_source && "(" + a.last_source + ")", a.last_classification]
        .filter(Boolean).map(esc).join(" ");
      return `<tr>
        <td>${esc(a.agent_id)}</td>
        <td class="${up ? "online" : "offline"}">${up ? "● online" : "○ offline"}</td>
        <td>${relTime(a.last_seen)} <span class="sub">${fmtTime(a.last_seen)}</span></td>
        <td>${esc(a.total_reports)}</td>
        <td>${last || "—"}</td>
      </tr>`;
    }).join("");
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

function renderEvents(events, fetched) {
  const total = fetched.length;
  el("shown-count").textContent = events.length < total
    ? `${events.length} z ${total} pobranych`
    : `${total} zdarzeń`;

  // Same rows as last time: leave the table alone so selection and focus survive.
  const signature = events.map((r) => r.report_id).join(",");
  if (signature === lastSignature) return;
  lastSignature = signature;

  const focused = document.activeElement && document.activeElement.dataset
    ? document.activeElement.dataset.id : null;

  reportsById = new Map();
  const tbody = el("events");
  if (!events.length) {
    tbody.innerHTML = total
      ? `<tr><td colspan='7' class='empty'>Wszystkie pobrane zdarzenia (${total}) są ukryte przez filtry.</td></tr>`
      : "<tr><td colspan='7' class='empty'>Brak zdarzeń dla wybranych filtrów.</td></tr>";
    return;
  }

  let day = null;
  const rows = [];
  for (const r of events) {
    reportsById.set(r.report_id, r);
    const when = r.observed_at || r.received_at;
    const d = dayOf(when);
    if (d !== day) {
      day = d;
      rows.push(`<tr class="day"><td colspan="7">${esc(d)}</td></tr>`);
    }
    const cls = r.analysis ? r.analysis.classification : null;
    const tone = classTone(cls);
    const mark = tone === "danger" ? "! " : tone === "warn" ? "~ " : "";
    rows.push(`<tr class="clickable row-${tone}" tabindex="0" data-id="${esc(r.report_id)}">
      <td class="time" title="${esc(when)}">${clock(when)}</td>
      <td>${esc(r.agent_id)}</td>
      <td class="src-${esc(r.source)}">${esc(r.source)}</td>
      <td>${esc(r.operation)}</td>
      <td class="c-${tone}">${mark}${esc(cls || "—")}</td>
      <td class="details">${summarize(r)}</td>
      <td>${stateCell(r)}</td>
    </tr>`);
  }
  tbody.innerHTML = rows.join("");

  if (focused) {
    const again = tbody.querySelector(`tr[data-id="${CSS.escape(focused)}"]`);
    if (again) again.focus();
  }
}

// Colours the keys, strings, numbers and literals of an already formatted JSON text.
// Every piece goes through esc(), so report content can't inject markup.
function highlightJson(text) {
  if (text.length > HIGHLIGHT_MAX) return esc(text);
  const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
  let out = "";
  let last = 0;
  let m;
  while ((m = re.exec(text))) {
    out += esc(text.slice(last, m.index));
    if (m[1]) {
      out += `<span class="${m[2] ? "j-k" : "j-s"}">${esc(m[1])}</span>${esc(m[2] || "")}`;
    } else {
      out += `<span class="${m[3] ? "j-b" : "j-n"}">${esc(m[0])}</span>`;
    }
    last = re.lastIndex;
  }
  return out + esc(text.slice(last));
}

function openDrawer(id) {
  const r = reportsById.get(id);
  if (!r) return;
  drawerOpener = document.activeElement;
  currentJson = JSON.stringify(r, null, 2);
  el("drawer-title").textContent = `${r.source} / ${r.operation}`;
  el("drawer-body").innerHTML = highlightJson(currentJson);
  el("drawer").classList.remove("hidden");
  el("drawer-close").focus();
}

function closeDrawer() {
  if (el("drawer").classList.contains("hidden")) return;
  el("drawer").classList.add("hidden");
  if (drawerOpener && document.contains(drawerOpener)) drawerOpener.focus();
  drawerOpener = null;
}

function copyJson() {
  const b = el("copy-json");
  navigator.clipboard.writeText(currentJson).then(
    () => { b.textContent = "skopiowano"; },
    () => { b.textContent = "nie udało się"; });
  setTimeout(() => { b.textContent = "kopiuj"; }, 1500);
}

function setConn(ok) {
  const c = el("conn");
  c.className = ok ? "conn-ok" : "conn-err";
  c.textContent = ok ? "● połączono" : "○ brak połączenia z serwerem";
}

let busy = false;
let pending = false;

async function refresh() {
  if (busy) { pending = true; return; }   // a slow server must not pile up requests
  busy = true;
  const source = el("filter-source").value;
  const agent = el("filter-agent").value;
  const limit = Number(el("filter-limit").value) || 100;
  const hideUnknown = el("hide-unknown").checked;
  const hideHeartbeat = el("hide-heartbeat").checked;
  const text = el("filter-text").value.trim().toLowerCase();
  const filtering = hideUnknown || hideHeartbeat || text;
  // Przy filtrowaniu pobieramy więcej, żeby po odfiltrowaniu została pełna lista.
  const fetchLimit = filtering ? Math.min(limit * 5, 1000) : limit;
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
    if (filtering) {
      shown = events.filter((r) => {
        if (r.error || r.complete === false) return true;   // luki w obserwacji zawsze widoczne
        const c = r.analysis && r.analysis.classification;
        if (hideHeartbeat && c === "heartbeat") return false;
        if (hideUnknown && (!c || c === "unknown")) return false;
        return !text || haystack(r).includes(text);
      }).slice(0, limit);
    }
    renderEvents(shown, events);
    setConn(true);
    lastOk = new Date().toLocaleTimeString("pl-PL", { hour12: false });
    el("updated").textContent = "zaktualizowano " + lastOk;
  } catch (e) {
    setConn(false);
    el("updated").textContent = (lastOk ? "ostatnie dane z " + lastOk + ", " : "") + String(e.message || e);
  } finally {
    busy = false;
    if (pending) { pending = false; refresh(); }
  }
}

function scheduleAuto() {
  if (timer) clearInterval(timer);
  if (el("auto").checked) timer = setInterval(refresh, REFRESH_MS);
}

function force() { lastSignature = ""; refresh(); }

el("refresh").addEventListener("click", force);
["filter-source", "filter-agent", "filter-limit", "hide-unknown", "hide-heartbeat"]
  .forEach((id) => el(id).addEventListener("change", force));
let typing = null;
el("filter-text").addEventListener("input", () => { clearTimeout(typing); typing = setTimeout(force, 250); });
el("auto").addEventListener("change", scheduleAuto);

el("events").addEventListener("click", (e) => {
  const tr = e.target.closest("tr.clickable");
  if (tr) openDrawer(tr.dataset.id);
});
el("events").addEventListener("keydown", (e) => {
  const tr = e.target.closest("tr.clickable");
  if (tr && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); openDrawer(tr.dataset.id); }
});
el("drawer-close").addEventListener("click", closeDrawer);
el("copy-json").addEventListener("click", copyJson);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

refresh();
scheduleAuto();
