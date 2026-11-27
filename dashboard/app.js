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
let threatByIp = new Map();   // ip -> threat from /api/attackers, for badges in the event log

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

// Human names for schema v2 event.type; unknown types are shown as-is.
const EVENT_LABELS = {
  "auth.failure": "nieudane logowanie",
  "auth.attempt": "próba hasła",
  "auth.success": "udane logowanie",
  "auth.invalid_user": "nieistniejące konto",
  "auth.denied": "odmowa dostępu",
  "net.scan": "skan portów",
  "net.probe": "sonda usługi (np. nmap -sV)",
  "net.connection": "połączenie TCP",
  "file.change": "zmiana pliku",
  "samba.audit": "audyt Samby",
  "system.heartbeat": "heartbeat",
  "system.observation_gap": "luka w obserwacji",
  "system.source_unavailable": "źródło niedostępne",
  "log.entry": "wpis logu",
  "system.unknown": "nieznane",
};
const TYPE_DANGER = ["auth.failure", "auth.attempt", "auth.denied", "net.scan", "net.probe", "file.change"];
const TYPE_WARN = ["auth.success", "auth.invalid_user", "net.connection", "samba.audit",
  "system.observation_gap", "system.source_unavailable"];

// "SSH · nieudane logowanie" from type + service; null service gives just the name.
function kindLabel(type, service) {
  const name = EVENT_LABELS[type] || type;
  return service ? service.toUpperCase() + " · " + name : name;
}

// Label for one report: the v2 event block when present, else the v1 classification.
function eventLabel(r) {
  const ev = r.event;
  if (ev && ev.type) return kindLabel(ev.type, ev.service);
  return r.analysis ? r.analysis.classification : null;
}

function eventTone(r) {
  const t = r.event && r.event.type;
  if (!t) return classTone(r.analysis ? r.analysis.classification : null);
  if (TYPE_DANGER.includes(t)) return "danger";
  if (TYPE_WARN.includes(t)) return "warn";
  return "info";
}

// Threat levels from /api/attackers, most serious first.
const THREATS = {
  confirmed: { label: "POTWIERDZONY", tone: "danger", hint: "zalogował się na konto-wabik" },
  bait: { label: "PRZYNĘTA", tone: "danger", hint: "próba na konto-przynętę albo odczyt pliku-przynęty" },
  brute_force: { label: "BRUTE FORCE", tone: "danger", hint: "5+ nieudanych logowań w 10 min" },
  fast_enum: { label: "SKANER", tone: "warn", hint: "skan portów albo 3+ porty w minutę" },
  suspicious: { label: "PODEJRZANY", tone: "warn", hint: "nieudane logowanie, sonda usługi albo nieistniejące konto" },
  contact: { label: "kontakt", tone: "info", hint: "samo połączenie" },
};

function threatBadge(threat) {
  const t = THREATS[threat];
  if (!t) return "";
  return `<span class="badge badge-${t.tone}" title="${esc(t.hint)}">${esc(t.label)}</span>`;
}

// Clickable IP (filters the event log to it) plus the attacker badge when that IP is graded above "contact".
function ipTag(ip, port, withBadge = true) {
  if (!ip) return "";
  const threat = withBadge ? threatByIp.get(ip) : null;
  const badge = threat && threat !== "contact" ? " " + threatBadge(threat) : "";
  return `<button type="button" class="ip" data-ip="${esc(ip)}" title="pokaż zdarzenia z tego adresu">`
    + `${esc(ip)}${port != null ? ":" + esc(port) : ""}</button>${badge}`;
}

// "bob @ 203.0.113.9:4242" for events with a parsed source, plus net.scan details.
function eventWho(r) {
  const ev = r.event;
  if (!ev) return "";
  const bits = [];
  const src = ev.src && ev.src.ip ? ipTag(ev.src.ip, ev.src.port) : "";
  const user = ev.user && ev.user.name ? esc(ev.user.name) : "";
  if (user || src) bits.push(user && src ? `${user} @ ${src}` : user || src);
  const d = ev.detail;
  if (d && d.ports) bits.push(`${esc(d.ports)} portów${d.scan ? " " + esc(d.scan) : ""}`);
  return bits.length ? ` <span class="sub">${bits.join(", ")}</span>` : "";
}

// A short, human summary of a report, tailored to its source/operation.
function summarize(r) {
  const path = r.path != null && r.path !== "" ? esc(r.path)
    : (r.path_base64 ? "<span class='sub'>(ścieżka binarna)</span>" : "");

  if (r.source === "network" && r.connection) {
    const c = r.connection;
    const peer = c.peer || {};
    let s = `<b>${esc(c.local_ip)}:${esc(c.local_port)}</b> ← ${peer.ip ? ipTag(peer.ip, c.peer_port) : "?"}`;
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
  return s + eventWho(r);
}

function stateCell(r) {
  if (r.error) return `<span class="bad" title="${esc(r.error)}">! ${esc(r.error)}</span>`;
  if (r.complete === false) return `<span class="bad">! niekompletny</span>`;
  return `<span class="ok">ok</span>`;
}

// Text used by the search box: the fields an analyst usually looks for.
function haystack(r) {
  const parts = [r.agent_id, r.source, r.operation, r.path,
    r.analysis && r.analysis.classification, eventLabel(r),
    r.event && r.event.type, r.event && r.event.user && r.event.user.name,
    r.event && r.event.src && r.event.src.ip,
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
  // Prefer "type/service" counts (server >= 0.3.1); older servers only send by_classification.
  const kinds = Object.entries(s.by_event_kind || {}).filter(([k]) => k !== "system.heartbeat");
  if (kinds.length) {
    el("stat-classes").innerHTML = kinds.sort((a, b) => b[1] - a[1]).slice(0, 6).map(([key, n]) => {
      const slash = key.indexOf("/");
      const type = slash < 0 ? key : key.slice(0, slash);
      const service = slash < 0 ? null : key.slice(slash + 1);
      const tone = eventTone({ event: { type } });
      return `<span class="c-${tone}">${esc(kindLabel(type, service))} ${esc(n)}</span>`;
    }).join("");
    return;
  }
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

// Second badge for an IP that reached the brute-force threshold but is graded higher (or has calmed down since).
function bruteTag(a) {
  if (!a.last_brute_force || a.threat === "brute_force") return "";
  return ` ${threatBadge("brute_force")} <span class="sub" title="${esc(fmtTime(a.last_brute_force))}">${relTime(a.last_brute_force)}</span>`;
}

function renderAttackers(list) {
  threatByIp = new Map(list.map((a) => [a.ip, a.threat]));
  const body = el("attackers");
  const shown = list.filter((a) => a.threat !== "contact");
  const contacts = list.length - shown.length;
  if (!shown.length) {
    body.innerHTML = `<tr><td colspan='6' class='empty'>Brak podejrzanych adresów`
      + (contacts ? ` (${contacts} z samym połączeniem).` : ".") + "</td></tr>";
    return;
  }
  const rows = shown.map((a) => {
    const signals = [];
    if (a.confirmed) signals.push("logowanie na wabik");
    if (a.breadcrumb_read) signals.push("odczyt przynęty");
    if (a.decoy_attempt) signals.push("próba na konto-przynętę");
    if (a.distinct_ports >= 3) signals.push(`${esc(a.distinct_ports)} porty/min`);
    if (a.threat === "fast_enum" && a.distinct_ports < 3) signals.push("skan portów");
    if (a.probed) signals.push("sonda usługi");
    if (a.invalid_users) signals.push(`${esc(a.invalid_users)}× nieistniejące konto`);
    const tone = (THREATS[a.threat] || {}).tone || "info";
    return `<tr class="row-${tone}">
      <td>${ipTag(a.ip, null, false)}${a.mac ? ` <span class="sub">${esc(a.mac)}</span>` : ""}</td>
      <td>${threatBadge(a.threat)}${bruteTag(a)}</td>
      <td>${esc(a.auth_failures)} <span class="sub">(${esc(a.failures_10m)} w 10 min)</span></td>
      <td>${signals.join(", ") || "<span class='sub'>—</span>"}</td>
      <td>${relTime(a.first_seen)}</td>
      <td>${relTime(a.last_seen)} <span class="sub">${fmtTime(a.last_seen)}</span></td>
    </tr>`;
  });
  if (contacts) rows.push(`<tr><td colspan='6' class='empty'>+ ${contacts} adresów z samym połączeniem</td></tr>`);
  body.innerHTML = rows.join("");
}

// Puts an IP into the search box, so the event log shows only that address.
function filterByIp(ip) {
  el("filter-text").value = ip;
  force();
  el("filter-text").scrollIntoView({ block: "nearest" });
}

function renderEvents(events, fetched) {
  const total = fetched.length;
  el("shown-count").textContent = events.length < total
    ? `${events.length} z ${total} pobranych`
    : `${total} zdarzeń`;

  // Same rows as last time: leave the table alone so selection and focus survive.
  const signature = events.map((r) => r.report_id).join(",")
    + "|" + [...threatByIp].map(([ip, t]) => ip + "=" + t).join(",");   // badges change with the grading
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
    const cls = eventLabel(r);
    const tone = eventTone(r);
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
    const [stats, agents, events, attackers] = await Promise.all([
      api("/api/stats"),
      api("/api/agents"),
      api("/api/events?" + query.toString()),
      api("/api/attackers").catch(() => []),   // older server without the endpoint: no panel data
    ]);
    if (!Array.isArray(agents) || !Array.isArray(events)) throw new Error("niepoprawna odpowiedź serwera");
    renderStats(stats);
    renderAgents(agents);
    renderAttackers(Array.isArray(attackers) ? attackers : []);
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

el("attackers").addEventListener("click", (e) => {
  const b = e.target.closest("button.ip");
  if (b) filterByIp(b.dataset.ip);
});
el("events").addEventListener("click", (e) => {
  const b = e.target.closest("button.ip");
  if (b) { filterByIp(b.dataset.ip); return; }   // clicking an IP filters instead of opening the report
  const tr = e.target.closest("tr.clickable");
  if (tr) openDrawer(tr.dataset.id);
});
el("events").addEventListener("keydown", (e) => {
  if (e.target.closest("button.ip")) return;   // Enter on an IP button triggers its click
  const tr = e.target.closest("tr.clickable");
  if (tr && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); openDrawer(tr.dataset.id); }
});
el("drawer-close").addEventListener("click", closeDrawer);
el("copy-json").addEventListener("click", copyJson);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

refresh();
scheduleAuto();
