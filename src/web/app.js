"use strict";
// Every domain shown here is attacker-influenced (any web page can make your machine look one up),
// so this file only ever sets textContent / attributes through el(); never HTML strings.

const CATS = [
  { id: "malware", label: "malware/phishing" },
  { id: "telemetry", label: "telemetry" },
  { id: "ads", label: "ads/trackers" },
  { id: "allowed", label: "allowlisted" },
  { id: "clean", label: "clean" },
  { id: "unknown", label: "unknown/new" },
];
const LABEL = Object.fromEntries(CATS.map(c => [c.id, c.label]));
const MAX_ROWS = 300;

const $ = id => document.getElementById(id);
const state = { window: "24h", cats: new Set(), text: "", rows: [], paused: false, buffered: [] };

function el(tag, cls, text, attrs) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = text;
  if (attrs) for (const k in attrs) n.setAttribute(k, attrs[k]);
  return n;
}
const colorVar = cat => "var(--" + (LABEL[cat] ? cat : "unknown") + ")";
const fmt = n => Number(n).toLocaleString();

async function api(path) {
  const r = await fetch(path, { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error(path + ": " + r.status);
  return r.json();
}

async function post(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Goop-Steppa": "1" },
    body: JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(typeof data === "string" ? data : "request failed (" + r.status + ")");
  return data;
}

let toastTimer;
function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 3500);
}

async function act(kind, domain, category) {
  try {
    const body = { domain };
    if (category) body.category = category;
    const r = await post("/api/" + kind, body);
    toast(kind + ": " + r.domain + " (subdomains included)");
    refresh();
  } catch (e) {
    toast("Failed: " + e.message);
  }
}

// ---------- summary tiles ----------
function renderSummary(s) {
  $("s-total").textContent = fmt(s.total);
  $("s-blocked").textContent = fmt(s.blocked);
  $("s-pct").textContent = s.total ? ((s.blocked * 100) / s.total).toFixed(1) + "%" : "-";
  const box = $("cats");
  box.replaceChildren();
  box.classList.toggle("dimmed", state.cats.size > 0);
  for (const c of CATS) {
    const v = s.categories[c.id] || { blocked: 0, allowed: 0 };
    const b = el("button", "cat", null, { type: "button", "aria-pressed": String(state.cats.has(c.id)) });
    b.style.setProperty("--c", colorVar(c.id));
    b.append(el("div", "n", fmt(v.blocked + v.allowed)), el("div", "l", c.label));
    b.addEventListener("click", () => {
      if (!state.cats.delete(c.id)) state.cats.add(c.id);
      renderFeed();
      b.setAttribute("aria-pressed", String(state.cats.has(c.id)));
      box.classList.toggle("dimmed", state.cats.size > 0);
    });
    box.append(b);
  }
}

// ---------- chart ----------
function renderTimeline(t) {
  const chart = $("chart");
  chart.replaceChildren();
  const byT = new Map(t.points.map(p => [p.t, p]));
  const start = Math.floor(t.since_ms / t.bucket_ms) * t.bucket_ms;
  const pts = [];
  for (let x = start; x <= t.now_ms; x += t.bucket_ms) pts.push(byT.get(x) || { t: x, blocked: 0, allowed: 0 });
  const max = Math.max(1, ...pts.map(p => p.blocked + p.allowed));
  for (const p of pts) {
    const tot = p.blocked + p.allowed;
    const bar = el("div", "bar", null, { title: new Date(p.t).toLocaleString() + "\n" + p.blocked + " blocked, " + p.allowed + " forwarded" });
    const a = el("div", "a"), b = el("div", "b");
    a.style.height = (p.allowed / max) * 100 + "%";
    b.style.height = (p.blocked / max) * 100 + "%";
    if (tot) bar.append(a, b);
    chart.append(bar);
  }
  $("ax-start").textContent = new Date(t.since_ms).toLocaleString();
  $("ax-end").textContent = "now";
}

// ---------- top domains ----------
function renderTops(tops) {
  const box = $("tops");
  box.replaceChildren();
  for (const c of CATS) {
    const card = el("div", "top");
    card.style.setProperty("--c", colorVar(c.id));
    card.append(el("h3", null, c.label));
    const rows = tops[c.id] || [];
    if (!rows.length) card.append(el("div", "none", "nothing yet"));
    else {
      const ol = el("ol");
      for (const r of rows) {
        const li = el("li");
        li.append(el("span", "d", r.domain, { title: r.domain }), el("span", "c", fmt(r.count)));
        li.append(...actionButtons(r.domain, c.id));
        ol.append(li);
      }
      card.append(ol);
    }
    box.append(card);
  }
}

function actionButtons(domain, cat) {
  const out = [];
  if (cat !== "allowed") {
    const b = el("button", "mini", "allow", { type: "button", title: "Allow this domain and its subdomains" });
    b.addEventListener("click", () => act("allow", domain));
    out.push(b);
  }
  if (cat !== "malware" && cat !== "telemetry" && cat !== "ads") {
    const b = el("button", "mini", "block", { type: "button", title: "Block this domain and its subdomains" });
    b.addEventListener("click", () => act("block", domain));
    out.push(b);
  } else {
    const b = el("button", "mini", "forget", { type: "button", title: "Remove from your own block/allow lists (does not affect imported lists)" });
    b.addEventListener("click", () => act("forget", domain));
    out.push(b);
  }
  return out;
}

// ---------- live feed ----------
function visibleRows() {
  const needle = state.text.toLowerCase();
  return state.rows.filter(r => (!state.cats.size || state.cats.has(r.category)) && (!needle || r.domain.toLowerCase().includes(needle)));
}

let feedQueued = false;
function renderFeed(freshId) {
  if (feedQueued) return;
  feedQueued = true;
  requestAnimationFrame(() => {
    feedQueued = false;
    const body = document.querySelector("#feed tbody");
    body.replaceChildren();
    const rows = visibleRows();
    $("empty").hidden = rows.length > 0;
    for (const r of rows.slice(0, MAX_ROWS)) {
      const tr = el("tr", r._fresh ? "fresh" : "");
      tr.style.setProperty("--c", colorVar(r.category));
      r._fresh = false;
      const time = new Date(r.ts_ms).toLocaleTimeString([], { hour12: false });
      tr.append(el("td", "muted", time));
      const v = el("td", "pill", r.action === "blocked" ? "BLOCK" : "ok");
      tr.append(v);
      const cat = el("td", "pill", LABEL[r.category] || r.category);
      tr.append(cat, el("td", "muted", r.qtype));
      tr.append(el("td", "dom pill", r.domain, { title: r.domain }));
      tr.append(el("td", "muted", r.source || ""));
      const act = el("td");
      act.append(...actionButtons(r.domain, r.action === "blocked" ? r.category : r.category === "allowed" ? "allowed" : "clean"));
      tr.append(act);
      body.append(tr);
    }
  });
}

function addLive(ev) {
  if (state.paused) { state.buffered.push(ev); return; }
  ev._fresh = true;
  state.rows.unshift(ev);
  if (state.rows.length > 2000) state.rows.length = 2000;
  renderFeed();
  scheduleRefresh();
}

function connect() {
  const es = new EventSource("/api/events");
  es.onopen = () => { $("live").classList.remove("off"); $("live-text").textContent = "live"; };
  es.onerror = () => { $("live").classList.add("off"); $("live-text").textContent = "reconnecting"; };
  es.onmessage = m => { try { addLive(JSON.parse(m.data)); } catch (_) { /* ignore malformed frame */ } };
}

// ---------- data refresh ----------
let refreshTimer;
function scheduleRefresh() {
  if (refreshTimer) return;
  refreshTimer = setTimeout(() => { refreshTimer = null; refresh(); }, 3000);
}

async function refresh() {
  const q = "?since=" + encodeURIComponent(state.window);
  try {
    const [s, tops, tl] = await Promise.all([api("/api/summary" + q), api("/api/top" + q), api("/api/timeline" + q)]);
    renderSummary(s);
    renderTops(tops);
    renderTimeline(tl);
  } catch (e) {
    toast("Could not load data: " + e.message);
  }
}

async function init() {
  $("window").addEventListener("change", e => { state.window = e.target.value; refresh(); });
  $("search").addEventListener("input", e => { state.text = e.target.value; renderFeed(); });
  $("clear").addEventListener("click", () => {
    state.cats.clear(); state.text = ""; $("search").value = "";
    refresh(); renderFeed();
  });
  $("pause").addEventListener("click", () => {
    state.paused = !state.paused;
    $("pause").textContent = state.paused ? "Resume" : "Pause";
    if (!state.paused) { const b = state.buffered; state.buffered = []; b.forEach(addLive); }
  });
  try {
    state.rows = await api("/api/recent?limit=300");
  } catch (e) { toast("Could not load history: " + e.message); }
  renderFeed();
  refresh();
  connect();
}
init();
