const ADMIN_HASH = "96d9a2539acbf3955441217a803568ebdf7fe673db1921c3e71ead99c533881a";
const TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV"];
const $ = (id) => document.getElementById(id);
const state = { user: null, monitors: [], users: [], incidents: [], open: null, tab: "overview", view: "websites" };

async function sha(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function load() {
  state.users = JSON.parse(localStorage.getItem("fs-users") || "null") || [{ username: "flotek", name: "Flotek", role: "admin", hash: ADMIN_HASH }];
  state.monitors = JSON.parse(localStorage.getItem("fs-monitors") || "[]");
  state.incidents = JSON.parse(localStorage.getItem("fs-incidents") || "[]");
  const id = sessionStorage.getItem("fs-session");
  state.user = state.users.find((u) => u.username === id) || null;
}
function save() {
  localStorage.setItem("fs-users", JSON.stringify(state.users));
  localStorage.setItem("fs-monitors", JSON.stringify(state.monitors));
  localStorage.setItem("fs-incidents", JSON.stringify(state.incidents));
}
function esc(value) {
  return String(value ?? "").replace(/[&<>"]/g, (c) => "&#" + c.charCodeAt(0) + ";");
}
function hostOf(value) {
  const raw = value.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(raw)) throw new Error("Enter a name like flotek.io");
  return raw;
}
function canEdit() { return state.user && state.user.role !== "viewer"; }
function websites() { return state.monitors.filter((m) => m.kind === "website"); }
function domains() { return state.monitors.filter((m) => m.kind === "domain"); }

async function dns(name, type) {
  const res = await fetch("https://dns.google/resolve?name=" + encodeURIComponent(name) + "&type=" + type);
  const json = await res.json();
  return (json.Answer || []).map((a) => String(a.data).replace(/^"|"$/g, ""));
}
async function reach(url) {
  const start = performance.now();
  try {
    await fetch(url, { mode: "no-cors", cache: "no-store" });
    return { up: true, ms: Math.round(performance.now() - start) };
  } catch {
    return { up: false, ms: null };
  }
}
async function certificate(host) {
  const res = await fetch("https://api.certspotter.com/v1/issuances?domain=" + encodeURIComponent(host) + "&include_subdomains=false&expand=issuer");
  if (!res.ok) return null;
  const list = await res.json();
  if (!Array.isArray(list) || !list.length) return null;
  list.sort((a, b) => new Date(b.not_after) - new Date(a.not_after));
  const cert = list[0];
  return {
    issuer: cert.issuer?.friendly_name || cert.issuer?.name || "Unknown",
    from: cert.not_before,
    until: cert.not_after,
    days: Math.round((new Date(cert.not_after) - Date.now()) / 86400000),
    revoked: !!cert.revoked
  };
}
async function registration(domain) {
  const boot = await fetch("https://data.iana.org/rdap/dns.json").then((r) => r.json());
  const labels = domain.split(".");
  let base = null;
  for (let i = 0; i < labels.length; i++) {
    const tld = labels.slice(i).join(".");
    const hit = (boot.services || []).find((s) => s[0].includes(tld));
    if (hit) { base = hit[1][0]; break; }
  }
  if (!base) return { error: "No registration server for this ending." };
  const res = await fetch(base.replace(/\/$/, "") + "/domain/" + domain, { headers: { Accept: "application/rdap+json, application/json" } });
  if (!res.ok) return { error: "Registration lookup returned " + res.status + "." };
  const data = await res.json();
  const date = (action) => (data.events || []).find((e) => e.eventAction === action)?.eventDate || "";
  const registrar = (data.entities || []).find((e) => (e.roles || []).includes("registrar"));
  const name = registrar?.vcardArray?.[1]?.find((v) => v[0] === "fn")?.[3] || "";
  return {
    name: data.ldhName || domain,
    status: (data.status || []).join(", ") || "—",
    registered: date("registration"),
    changed: date("last changed"),
    expires: date("expiration"),
    registrar: name || "—",
    nameservers: (data.nameservers || []).map((n) => n.ldhName).filter(Boolean)
  };
}
async function mail(host, addresses) {
  const txt = await dns(host, "TXT");
  const dmarc = await dns("_dmarc." + host, "TXT");
  const selectors = ["default", "google", "selector1", "selector2", "k1", "s1"];
  const dkim = [];
  for (const sel of selectors) {
    const rows = await dns(sel + "._domainkey." + host, "TXT");
    if (rows.length) dkim.push(sel);
  }
  let listed = "Not checked";
  const ip = (addresses || []).find((d) => /^\d+\.\d+\.\d+\.\d+$/.test(d));
  if (ip) {
    const rev = ip.split(".").reverse().join(".") + ".zen.spamhaus.org";
    const bl = await dns(rev, "A");
    listed = bl.length ? "Listed" : "Not listed";
  }
  return {
    spf: txt.find((d) => d.includes("v=spf1")) || "Missing",
    dmarc: dmarc.find((d) => d.includes("v=DMARC1")) || "Missing",
    dkim: dkim.length ? dkim.join(", ") : "No common selector",
    blacklist: listed
  };
}
function daysUntil(value) {
  if (!value) return null;
  const n = Math.round((new Date(value) - Date.now()) / 86400000);
  return Number.isNaN(n) ? null : n;
}
function problems(mon) {
  const r = mon.result;
  if (!r) return [];
  const list = [];
  if (mon.kind === "website" && r.reach && !r.reach.up) list.push({ code: "down", message: "Website did not answer" });
  if (r.cert?.revoked) list.push({ code: "cert-revoked", message: "Certificate is revoked" });
  else if (r.cert && r.cert.days < 30) list.push({ code: "cert-soon", message: "Certificate expires in " + r.cert.days + " days" });
  if (r.mail?.spf === "Missing") list.push({ code: "spf", message: "SPF record is missing" });
  if (r.mail?.dmarc === "Missing") list.push({ code: "dmarc", message: "DMARC record is missing" });
  if (r.mail?.blacklist === "Listed") list.push({ code: "blacklist", message: "Address is listed on Spamhaus" });
  const left = daysUntil(r.rdap?.expires);
  if (left != null && left < 30) list.push({ code: "domain-soon", message: "Domain expires in " + left + " days" });
  return list;
}
function syncIncidents(mon) {
  const found = problems(mon);
  const codes = new Set(found.map((p) => p.code));
  mon.silenced = mon.silenced || {};
  Object.keys(mon.silenced).forEach((code) => { if (!codes.has(code)) delete mon.silenced[code]; });
  found.forEach((p) => {
    if (mon.silenced[p.code]) return;
    if (state.incidents.some((i) => i.host === mon.host && i.kind === mon.kind && i.code === p.code)) return;
    state.incidents.unshift({ id: crypto.randomUUID(), host: mon.host, kind: mon.kind, code: p.code, message: p.message, at: new Date().toISOString() });
  });
}
async function runCheck(mon) {
  mon.checking = true;
  render();
  try {
    const records = {};
    for (const type of TYPES) records[type] = await dns(mon.host, type);
    const flat = TYPES.flatMap((type) => records[type].map((data) => ({ type, data })));
    const site = mon.kind === "website" ? await reach("https://" + mon.host + "/") : null;
    mon.result = {
      at: new Date().toISOString(),
      records: flat,
      reach: site,
      cert: await certificate(mon.host).catch(() => null),
      rdap: await registration(mon.host).catch((e) => ({ error: e.message })),
      mail: await mail(mon.host, records.A).catch(() => null)
    };
    mon.history = mon.history || [];
    mon.history.push({ at: mon.result.at, up: site ? site.up : true, ms: site?.ms ?? null });
    mon.history = mon.history.slice(-40);
    mon.error = "";
    syncIncidents(mon);
  } catch (error) {
    mon.error = error.message || "The check failed.";
  }
  mon.checking = false;
  save();
  render();
  if (state.open === mon.id) openDrawer(mon.id);
}
async function wpCall(mon, path, method, body) {
  if (!mon.secret) throw new Error("Save the agent secret first.");
  let res;
  try {
    res = await fetch("https://" + mon.host + "/wp-json/flotek/v1/" + path, {
      method,
      headers: { "X-Hub-Secret": mon.secret, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined
    });
  } catch {
    throw new Error("The site did not answer the agent. Upload the PHP file and use the same secret.");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.message || "WordPress refused the request.");
  return data;
}
async function loadWp(mon) {
  mon.wpError = "";
  mon.wp = await wpCall(mon, "health", "GET");
  save();
  openDrawer(mon.id);
}

function stat(label, value) {
  return `<div class="stat"><span>${label}</span><b>${value}</b></div>`;
}
function pill(mon) {
  if (mon.checking) return `<span class="pill">Checking</span>`;
  if (!mon.result) return `<span class="pill">Not checked</span>`;
  if (mon.kind === "domain") return `<span class="pill up">Domain</span>`;
  const up = mon.result.reach?.up;
  return `<span class="pill ${up ? "up" : "down"}">${up ? "Reachable" : "Unreachable"}</span>`;
}
function card(mon) {
  const when = mon.result ? new Date(mon.result.at).toLocaleString() : "Not checked yet";
  const extra = mon.result?.cert ? " · Certificate " + mon.result.cert.days + " days" : "";
  return `<button class="mon" data-id="${mon.id}"><div><strong>${esc(mon.host)}</strong><div class="meta">${when}${extra}</div>${mon.error ? `<div class="err">${esc(mon.error)}</div>` : ""}</div><div>${pill(mon)}</div></button>`;
}
function show(view) {
  state.view = view;
  document.querySelectorAll("header.app nav button").forEach((b) => b.classList.toggle("on", b.dataset.view === view));
  ["websites", "domains", "incidents", "team"].forEach((v) => $("view-" + v).classList.toggle("hidden", v !== view));
}
function render() {
  $("login").classList.toggle("hidden", !!state.user);
  $("app").classList.toggle("hidden", !state.user);
  if (!state.user) return;
  $("who").textContent = state.user.name + " · " + state.user.role;
  $("teamNav").classList.toggle("hidden", state.user.role !== "admin");
  const open = state.incidents.length;
  $("incBadge").textContent = String(open);
  $("incBadge").classList.toggle("hidden", open === 0);
  const webs = websites();
  const doms = domains();
  const times = webs.map((m) => m.result?.reach?.ms).filter((n) => n != null);
  const avg = times.length ? Math.round(times.reduce((a, b) => a + b, 0) / times.length) + " ms" : "—";
  $("webStats").innerHTML = [
    stat("Websites", webs.length),
    stat("Reachable", webs.filter((m) => m.result?.reach?.up).length),
    stat("Unreachable", webs.filter((m) => m.result?.reach && !m.result.reach.up).length),
    stat("Average response", avg)
  ].join("");
  $("domStats").innerHTML = [
    stat("Domains", doms.length),
    stat("Certificates under 30 days", doms.filter((m) => m.result?.cert && m.result.cert.days < 30).length),
    stat("Registration under 30 days", doms.filter((m) => { const d = daysUntil(m.result?.rdap?.expires); return d != null && d < 30; }).length),
    stat("Open incidents", state.incidents.filter((i) => i.kind === "domain").length)
  ].join("");
  $("webForm").classList.toggle("hidden", !canEdit());
  $("domForm").classList.toggle("hidden", !canEdit());
  $("webList").innerHTML = webs.length ? webs.map(card).join("") : `<div class="card"><p>No websites yet. Add one, or press Check flotek.io.</p></div>`;
  $("domList").innerHTML = doms.length ? doms.map(card).join("") : `<div class="card"><p>No domains yet. Add a domain name on its own, separate from the websites.</p></div>`;
  $("incTable").innerHTML = state.incidents.length
    ? `<tr><th>When</th><th>Name</th><th>Type</th><th>Problem</th><th></th></tr>` + state.incidents.map((i) => `<tr><td>${esc(new Date(i.at).toLocaleString())}</td><td>${esc(i.host)}</td><td>${esc(i.kind)}</td><td>${esc(i.message)}</td><td>${canEdit() ? `<button class="btn ghost small" data-ack="${i.id}" type="button">Acknowledge</button>` : ""}</td></tr>`).join("")
    : `<tr><td>No open incidents.</td></tr>`;
  $("userTable").innerHTML = `<tr><th>Name</th><th>Username</th><th>Role</th><th></th></tr>` + state.users.map((u) => `<tr><td>${esc(u.name)}</td><td>${esc(u.username)}</td><td>${esc(u.role)}</td><td>${u.username === "flotek" ? "" : `<button data-del="${esc(u.username)}" class="btn ghost small" type="button">Remove</button>`}</td></tr>`).join("");
  $("userForm").classList.toggle("hidden", state.user.role !== "admin");
}

function table(rows) {
  return `<table>${rows.map((r) => `<tr><td>${esc(r[0])}</td><td>${esc(r[1])}</td></tr>`).join("")}</table>`;
}
function openDrawer(id) {
  const m = state.monitors.find((x) => x.id === id);
  if (!m) return;
  state.open = id;
  const tabs = m.kind === "website"
    ? ["overview", "dns", "mail", "certificate", "registration", "wordpress", "analytics"]
    : ["overview", "dns", "mail", "certificate", "registration"];
  if (!tabs.includes(state.tab)) state.tab = "overview";
  const tabHtml = tabs.map((t) => `<button type="button" data-tab="${t}" class="${state.tab === t ? "on" : ""}">${t[0].toUpperCase() + t.slice(1)}</button>`).join("");
  const actions = canEdit()
    ? `<button class="btn plum small" id="re" type="button">Check again</button><button class="btn ghost small" id="pdfOne" type="button">Download PDF</button><button class="btn ghost small" id="remove" type="button">Remove</button>`
    : `<button class="btn ghost small" id="pdfOne" type="button">Download PDF</button>`;
  $("drawer").classList.remove("hidden");
  $("drawer").innerHTML = `<div class="panel"><div class="row"><div class="grow"><h2>${esc(m.host)}</h2><p class="meta">${m.kind === "website" ? "Website" : "Domain"}</p></div><button class="btn ghost small" id="close" type="button">Close</button>${actions}</div><div class="tabs">${tabHtml}</div><div class="card" id="pane"></div></div>`;
  $("pane").innerHTML = pane(m);
  $("close").onclick = () => { state.open = null; $("drawer").classList.add("hidden"); };
  $("drawer").onclick = (e) => { if (e.target.id === "drawer") $("close").click(); };
  if ($("re")) $("re").onclick = () => runCheck(m);
  if ($("remove")) $("remove").onclick = () => {
    state.monitors = state.monitors.filter((x) => x.id !== m.id);
    state.incidents = state.incidents.filter((i) => !(i.host === m.host && i.kind === m.kind));
    state.open = null; save(); $("drawer").classList.add("hidden"); render();
  };
  $("pdfOne").onclick = () => downloadPdf(m.host + "-report.pdf", reportLines(m));
  $("drawer").querySelectorAll("[data-tab]").forEach((b) => { b.onclick = () => { state.tab = b.dataset.tab; openDrawer(m.id); }; });
  bindPane(m);
}
function pane(m) {
  const r = m.result;
  if (state.tab === "overview") {
    if (!r) return "<p>Press Check again. The DNS list, certificate, mail and registration fill in from that check.</p>";
    const reachLine = m.kind === "website" ? (r.reach?.up ? "Website answered in " + r.reach.ms + " ms" : "Website did not answer") : "Domain only. There is no page to open.";
    return `<p><b>${esc(reachLine)}</b></p><p>Last check ${esc(new Date(r.at).toLocaleString())}</p>`;
  }
  if (!r) return "<p>Run a check first.</p>";
  if (state.tab === "dns") {
    const rows = r.records.length ? `<table><tr><th>Type</th><th>Value</th></tr>${r.records.map((row) => `<tr><td>${esc(row.type)}</td><td>${esc(row.data)}</td></tr>`).join("")}</table>` : "<p>No public records were returned.</p>";
    return `<button class="btn plum small" id="dnsCsv" type="button">Export DNS</button><div style="height:12px"></div>${rows}`;
  }
  if (state.tab === "mail") {
    const mail = r.mail || {};
    return table([["SPF", mail.spf], ["DMARC", mail.dmarc], ["DKIM selectors", mail.dkim], ["Spamhaus", mail.blacklist]]);
  }
  if (state.tab === "certificate") {
    const c = r.cert;
    return c ? table([["Issuer", c.issuer], ["Valid from", c.from], ["Expires", c.until], ["Days left", c.days], ["Revoked", c.revoked ? "Yes" : "No"]]) : "<p>No public certificate was found.</p>";
  }
  if (state.tab === "registration") {
    const d = r.rdap || {};
    if (d.error) return `<p>${esc(d.error)}</p>`;
    return table([["Name", d.name], ["Registrar", d.registrar], ["Status", d.status], ["Registered", d.registered], ["Updated", d.changed], ["Expires", d.expires], ["Name servers", (d.nameservers || []).join(", ")]]);
  }
  if (state.tab === "analytics") return analytics(m);
  if (state.tab === "wordpress") return wordpress(m);
  return "";
}
function analytics(m) {
  const hist = m.history || [];
  const ups = hist.filter((h) => h.up).length;
  const uptime = hist.length ? Math.round((ups / hist.length) * 100) + "%" : "—";
  const times = hist.map((h) => h.ms).filter((n) => n != null);
  const avg = times.length ? Math.round(times.reduce((a, b) => a + b, 0) / times.length) + " ms" : "—";
  const rows = hist.slice().reverse().slice(0, 20).map((h) => `<tr><td>${esc(new Date(h.at).toLocaleString())}</td><td>${h.up ? "Up" : "Down"}</td><td>${h.ms ?? "—"}</td></tr>`).join("");
  return `<div class="stats">${stat("Checks stored", hist.length)}${stat("Uptime", uptime)}${stat("Average", avg)}${stat("Open incidents", state.incidents.filter((i) => i.host === m.host).length)}</div><p>This is Sentinel's own record of checks for this website. Visitor numbers from Google or Jetpack stay in those products.</p><table><tr><th>When</th><th>Result</th><th>Response</th></tr>${rows || "<tr><td colspan='3'>No checks yet.</td></tr>"}</table>`;
}
function wordpress(m) {
  const secret = `<label for="secret">Agent secret</label><input id="secret" value="${esc(m.secret || "")}" placeholder="Same secret you pasted in the PHP file" /><button class="btn plum small" id="saveSecret" type="button" style="margin-top:10px">Save secret</button>`;
  const intro = `<p>Upload <b>flotek-sentinel-agent.php</b> to <b>wp-content/mu-plugins/</b> on this WordPress site. Put a secret in that file, then paste the same secret here. Sentinel does not log in to wp-admin.</p>${secret}`;
  if (!m.wp) return intro + `<div style="height:10px"></div><button class="btn ghost small" id="loadWp" type="button">Load WordPress</button><p class="err">${esc(m.wpError || "")}</p>`;
  const w = m.wp;
  const users = (w.users || []).map((u) => `<tr><td>${esc(u.user_login)}</td><td>${esc(u.user_email)}</td><td>${esc((u.roles || []).join(", "))}</td><td>${canEdit() ? `<button class="btn ghost small" data-wpdel="${u.id}" type="button">Delete</button>` : ""}</td></tr>`).join("");
  const plugins = (w.plugins || []).map((p) => `<tr><td>${esc(p.name)}</td><td>${esc(p.version)}${p.has_update ? " → " + esc(p.new_version) : ""}</td><td>${p.active ? "Active" : "Off"}</td><td>${canEdit() ? `<button class="btn ghost small" data-disable="${esc(p.file)}" type="button">Disable</button>` : ""}</td></tr>`).join("");
  const backups = (w.backups || []).map((b) => `<tr><td>${esc(b.filename)}</td><td>${esc(b.filesize)}</td><td>${canEdit() ? `<button class="btn ghost small" data-restore="${esc(b.filename)}" type="button">Restore</button>` : ""}</td></tr>`).join("");
  const forms = canEdit() ? `
    <h3>Site settings</h3>
    <label>Site name</label><input id="siteName" value="${esc(w.site_name || "")}" />
    <label>Tagline</label><input id="tagline" value="${esc(w.tagline || "")}" />
    <button class="btn plum small" id="saveSettings" type="button" style="margin-top:10px">Save settings</button>
    <h3>Add WordPress user</h3>
    <div class="row"><div class="grow"><input id="wu" placeholder="Username" /></div><div class="grow"><input id="we" placeholder="Email" /></div></div>
    <div class="row"><div class="grow"><input id="wpw" type="password" placeholder="Password" /></div><div><select id="wr"><option>subscriber</option><option>contributor</option><option>author</option><option>editor</option><option>administrator</option></select></div><button class="btn plum small" id="addWpUser" type="button">Add user</button></div>
    <h3>Plugins and backups</h3>
    <div class="row"><button class="btn plum small" id="updatePlugins" type="button">Update plugins</button><button class="btn ghost small" id="makeBackup" type="button">Create backup</button></div>` : "";
  return `${intro}<p><b>${esc(w.site_name || m.host)}</b> · WordPress ${esc(w.wp_version || "")} · PHP ${esc(w.php_version || "")} · Theme ${esc(w.theme?.name || "")}</p>${forms}
    <h3>Users</h3><table><tr><th>User</th><th>Email</th><th>Role</th><th></th></tr>${users || ""}</table>
    <h3>Plugins</h3><table><tr><th>Plugin</th><th>Version</th><th>State</th><th></th></tr>${plugins || ""}</table>
    <h3>Backups</h3><table><tr><th>File</th><th>Size</th><th></th></tr>${backups || "<tr><td colspan='3'>No backups yet.</td></tr>"}</table>
    <p class="err">${esc(m.wpError || "")}</p>`;
}
function bindPane(m) {
  const go = (fn) => fn().catch((e) => { m.wpError = e.message; openDrawer(m.id); });
  if ($("dnsCsv")) $("dnsCsv").onclick = () => exportDns(m);
  if ($("saveSecret")) $("saveSecret").onclick = () => { m.secret = $("secret").value.trim(); save(); m.wpError = "Secret saved in this browser."; openDrawer(m.id); };
  if ($("loadWp")) $("loadWp").onclick = () => go(() => loadWp(m));
  if ($("saveSettings")) $("saveSettings").onclick = () => go(async () => { await wpCall(m, "update-settings", "POST", { site_name: $("siteName").value, tagline: $("tagline").value }); await loadWp(m); });
  if ($("addWpUser")) $("addWpUser").onclick = () => go(async () => { await wpCall(m, "create-user", "POST", { username: $("wu").value, email: $("we").value, password: $("wpw").value, role: $("wr").value }); await loadWp(m); });
  if ($("updatePlugins")) $("updatePlugins").onclick = () => go(async () => { await wpCall(m, "update-plugins", "POST"); await loadWp(m); });
  if ($("makeBackup")) $("makeBackup").onclick = () => go(async () => { await wpCall(m, "create-backup", "POST"); await loadWp(m); });
  $("pane").querySelectorAll("[data-wpdel]").forEach((b) => { b.onclick = () => { if (confirm("Delete this WordPress user?")) go(async () => { await wpCall(m, "delete-user", "POST", { user_id: Number(b.dataset.wpdel) }); await loadWp(m); }); }; });
  $("pane").querySelectorAll("[data-disable]").forEach((b) => { b.onclick = () => go(async () => { await wpCall(m, "disable-plugin", "POST", { plugin: b.dataset.disable }); await loadWp(m); }); });
  $("pane").querySelectorAll("[data-restore]").forEach((b) => { b.onclick = () => { if (confirm("Restore this backup over the current database?")) go(async () => { await wpCall(m, "rollback", "POST", { filename: b.dataset.restore }); await loadWp(m); }); }; });
}
function exportDns(m) {
  const lines = ["Type,Value"].concat((m.result?.records || []).map((r) => r.type + "," + JSON.stringify(r.data)));
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = m.host + "-dns.csv";
  a.click();
}
function reportLines(m) {
  const r = m.result;
  const lines = [m.kind.toUpperCase() + " " + m.host, "Generated " + new Date().toLocaleString(), ""];
  if (!r) return lines.concat(["No check has been run."]);
  if (m.kind === "website") lines.push(r.reach?.up ? "Reachable in " + r.reach.ms + " ms" : "Unreachable");
  lines.push("", "DNS");
  (r.records || []).forEach((row) => lines.push(row.type + "  " + row.data));
  lines.push("", "Mail", "SPF " + (r.mail?.spf || "—"), "DMARC " + (r.mail?.dmarc || "—"), "DKIM " + (r.mail?.dkim || "—"), "Spamhaus " + (r.mail?.blacklist || "—"));
  if (r.cert) lines.push("", "Certificate", r.cert.issuer, "Expires " + r.cert.until, r.cert.days + " days left");
  if (r.rdap && !r.rdap.error) lines.push("", "Registration", "Registrar " + r.rdap.registrar, "Expires " + (r.rdap.expires || "—"), "Status " + r.rdap.status);
  const mine = state.incidents.filter((i) => i.host === m.host && i.kind === m.kind);
  lines.push("", "Open incidents");
  if (!mine.length) lines.push("None");
  mine.forEach((i) => lines.push(new Date(i.at).toLocaleString() + "  " + i.message));
  return lines;
}
function downloadPdf(filename, lines) {
  const clean = lines.map((line) => String(line).replace(/[^\x20-\x7E]/g, " ").slice(0, 100));
  if (!clean.length) clean.push("Empty");
  const groups = [];
  for (let i = 0; i < clean.length; i += 46) groups.push(clean.slice(i, i + 46));
  const body = new Array(3 + groups.length * 2);
  const kids = [];
  body[2] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";
  groups.forEach((pageLines, index) => {
    let text = "BT /F1 10 Tf 14 TL 48 800 Td\n";
    pageLines.forEach((line, n) => {
      const shown = line.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
      if (n) text += "T*\n";
      text += "(" + shown + ") Tj\n";
    });
    text += "ET";
    const contentIndex = 3 + index * 2;
    const pageIndex = 4 + index * 2;
    body[contentIndex] = "<< /Length " + text.length + " >>\nstream\n" + text + "\nendstream";
    body[pageIndex] = "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents " + (contentIndex + 1) + " 0 R /Resources << /Font << /F1 3 0 R >> >> >>";
    kids.push(pageIndex + 1);
  });
  body[1] = "<< /Type /Pages /Count " + kids.length + " /Kids [" + kids.map((id) => id + " 0 R").join(" ") + "] >>";
  body[0] = "<< /Type /Catalog /Pages 2 0 R >>";
  let pdf = "%PDF-1.4\n";
  const offsets = [0];
  body.forEach((part, i) => {
    offsets.push(pdf.length);
    pdf += (i + 1) + " 0 obj\n" + part + "\nendobj\n";
  });
  const xref = pdf.length;
  pdf += "xref\n0 " + (body.length + 1) + "\n0000000000 65535 f \n";
  offsets.slice(1).forEach((off) => { pdf += String(off).padStart(10, "0") + " 00000 n \n"; });
  pdf += "trailer << /Size " + (body.length + 1) + " /Root 1 0 R >>\nstartxref\n" + xref + "\n%%EOF";
  const blob = new Blob([pdf], { type: "application/pdf" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}
function addMonitor(value, kind) {
  if (!canEdit()) return;
  let host;
  try { host = hostOf(value); } catch (error) { alert(error.message); return; }
  if (state.monitors.some((m) => m.host === host && m.kind === kind)) { alert("That " + kind + " is already on the list."); return; }
  const mon = { id: crypto.randomUUID(), host, kind, secret: "", result: null, history: [], silenced: {} };
  state.monitors.unshift(mon);
  save();
  runCheck(mon);
}

$("loginForm").onsubmit = async (e) => {
  e.preventDefault();
  const username = $("user").value.trim().toLowerCase();
  const hash = await sha($("pass").value);
  const found = state.users.find((u) => u.username === username && u.hash === hash);
  $("loginErr").textContent = found ? "" : "That username or password is not correct.";
  if (!found) return;
  state.user = found;
  sessionStorage.setItem("fs-session", found.username);
  render();
};
$("out").onclick = () => { state.user = null; sessionStorage.removeItem("fs-session"); render(); };
document.querySelectorAll("header.app nav button").forEach((b) => { b.onclick = () => show(b.dataset.view); });
$("webForm").onsubmit = (e) => { e.preventDefault(); addMonitor($("webTarget").value, "website"); $("webTarget").value = ""; };
$("domForm").onsubmit = (e) => { e.preventDefault(); addMonitor($("domTarget").value, "domain"); $("domTarget").value = ""; };
$("demo").onclick = () => addMonitor("flotek.io", "website");
$("webList").onclick = (e) => { const b = e.target.closest("[data-id]"); if (b) { state.tab = "overview"; openDrawer(b.dataset.id); } };
$("domList").onclick = (e) => { const b = e.target.closest("[data-id]"); if (b) { state.tab = "overview"; openDrawer(b.dataset.id); } };
$("incTable").onclick = (e) => {
  const id = e.target.dataset.ack;
  if (!id || !canEdit()) return;
  const item = state.incidents.find((i) => i.id === id);
  const mon = state.monitors.find((m) => m.host === item.host && m.kind === item.kind);
  if (mon) { mon.silenced = mon.silenced || {}; mon.silenced[item.code] = true; }
  state.incidents = state.incidents.filter((i) => i.id !== id);
  save();
  render();
};
$("pdfIncidents").onclick = () => {
  const lines = ["Flotek Sentinel incidents", new Date().toLocaleString(), ""];
  if (!state.incidents.length) lines.push("No open incidents.");
  state.incidents.forEach((i) => lines.push(new Date(i.at).toLocaleString() + "  " + i.kind + "  " + i.host + "  " + i.message));
  downloadPdf("sentinel-incidents.pdf", lines);
};
$("userForm").onsubmit = async (e) => {
  e.preventDefault();
  const username = $("nUser").value.trim().toLowerCase();
  const password = $("nPass").value;
  if (!/^[a-z][a-z0-9._-]{2,31}$/.test(username)) { $("userErr").textContent = "Usernames start with a letter and use 3 to 32 letters, numbers, dots or dashes."; return; }
  if (password.length < 8 || !/[A-Za-z]/.test(password) || !/\d/.test(password)) { $("userErr").textContent = "Passwords need 8 characters, a letter and a number."; return; }
  if (state.users.some((u) => u.username === username)) { $("userErr").textContent = "That username is already in use."; return; }
  state.users.push({ username, name: $("nName").value.trim(), role: $("nRole").value, hash: await sha(password) });
  save();
  $("userErr").textContent = "";
  e.target.reset();
  render();
};
$("userTable").onclick = (e) => {
  const name = e.target.dataset.del;
  if (!name || state.user.role !== "admin") return;
  state.users = state.users.filter((u) => u.username !== name);
  save();
  render();
};
load();
render();
