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
function canEdit() { return state.user && state.user.role === "admin"; }
function allowed(mon) {
  if (!state.user) return false;
  if (state.user.role === "admin") return true;
  return (state.user.scope || []).includes(mon.kind + ":" + mon.host);
}
function canEditMon(mon) {
  if (!state.user || state.user.role === "viewer") return false;
  return state.user.role === "admin" || allowed(mon);
}
function websites() { return state.monitors.filter((m) => m.kind === "website" && allowed(m)); }
function domains() { return state.monitors.filter((m) => m.kind === "domain" && allowed(m)); }

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
  const res = await fetch("https://api.certspotter.com/v1/issuances?domain=" + encodeURIComponent(host) + "&include_subdomains=true&expand=issuer&expand=dns_names");
  if (!res.ok) return [];
  const list = await res.json();
  if (!Array.isArray(list)) return [];
  return list.map((cert) => ({
    issuer: cert.issuer?.friendly_name || cert.issuer?.name || "Unknown",
    from: cert.not_before,
    until: cert.not_after,
    days: Math.round((new Date(cert.not_after) - Date.now()) / 86400000),
    revoked: !!cert.revoked,
    names: (cert.dns_names || []).slice(0, 6).join(", ")
  })).sort((a, b) => new Date(b.from) - new Date(a.from));
}
async function registration(domain) {
  const labels = domain.split(".");
  const fallbacks = [
    [["co.za", "web.za", "org.za", "net.za"], "https://whois.registry.net.za/rdap/"]
  ];
  let base = "";
  try {
    const boot = await fetch("https://data.iana.org/rdap/dns.json").then((r) => r.json());
    for (let i = 1; i < labels.length; i++) {
      const tld = labels.slice(i).join(".");
      const hit = (boot.services || []).find((s) => Array.isArray(s[0]) && s[0].includes(tld));
      if (hit && hit[1] && hit[1][0]) { base = hit[1][0]; break; }
    }
  } catch (error) {
    base = "";
  }
  if (!base) {
    for (let i = 1; i < labels.length; i++) {
      const tld = labels.slice(i).join(".");
      const hit = fallbacks.find((row) => row[0].includes(tld));
      if (hit) { base = hit[1]; break; }
    }
  }
  if (!base) return { error: "No registration server is published for ." + labels.slice(1).join(".") + "." };
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
    changed: date("last changed") || date("last update of RDAP database"),
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
  let listed = [];
  const ip = (addresses || []).find((d) => /^\d+\.\d+\.\d+\.\d+$/.test(d));
  if (ip) {
    const zones = [["Spamhaus", "zen.spamhaus.org"], ["Barracuda", "b.barracudacentral.org"], ["SORBS", "dnsbl.sorbs.net"]];
    for (const zone of zones) {
      const rev = ip.split(".").reverse().join(".") + "." + zone[1];
      const bl = await dns(rev, "A");
      listed.push(zone[0] + ": " + (bl.length ? "listed" : "clear"));
    }
  }
  const spf = txt.find((d) => d.toLowerCase().includes("v=spf1")) || "";
  const dmarcRaw = dmarc.find((d) => d.toLowerCase().includes("v=dmarc1")) || "";
  return {
    spf: spf || "Missing",
    spfNote: spfNote(spf),
    dmarc: dmarcRaw || "Missing",
    dmarcNote: dmarcNote(dmarcRaw),
    dkim: dkim.length ? dkim.join(", ") : "No common selector",
    blacklist: listed.length ? listed.join("; ") : "No address to test"
  };
}
function spfNote(spf) {
  if (!spf) return "No SPF record was published.";
  if (!/^v=spf1(\s|$)/i.test(spf)) return "SPF must start with v=spf1.";
  if (/\+all\b/i.test(spf)) return "SPF ends with +all, so any server may send mail.";
  if (!/[~\-\?]all\b/i.test(spf) && !/\ball\b/i.test(spf)) return "SPF has no all mechanism, so the policy is unfinished.";
  return "SPF syntax is usable.";
}
function dmarcNote(record) {
  if (!record) return "No DMARC record was published.";
  if (!/^v=DMARC1\b/i.test(record)) return "DMARC must start with v=DMARC1.";
  const policy = (record.match(/\bp=([a-z]+)/i) || [])[1] || "";
  if (!policy) return "DMARC has no p= policy.";
  if (policy.toLowerCase() === "none") return "DMARC policy is none, so failing mail is still delivered.";
  return "DMARC policy is " + policy + ".";
}
function recordBar(mon, site) {
  if (!site) return;
  mon.bars = mon.bars || [];
  mon.bars.push({ t: Date.now(), up: !!site.up, ms: site.ms });
  if (mon.bars.length > 60) mon.bars = mon.bars.slice(-60);
}
function uptimeBar(mon) {
  const slots = (mon.bars || []).slice(-48);
  const pad = Array(Math.max(0, 48 - slots.length)).fill(null);
  const last = slots[slots.length - 1];
  const down = last && !last.up;
  const cells = pad.concat(slots).map((slot, index, all) => {
    const scanning = mon.scanning && index === all.length - 1;
    if (!slot) return `<i class="${scanning ? "scan" : ""}"></i>`;
    const when = new Date(slot.t).toLocaleString();
    const label = slot.up ? "Up" : "Down";
    return `<i class="${scanning ? "scan" : slot.up ? "ok" : "bad"}" title="${label} ${esc(when)}${slot.ms ? " · " + slot.ms + " ms" : ""}"></i>`;
  }).join("");
  const text = mon.scanning ? "Scanning" : !last ? "Waiting" : down ? "Down" : "Up";
  return `<div class="barline"><span class="${down ? "bad" : ""}">${text}</span><div class="bar" aria-label="Uptime">${cells}</div></div>`;
}
function daysUntil(value) {
  if (!value) return null;
  const n = Math.round((new Date(value) - Date.now()) / 86400000);
  return Number.isNaN(n) ? null : n;
}
function problems(mon) {
  const r = mon.result;
  const list = [];
  const lastBar = (mon.bars || []).slice(-1)[0];
  if (mon.kind === "website" && (lastBar?.up === false || (r?.reach && !r.reach.up))) {
    const when = lastBar ? new Date(lastBar.t).toLocaleString() : "the last check";
    list.push({ code: "down", message: mon.host + " went offline at " + when + ". The homepage did not answer." });
  }
  if (!r) return list;
  if (r.cert?.revoked) list.push({ code: "cert-revoked", message: "Certificate for " + mon.host + " is revoked. Issuer " + r.cert.issuer + "." });
  else if (r.cert && r.cert.days < 30) list.push({ code: "cert-soon", message: "Certificate for " + mon.host + " expires on " + r.cert.until + " (" + r.cert.days + " days)." });
  if (r.mail?.spf === "Missing") list.push({ code: "spf", message: mon.host + ": " + (r.mail.spfNote || "SPF record is missing.") });
  else if (r.mail?.spfNote && /any server|unfinished|must start/.test(r.mail.spfNote)) list.push({ code: "spf-bad", message: mon.host + ": " + r.mail.spfNote });
  if (r.mail?.dmarc === "Missing") list.push({ code: "dmarc", message: mon.host + ": " + (r.mail.dmarcNote || "DMARC record is missing.") });
  if ((r.mail?.blacklist || "").includes("listed")) list.push({ code: "blacklist", message: mon.host + " blacklist: " + r.mail.blacklist });
  const left = daysUntil(r.rdap?.expires);
  if (left != null && left < 30) list.push({ code: "domain-soon", message: mon.host + " registration expires on " + r.rdap.expires + " (" + left + " days)." });
  (mon.dnsChanges || []).forEach((change) => list.push({ code: "dns-" + change.type, message: mon.host + " " + change.type + " changed. Was: " + (change.old || "empty") + ". Now: " + (change.now || "empty") + "." }));
  (mon.security?.files?.changes || []).forEach((change) => list.push({ code: "file-" + change.file, message: mon.host + ": " + change.detail }));
  if (mon.seo?.robots_blocks_google) list.push({ code: "robots-block", message: mon.host + ": robots.txt is blocking Googlebot or all crawlers from the whole site." });
  if (mon.seo && !mon.seo.robots_present) list.push({ code: "robots-missing", message: mon.host + ": robots.txt is not on the server." });
  (mon.seo?.broken_links || []).slice(0, 6).forEach((link) => list.push({ code: "link-" + link.status + "-" + link.url, message: mon.host + " broken link " + link.url + " returned " + link.status + "." }));
  (mon.security?.vulns || []).forEach((vuln) => list.push({ code: "vuln-" + vuln.slug, message: mon.host + ": " + vuln.plugin + " " + vuln.version + " is affected. " + (vuln.cve || vuln.title) }));
  if (mon.relay?.open) list.push({ code: "relay", message: mon.relay.detail });
  return list;
}
function syncIncidents(mon) {
  const found = problems(mon);
  const codes = new Set(found.map((p) => p.code));
  mon.silenced = mon.silenced || {};
  Object.keys(mon.silenced).forEach((code) => { if (!codes.has(code)) delete mon.silenced[code]; });
  found.forEach((p) => {
    if (mon.silenced && mon.silenced[p.code] === p.message) return;
    if (state.incidents.some((i) => i.host === mon.host && i.kind === mon.kind && i.code === p.code && i.message === p.message)) return;
    state.incidents = state.incidents.filter((i) => !(i.host === mon.host && i.kind === mon.kind && i.code === p.code));
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
    const watch = ["A", "AAAA", "MX", "CNAME", "TXT"];
    const snap = {};
    watch.forEach((type) => { snap[type] = (records[type] || []).slice().sort(); });
    mon.dnsChanges = [];
    if (mon.dnsSnap) {
      watch.forEach((type) => {
        const old = (mon.dnsSnap[type] || []).join(" | ");
        const now = snap[type].join(" | ");
        if (old !== now) mon.dnsChanges.push({ type, old, now });
      });
    }
    mon.dnsSnap = snap;
    const certs = (await certificate(mon.host).catch(() => [])).slice(0, 12);
    const currentCert = certs.reduce((best, cert) => (!best || new Date(cert.until) > new Date(best.until) ? cert : best), null);
    const site = mon.kind === "website" ? await reach("https://" + mon.host + "/") : null;
    recordBar(mon, site);
    mon.result = {
      at: new Date().toISOString(),
      records: flat,
      reach: site,
      cert: currentCert,
      certs,
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
      headers: {
        "X-Hub-Secret": mon.secret,
        "Content-Type": "application/json",
        ...(mon.recovery ? { "X-Flotek-Disable": "*" } : {})
      },
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
async function runSecurity(mon) {
  mon.wpError = "";
  mon.security = await wpCall(mon, "security", "GET");
  syncIncidents(mon);
  save();
  openDrawer(mon.id);
}
async function runSeo(mon) {
  const button = $("runSeo");
  if (button) button.textContent = "Running…";
  mon.wpError = "The speed audit is running. You can keep using the rest of the page.";
  const endpoint = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=" + encodeURIComponent("https://" + mon.host + "/") + "&strategy=mobile&category=performance&category=seo";
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 40000);
  let res;
  try {
    res = await fetch(endpoint, { signal: controller.signal });
  } catch (error) {
    throw new Error(error.name === "AbortError" ? "PageSpeed took too long and was stopped. Try again in a minute." : "PageSpeed could not be reached.");
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) throw new Error("PageSpeed returned " + res.status + ". Wait a minute and run it again.");
  const data = await res.json();
  const audits = data.lighthouseResult?.audits || {};
  const pick = (id) => audits[id] ? { title: String(audits[id].title || id).slice(0, 80), value: String(audits[id].displayValue || "").slice(0, 80), score: audits[id].score } : null;
  const requests = (audits["network-requests"]?.details?.items || []).map((item) => ({
    url: String(item.url || "").slice(0, 120),
    type: item.resourceType || "",
    size: item.transferSize || 0,
    time: item.networkEndTime && item.networkRequestTime ? Math.round(item.networkEndTime - item.networkRequestTime) : null
  })).sort((a, b) => b.size - a.size).slice(0, 12);
  mon.seoAudits = ["is-crawlable", "robots-txt", "document-title", "meta-description", "http-status-code", "link-text", "crawlable-anchors", "canonical"].map(pick).filter(Boolean);
  mon.waterfall = requests;
  mon.vitals = mon.vitals || [];
  mon.vitals.push({
    at: new Date().toISOString(),
    score: Math.round((data.lighthouseResult?.categories?.performance?.score || 0) * 100),
    seo: Math.round((data.lighthouseResult?.categories?.seo?.score || 0) * 100),
    lcp: pick("largest-contentful-paint"),
    cls: pick("cumulative-layout-shift"),
    inp: pick("interaction-to-next-paint") || pick("experimental-interaction-to-next-paint")
  });
  mon.vitals = mon.vitals.slice(-12);
  if (mon.secret && mon.kind === "website") {
    mon.seo = await wpCall(mon, "seo", "GET").catch((error) => ({ robots_present: false, robots_blocks_google: false, sitemaps: [], broken_links: [], broken_images: [], error: error.message }));
    mon.journey = await wpCall(mon, "journey", "GET").catch(() => null);
  }
  syncIncidents(mon);
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
  const down = mon.kind === "website" && (mon.bars || []).slice(-1)[0]?.up === false;
  return `<button class="mon${down ? " alarm" : ""}" data-id="${mon.id}"><div><strong>${esc(mon.host)}</strong><div class="meta">${when}${extra}</div>${mon.error ? `<div class="err">${esc(mon.error)}</div>` : ""}</div><div>${pill(mon)}</div>${mon.kind === "website" ? uptimeBar(mon) : ""}</button>`;
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
  const visibleIncidents = state.incidents.filter((item) => {
    const mon = state.monitors.find((m) => m.host === item.host && m.kind === item.kind);
    return mon ? allowed(mon) : state.user.role === "admin";
  });
  const open = visibleIncidents.length;
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
    stat("Open incidents", visibleIncidents.filter((i) => i.kind === "domain").length)
  ].join("");
  $("webForm").classList.toggle("hidden", !canEdit());
  $("domForm").classList.toggle("hidden", !canEdit());
  $("webList").innerHTML = webs.length ? webs.map(card).join("") : `<div class="card"><p>No websites yet. Add one, or press Check flotek.io.</p></div>`;
  $("domList").innerHTML = doms.length ? doms.map(card).join("") : `<div class="card"><p>No domains yet. Add a domain name on its own, separate from the websites.</p></div>`;
  $("incTable").innerHTML = visibleIncidents.length
    ? `<tr><th>When</th><th>Name</th><th>Type</th><th>What happened</th><th class="act"></th></tr>` + visibleIncidents.map((i) => `<tr><td>${esc(new Date(i.at).toLocaleString())}</td><td>${esc(i.host)}</td><td>${esc(i.kind)}</td><td>${esc(i.message)}</td><td class="act">${canEditMon(state.monitors.find((m) => m.host === i.host && m.kind === i.kind) || { kind: i.kind, host: i.host }) ? `<button class="btn ghost small" data-ack="${i.id}" type="button">Acknowledge</button>` : ""}</td></tr>`).join("")
    : `<tr><td>No open incidents.</td></tr>`;
  const box = $("scopeBox");
  if (box && box.dataset.count !== String(state.monitors.length)) {
    box.dataset.count = String(state.monitors.length);
    box.innerHTML = `<span class="meta">Viewer and Operator only see the ticked names.</span><div class="scope">${state.monitors.map((m) => `<label><input type="checkbox" name="scope" value="${m.kind}:${esc(m.host)}" /> ${esc(m.host)} · ${m.kind}</label>`).join("")}</div>`;
  }
  $("userTable").innerHTML = `<tr><th>Name</th><th>Username</th><th>Role</th><th>Access</th><th class="act"></th></tr>` + state.users.map((u) => `<tr><td>${esc(u.name)}</td><td>${esc(u.username)}</td><td>${esc(u.role)}</td><td>${u.role === "admin" ? "All" : esc((u.scope || []).join(", ") || "None")}</td><td class="act">${u.username === "flotek" ? "" : `<button data-del="${esc(u.username)}" class="btn ghost small" type="button">Remove</button>`}</td></tr>`).join("");
  $("userForm").classList.toggle("hidden", state.user.role !== "admin");
}

function table(rows) {
  return `<table>${rows.map((r) => `<tr><td>${esc(r[0])}</td><td>${esc(r[1])}</td></tr>`).join("")}</table>`;
}
let drawing = false;
function openDrawer(id) {
  if (drawing) return;
  const m = state.monitors.find((x) => x.id === id);
  if (!m || !allowed(m)) return;
  drawing = true;
  try {
  state.open = id;
  const labels = { overview: "Overview", dns: "DNS", mail: "Mail", certificate: "Certificate", registration: "Registration", wordpress: "WordPress", analytics: "Analytics", seo: "SEO", security: "Security" };
  const tabs = m.kind === "website"
    ? ["overview", "dns", "mail", "certificate", "registration", "seo", "security", "wordpress", "analytics"]
    : ["overview", "dns", "mail", "certificate", "registration", "seo"];
  if (!tabs.includes(state.tab)) state.tab = "overview";
  const tabHtml = tabs.map((t) => `<button type="button" data-tab="${t}" class="${state.tab === t ? "on" : ""}">${labels[t]}</button>`).join("");
  const actions = canEditMon(m)
    ? `<button class="btn plum small" id="re" type="button">Check again</button><button class="btn ghost small" id="pdfOne" type="button">PDF report</button><button class="btn ghost small" id="remove" type="button">Remove</button>`
    : `<button class="btn ghost small" id="pdfOne" type="button">PDF report</button>`;
  $("drawer").classList.remove("hidden");
  $("drawer").innerHTML = `<div class="panel"><div class="row"><div class="grow"><h2>${esc(m.host)}</h2><p class="meta">${m.kind === "website" ? "Website" : "Domain"}</p></div><button class="btn ghost small" id="close" type="button">Close</button>${actions}</div><div class="tabs">${tabHtml}</div><div class="card" id="pane"></div></div>`;
  $("close").onclick = (e) => { e.stopPropagation(); state.open = null; $("drawer").classList.add("hidden"); };
  $("drawer").onclick = (e) => { if (e.target.id === "drawer") $("close").click(); };
  try { $("pane").innerHTML = pane(m); } catch (error) { $("pane").innerHTML = `<p class="err">${esc(error.message)}</p>`; }
  if ($("re")) $("re").onclick = (e) => { e.stopPropagation(); runCheck(m); };
  if ($("remove")) $("remove").onclick = (e) => {
    e.stopPropagation();
    state.monitors = state.monitors.filter((x) => x.id !== m.id);
    state.incidents = state.incidents.filter((i) => !(i.host === m.host && i.kind === m.kind));
    state.open = null; save(); $("drawer").classList.add("hidden"); render();
  };
  $("pdfOne").onclick = (e) => { e.stopPropagation(); downloadPdf(m.host + "-report.pdf", reportLines(m)); };
  $("drawer").querySelectorAll("[data-tab]").forEach((b) => { b.onclick = (e) => { e.preventDefault(); e.stopPropagation(); state.tab = b.dataset.tab; drawing = false; openDrawer(m.id); }; });
  bindPane(m);
  } catch (error) {
    if ($("pane")) $("pane").innerHTML = `<p class="err">${esc(error.message)}</p>`;
  } finally {
    drawing = false;
  }
}
function pane(m) {
  const r = m.result;
  if (state.tab === "overview") {
    if (!r) return "<p>Press Check again. The DNS list, certificate, mail and registration fill in from that check.</p>";
    const reachLine = m.kind === "website" ? (r.reach?.up ? "Website answered in " + r.reach.ms + " ms" : "Website did not answer") : "Domain only. There is no page to open.";
    return `<p><b>${esc(reachLine)}</b></p><p>Last check ${esc(new Date(r.at).toLocaleString())}</p>`;
  }
  if (state.tab === "seo") return seoPane(m);
  if (state.tab === "security") return securityPane(m);
  if (state.tab === "wordpress") return wordpress(m);
  if (!r) return "<p>Run a check first.</p>";
  if (state.tab === "dns") {
    const rows = r.records.length ? `<table><tr><th>Type</th><th>Value</th></tr>${r.records.map((row) => `<tr><td>${esc(row.type)}</td><td>${esc(row.data)}</td></tr>`).join("")}</table>` : "<p>No public records were returned.</p>";
    return `<button class="btn plum small" id="dnsCsv" type="button">Export DNS</button><div style="height:12px"></div>${rows}`;
  }
  if (state.tab === "mail") return mailPane(m);
  if (state.tab === "certificate") return certPane(m);
  if (state.tab === "registration") {
    const d = r.rdap || {};
    if (d.error) return `<p>${esc(d.error)}</p>`;
    return table([["Name", d.name], ["Registrar", d.registrar], ["Status", d.status], ["Registered", d.registered], ["Updated", d.changed], ["Expires", d.expires], ["Name servers", (d.nameservers || []).join(", ")]]);
  }
  if (state.tab === "analytics") return analytics(m);
  return "";
}
function mailPane(m) {
  const mail = m.result.mail || {};
  const relay = m.relay ? `<p><b>${esc(m.relay.detail)}</b></p>` : "";
  return table([["SPF", mail.spf], ["SPF check", mail.spfNote], ["DMARC", mail.dmarc], ["DMARC check", mail.dmarcNote], ["DKIM selectors", mail.dkim], ["Blacklists", mail.blacklist]])
    + relay
    + (canEditMon(m) && m.kind === "website" ? `<button class="btn ghost small" id="relay" type="button">Test open relay</button>` : "");
}
function certPane(m) {
  const certs = m.result.certs || [];
  if (!certs.length) return "<p>No public certificates were found.</p>";
  return `<table><tr><th>Issued</th><th>Expires</th><th>Issuer</th><th>Names</th><th>State</th></tr>${certs.slice(0, 12).map((c) => `<tr><td>${esc(c.from)}</td><td>${esc(c.until)}</td><td>${esc(c.issuer)}</td><td>${esc(c.names || "")}</td><td>${c.revoked ? "Revoked" : c.days + " days"}</td></tr>`).join("")}</table>`;
}
function seoPane(m) {
  const vitals = Array.isArray(m.vitals) ? m.vitals : [];
  const latest = vitals[vitals.length - 1];
  const history = vitals.slice().reverse().map((v) => `<tr><td>${esc(new Date(v.at).toLocaleString())}</td><td>${v.score}</td><td>${v.seo}</td><td>${esc(v.lcp?.value || "—")}</td><td>${esc(v.cls?.value || "—")}</td><td>${esc(v.inp?.value || "—")}</td></tr>`).join("");
  const audits = (Array.isArray(m.seoAudits) ? m.seoAudits : []).map((a) => `<tr><td>${esc(a.title)}</td><td>${a.score == null ? "—" : Math.round(a.score * 100)}</td><td>${esc(a.value || "")}</td></tr>`).join("");
  const water = (Array.isArray(m.waterfall) ? m.waterfall : []).slice(0, 15).map((item) => `<tr><td>${esc(item.url)}</td><td>${esc(item.type || "")}</td><td>${item.size ? Math.round(item.size / 1024) + " KB" : "—"}</td><td>${item.time ?? "—"}</td></tr>`).join("");
  const seo = m.seo || null;
  const sitemaps = Array.isArray(seo?.sitemaps) ? seo.sitemaps : [];
  const broken = Array.isArray(seo?.broken_links) ? seo.broken_links : [];
  const images = Array.isArray(seo?.broken_images) ? seo.broken_images : [];
  const crawl = seo ? `<p>robots.txt ${seo.robots_present ? "is present" : "is missing"}. ${seo.robots_blocks_google ? "It blocks crawlers." : "It does not block the whole site."}</p>
    <table><tr><th>Sitemap</th><th>Status</th></tr>${sitemaps.map((s) => `<tr><td>${esc(s.url)}</td><td>${s.status}</td></tr>`).join("")}</table>
    <h3>Broken links</h3>${broken.length ? `<table><tr><th>URL</th><th>Status</th></tr>${broken.map((l) => `<tr><td>${esc(l.url)}</td><td>${l.status}</td></tr>`).join("")}</table>` : "<p>No broken internal links in the sample.</p>"}
    <h3>Broken images</h3>${images.length ? images.map((l) => `<p>${esc(l.url)} · ${l.status}</p>`).join("") : "<p>No broken images in the sample.</p>"}` : "<p>WordPress crawl runs when the agent secret is saved.</p>";
  const steps = Array.isArray(m.journey?.steps) ? m.journey.steps : [];
  const journey = steps.map((s) => `<tr><td>${esc(s.path)}</td><td>${s.status}</td><td>${s.ok ? "Ok" : "Failed"}</td></tr>`).join("");
  return `<button class="btn plum small" id="runSeo" type="button">Run SEO and speed audit</button>
    ${latest ? `<div class="stats">${stat("Speed", latest.score)}${stat("SEO", latest.seo)}${stat("LCP", latest.lcp?.value || "—")}${stat("CLS", latest.cls?.value || "—")}</div>` : ""}
    <h3>History</h3><table><tr><th>When</th><th>Speed</th><th>SEO</th><th>LCP</th><th>CLS</th><th>INP</th></tr>${history || "<tr><td colspan='6'>Not run yet.</td></tr>"}</table>
    <h3>SEO checks</h3><table><tr><th>Check</th><th>Score</th><th>Detail</th></tr>${audits || "<tr><td colspan='3'>Not run yet.</td></tr>"}</table>
    <h3>Largest files</h3><table><tr><th>File</th><th>Type</th><th>Size</th><th>ms</th></tr>${water || "<tr><td colspan='4'>Not run yet.</td></tr>"}</table>
    <h3>Crawl</h3>${crawl}
    <h3>Shop path</h3>${journey ? `<table><tr><th>Path</th><th>Status</th><th>Result</th></tr>${journey}</table><p>${esc(m.journey.detail || "")}</p>` : "<p>Included with the SEO audit when the agent is connected.</p>"}
    <p class="err">${esc(m.wpError || "")}</p>`;
}
function securityPane(m) {
  if (!canEditMon(m) && state.user.role === "viewer") {
    const s = m.security;
    if (!s) return "<p>An operator needs to load the security check. You can still download the PDF report.</p>";
  }
  const s = m.security;
  const policy = s?.policy || {};
  const controls = canEditMon(m) ? `<button class="btn plum small" id="loadSecurity" type="button">Load security</button>
    <div class="row"><label><input id="autoCore" type="checkbox" ${policy.core ? "checked" : ""} style="width:auto;height:auto" /> Core updates</label>
    <label><input id="autoPlugins" type="checkbox" ${policy.plugins ? "checked" : ""} style="width:auto;height:auto" /> Plugin updates</label>
    <label><input id="autoThemes" type="checkbox" ${policy.themes ? "checked" : ""} style="width:auto;height:auto" /> Theme updates</label>
    <button class="btn ghost small" id="savePolicy" type="button">Save schedule</button></div>
    <div class="row"><button class="btn ghost small" id="pushCore" type="button">Update core now</button><button class="btn ghost small" id="pushThemes" type="button">Update themes now</button><button class="btn ghost small" id="acceptFiles" type="button">Accept file changes</button></div>` : `<button class="btn ghost small" id="loadSecurity" type="button">Refresh</button>`;
  if (!s) return controls + `<p class="err">${esc(m.wpError || "")}</p>`;
  const files = Object.entries(s.files?.files || {}).map(([name, hash]) => `<tr><td>${esc(name)}</td><td>${hash ? esc(hash.slice(0, 16)) : "Not on the server"}</td></tr>`).join("");
  const changes = (s.files?.changes || []).map((c) => `<p><b>${esc(c.file)}</b> ${esc(c.change)}. ${esc(c.detail)}</p>`).join("") || "<p>No core file changes since the baseline.</p>";
  const vulns = (s.vulns || []).map((v) => `<tr><td>${esc(v.plugin)}</td><td>${esc(v.version)}</td><td>${esc(v.cve || v.title)}</td></tr>`).join("") || "<tr><td colspan='3'>No known vulnerability matched the installed versions.</td></tr>";
  const logins = (s.logins || []).map((l) => `<tr><td>${esc(l.time)}</td><td>${esc(l.ip)}</td><td>${esc(l.username)}</td><td class="act">${canEditMon(m) ? `<button class="btn ghost small" data-block="${esc(l.ip)}" type="button">Block</button> <button class="btn ghost small" data-allow="${esc(l.ip)}" type="button">Allow</button>` : ""}</td></tr>`).join("");
  const cloud = canEditMon(m) ? `<h3>Off-site backup</h3><p>Paste a Supabase project URL and service key to upload the zip there. Leave this empty to keep the zip on the website only.</p>
    <label>Supabase URL</label><input id="sbUrl" placeholder="https://project.supabase.co" />
    <label>Service key</label><input id="sbKey" type="password" />
    <label>Bucket</label><input id="sbBucket" placeholder="sentinel" />
    <div class="row"><button class="btn ghost small" id="saveCloud" type="button">Save destination</button><button class="btn plum small" id="fullBackup" type="button">Create full backup</button></div>` : "";
  return `${controls}<h3>File integrity</h3>${changes}<table><tr><th>File</th><th>Fingerprint</th></tr>${files}</table>
    <h3>Vulnerabilities</h3><table><tr><th>Plugin</th><th>Version</th><th>Finding</th></tr>${vulns}</table>
    <h3>Failed logins</h3><table><tr><th>When</th><th>Address</th><th>Username</th><th class="act"></th></tr>${logins || "<tr><td colspan='4'>None recorded.</td></tr>"}</table>
    <p>Blocked: ${esc((s.blocked || []).join(", ") || "none")}. Allowed: ${esc((s.allowed || []).join(", ") || "none")}.</p>
    ${cloud}<p class="err">${esc(m.wpError || "")}</p>`;
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
  const users = (w.users || []).map((u) => `<tr><td>${esc(u.user_login)}</td><td>${esc(u.user_email)}</td><td>${esc((u.roles || []).join(", "))}</td><td class="act">${canEditMon(m) ? `<button class="btn ghost small" data-wpdel="${u.id}" type="button">Remove</button>` : ""}</td></tr>`).join("");
  const plugins = (w.plugins || []).map((p) => `<tr><td>${esc(p.name)}</td><td>${esc(p.version)}${p.has_update ? " → " + esc(p.new_version) : ""}</td><td>${p.active ? "Active" : "Off"}</td><td class="act">${canEditMon(m) ? `<button class="btn ghost small" data-disable="${esc(p.file)}" type="button">Disable</button>` : ""}</td></tr>`).join("");
  const backups = (w.backups || []).map((b) => `<tr><td>${esc(b.filename)}</td><td>${esc(b.filesize)}</td><td>${esc(b.location || "wp-content/flotek-backups")}</td><td class="act">${canEditMon(m) ? `<button class="btn ghost small" data-restore="${esc(b.filename)}" type="button">Restore</button>` : ""}</td></tr>`).join("");
  const forms = canEditMon(m) ? `
    <h3>Plugin updates and backups</h3>
    <p>Update plugins installs the available updates on this website now. Disable turns one plugin off. Use that if an update breaks the site.</p>
    <div class="row"><button class="btn plum small" id="updatePlugins" type="button">Update plugins</button><button class="btn ghost small" id="makeBackup" type="button">Back up database</button><button class="btn ghost small" id="fullBackup" type="button">Back up files and database</button><button class="btn ghost small" id="recovery" type="button">${m.recovery ? "Recovery mode is on" : "Turn on recovery mode"}</button></div>
    <p>Backups are saved on the website in <b>wp-content/flotek-backups/</b>. Restore puts that copy back. Recovery mode switches normal plugins off for Sentinel's request, so a broken plugin cannot stop the restore. It cannot repair wp-config.php or the Sentinel file itself.</p>
    <label>Upload a .sql or .zip backup</label>
    <input id="backupFile" type="file" accept=".sql,.zip,application/zip,application/sql" />
    <button class="btn ghost small" id="uploadBackup" type="button" style="margin-top:8px">Upload and store on the site</button>
    <h3>Site settings</h3>
    <label>Site name</label><input id="siteName" value="${esc(w.site_name || "")}" />
    <label>Tagline</label><input id="tagline" value="${esc(w.tagline || "")}" />
    <button class="btn plum small" id="saveSettings" type="button" style="margin-top:10px">Save settings</button>
    <h3>Add WordPress user</h3>
    <div class="row"><div class="grow"><input id="wu" placeholder="Username" /></div><div class="grow"><input id="we" placeholder="Email" /></div></div>
    <div class="row"><div class="grow"><input id="wpw" type="password" placeholder="Password" /></div><div><select id="wr"><option>subscriber</option><option>contributor</option><option>author</option><option>editor</option><option>administrator</option></select></div><button class="btn plum small" id="addWpUser" type="button">Add user</button></div>` : "";
  return `${intro}<p><b>${esc(w.site_name || m.host)}</b> · WordPress ${esc(w.wp_version || "")} · PHP ${esc(w.php_version || "")} · Theme ${esc(w.theme?.name || "")}</p>${forms}
    <h3>Users</h3><table><tr><th>User</th><th>Email</th><th>Role</th><th></th></tr>${users || ""}</table>
    <h3>Plugins</h3><table><tr><th>Plugin</th><th>Version</th><th>State</th><th class="act"></th></tr>${plugins || ""}</table>
    <h3>Backups on the server</h3><table><tr><th>File</th><th>Size</th><th>Where</th><th class="act"></th></tr>${backups || "<tr><td colspan='4'>No backups yet. Use Back up database or Back up files and database.</td></tr>"}</table>
    <p class="err">${esc(m.wpError || "")}</p>`;
}
async function uploadBackup(mon) {
  const file = $("backupFile") && $("backupFile").files ? $("backupFile").files[0] : null;
  if (!file) throw new Error("Choose a .sql or .zip file first.");
  if (file.size > 6 * 1024 * 1024) throw new Error("That file is over 6 MB. Create the backup from this page so it stays on the server.");
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let i = 0; i < bytes.length; i += 8000) binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 8000));
  const result = await wpCall(mon, "upload-backup", "POST", { filename: file.name, content: btoa(binary) });
  mon.wpError = result.detail || "Upload stored on the website.";
  await loadWp(mon);
}
function bindPane(m) {
  const go = (fn) => fn().catch((e) => { m.wpError = e.message; openDrawer(m.id); });
  if ($("dnsCsv")) $("dnsCsv").onclick = () => exportDns(m);
  if ($("saveSecret")) $("saveSecret").onclick = () => { m.secret = $("secret").value.trim(); save(); m.wpError = "Secret saved in this browser."; openDrawer(m.id); };
  if ($("loadWp")) $("loadWp").onclick = () => go(() => loadWp(m));
  if ($("saveSettings")) $("saveSettings").onclick = () => go(async () => { await wpCall(m, "update-settings", "POST", { site_name: $("siteName").value, tagline: $("tagline").value }); await loadWp(m); });
  if ($("addWpUser")) $("addWpUser").onclick = () => go(async () => { await wpCall(m, "create-user", "POST", { username: $("wu").value, email: $("we").value, password: $("wpw").value, role: $("wr").value }); await loadWp(m); });
  if ($("updatePlugins")) $("updatePlugins").onclick = () => { if (confirm("Install the available plugin updates on this website now?")) go(async () => { await wpCall(m, "update-plugins", "POST"); await loadWp(m); }); };
  if ($("makeBackup")) $("makeBackup").onclick = () => go(async () => { await wpCall(m, "create-backup", "POST"); m.wpError = "Database backup saved in wp-content/flotek-backups/."; await loadWp(m); });
  if ($("recovery")) $("recovery").onclick = () => { m.recovery = !m.recovery; save(); m.wpError = m.recovery ? "Recovery mode is on. Plugin loads are skipped for Sentinel requests." : "Recovery mode is off."; openDrawer(m.id); };
  if ($("uploadBackup")) $("uploadBackup").onclick = () => go(() => uploadBackup(m));
  $("pane").querySelectorAll("[data-wpdel]").forEach((b) => { b.onclick = () => { if (confirm("Delete this WordPress user?")) go(async () => { await wpCall(m, "delete-user", "POST", { user_id: Number(b.dataset.wpdel) }); await loadWp(m); }); }; });
  $("pane").querySelectorAll("[data-disable]").forEach((b) => { b.onclick = () => go(async () => { await wpCall(m, "disable-plugin", "POST", { plugin: b.dataset.disable }); await loadWp(m); }); });
  $("pane").querySelectorAll("[data-restore]").forEach((b) => { b.onclick = () => { if (confirm("Restore this backup over the live site? Turn recovery mode on first if a plugin is causing a fatal error.")) go(async () => { const result = await wpCall(m, "restore-backup", "POST", { filename: b.dataset.restore }); m.wpError = result.detail || "Restore finished."; await loadWp(m); }); }; });
  if ($("relay")) $("relay").onclick = () => go(async () => { m.relay = await wpCall(m, "relay", "GET"); syncIncidents(m); save(); openDrawer(m.id); });
  if ($("runSeo")) $("runSeo").onclick = () => go(() => runSeo(m));
  if ($("loadSecurity")) $("loadSecurity").onclick = () => go(() => runSecurity(m));
  if ($("savePolicy")) $("savePolicy").onclick = () => go(async () => { await wpCall(m, "update-policy", "POST", { core: $("autoCore").checked, plugins: $("autoPlugins").checked, themes: $("autoThemes").checked }); await runSecurity(m); });
  if ($("pushCore")) $("pushCore").onclick = () => { if (confirm("Update WordPress core on this site now?")) go(async () => { await wpCall(m, "update-core", "POST"); await runSecurity(m); }); };
  if ($("pushThemes")) $("pushThemes").onclick = () => go(async () => { await wpCall(m, "update-themes", "POST"); await runSecurity(m); });
  if ($("acceptFiles")) $("acceptFiles").onclick = () => go(async () => { await wpCall(m, "accept-files", "POST"); await runSecurity(m); });
  if ($("saveCloud")) $("saveCloud").onclick = () => go(async () => { await wpCall(m, "backup-settings", "POST", { supabase_url: $("sbUrl").value, supabase_key: $("sbKey").value, bucket: $("sbBucket").value }); m.wpError = "Backup destination saved."; openDrawer(m.id); });
  if ($("fullBackup")) $("fullBackup").onclick = () => go(async () => { const result = await wpCall(m, "create-full-backup", "POST"); m.wpError = result.detail || "Backup created."; await loadWp(m); });
  $("pane").querySelectorAll("[data-block]").forEach((b) => { b.onclick = () => go(async () => { await wpCall(m, "block-ip", "POST", { ip: b.dataset.block, block: true }); await runSecurity(m); }); });
  $("pane").querySelectorAll("[data-allow]").forEach((b) => { b.onclick = () => go(async () => { await wpCall(m, "allow-ip", "POST", { ip: b.dataset.allow, allow: true }); await runSecurity(m); }); });
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
  if (!id) return;
  const item = state.incidents.find((i) => i.id === id);
  const mon = state.monitors.find((m) => m.host === item.host && m.kind === item.kind);
  if (mon && !canEditMon(mon)) return;
  if (!mon && state.user.role !== "admin") return;
  if (mon) { mon.silenced = mon.silenced || {}; mon.silenced[item.code] = item.message; }
  state.incidents = state.incidents.filter((i) => i.id !== id);
  save();
  render();
};
$("pdfIncidents").onclick = () => {
  const lines = ["Flotek Sentinel incidents", new Date().toLocaleString(), ""];
  const rows = state.incidents.filter((item) => {
    const mon = state.monitors.find((m) => m.host === item.host && m.kind === item.kind);
    return mon ? allowed(mon) : state.user.role === "admin";
  });
  if (!rows.length) lines.push("No open incidents.");
  rows.forEach((i) => lines.push(new Date(i.at).toLocaleString() + "  " + i.kind + "  " + i.host + "  " + i.message));
  downloadPdf("sentinel-incidents.pdf", lines);
};
$("userForm").onsubmit = async (e) => {
  e.preventDefault();
  const username = $("nUser").value.trim().toLowerCase();
  const password = $("nPass").value;
  if (!/^[a-z][a-z0-9._-]{2,31}$/.test(username)) { $("userErr").textContent = "Usernames start with a letter and use 3 to 32 letters, numbers, dots or dashes."; return; }
  if (password.length < 8 || !/[A-Za-z]/.test(password) || !/\d/.test(password)) { $("userErr").textContent = "Passwords need 8 characters, a letter and a number."; return; }
  if (state.users.some((u) => u.username === username)) { $("userErr").textContent = "That username is already in use."; return; }
  const role = $("nRole").value;
  const scope = [...document.querySelectorAll("input[name=scope]:checked")].map((input) => input.value);
  if (role !== "admin" && !scope.length) { $("userErr").textContent = "Tick the websites or domains this person may see."; return; }
  state.users.push({ username, name: $("nName").value.trim(), role, hash: await sha(password), scope });
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
state.monitors.forEach((mon) => {
  if (mon.result?.certs) mon.result.certs = mon.result.certs.slice(0, 12);
  if (mon.waterfall) mon.waterfall = mon.waterfall.slice(0, 12).map((item) => ({ url: String(item.url || "").slice(0, 120), type: item.type || "", size: item.size || 0, time: item.time }));
});
let ticking = false;
async function liveTick() {
  if (!state.user || ticking) return;
  const list = websites();
  if (!list.length) return;
  ticking = true;
  try {
    for (const mon of list) {
      mon.scanning = true;
      render();
      const site = await reach("https://" + mon.host + "/");
      mon.scanning = false;
      recordBar(mon, site);
      mon.result = mon.result || { records: [], at: new Date().toISOString() };
      mon.result.reach = site;
      mon.result.at = new Date().toISOString();
      syncIncidents(mon);
      render();
    }
    save();
  } finally {
    ticking = false;
  }
}
setInterval(liveTick, 45000);
setTimeout(liveTick, 4000);
render();
