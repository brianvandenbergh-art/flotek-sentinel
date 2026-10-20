const ADMIN_HASH = "96d9a2539acbf3955441217a803568ebdf7fe673db1921c3e71ead99c533881a";
const TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV"];
const $ = (id) => document.getElementById(id);
const state = { user: null, monitors: [], users: [], incidents: [], archive: [], open: null, tab: "overview", view: "websites" };

async function sha(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function readJson(key, fallback) {
  try {
    const value = JSON.parse(localStorage.getItem(key) || "");
    return value == null ? fallback : value;
  } catch {
    return fallback;
  }
}
function catalogOf(monitors) {
  return (monitors || []).filter((mon) => mon && mon.host).map((mon) => ({
    id: mon.id,
    host: mon.host,
    kind: mon.kind || "website",
    secret: mon.secret || "",
    dnsHosts: mon.dnsHosts || [],
    silenced: mon.silenced || {}
  }));
}
function mergeMonitors(lists) {
  const by = new Map();
  lists.forEach((list) => {
    (list || []).forEach((mon) => {
      if (!mon || !mon.host) return;
      const key = (mon.kind || "website") + ":" + mon.host;
      const prev = by.get(key) || {};
      by.set(key, {
        ...prev,
        ...mon,
        id: prev.id || mon.id,
        kind: mon.kind || prev.kind || "website",
        secret: mon.secret || prev.secret || "",
        dnsHosts: (mon.dnsHosts && mon.dnsHosts.length) ? mon.dnsHosts : (prev.dnsHosts || []),
        result: mon.result || prev.result || null,
        history: (mon.history && mon.history.length) ? mon.history : (prev.history || []),
        silenced: { ...(prev.silenced || {}), ...(mon.silenced || {}) }
      });
    });
  });
  return [...by.values()];
}
function load() {
  state.users = readJson("fs-users", null) || [{ username: "flotek", name: "Flotek", role: "admin", hash: ADMIN_HASH }];
  state.monitors = mergeMonitors([
    readJson("fs-catalog", []),
    readJson("fs-monitors-backup", []),
    readJson("fs-monitors", [])
  ]);
  state.incidents = readJson("fs-incidents", []);
  state.archive = readJson("fs-archive", []);
  const id = sessionStorage.getItem("fs-session");
  state.user = state.users.find((u) => u.username === id) || null;
}
function db() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("flotek-sentinel", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("store");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
function readDb() {
  return db().then((database) => new Promise((resolve) => {
    const request = database.transaction("store", "readonly").objectStore("store").get("state");
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => resolve(null);
  })).catch(() => null);
}
function writeDb(data) {
  db().then((database) => {
    database.transaction("store", "readwrite").objectStore("store").put(data, "state");
  }).catch(() => {});
}
function save() {
  const names = catalogOf(state.monitors);
  const slim = state.monitors.map((mon) => {
    const copy = { ...mon, checking: false, scanning: false };
    delete copy.waterfall;
    if (copy.result) {
      copy.result = { ...copy.result, certs: (copy.result.certs || []).slice(0, 4) };
    }
    if (copy.history) copy.history = copy.history.slice(-20);
    return copy;
  });
  try { localStorage.setItem("fs-catalog", JSON.stringify(names)); } catch (error) { console.error(error); }
  try { localStorage.setItem("fs-users", JSON.stringify(state.users)); } catch (error) { console.error(error); }
  try { localStorage.setItem("fs-incidents", JSON.stringify(state.incidents.slice(0, 200))); } catch (error) { console.error(error); }
  try { localStorage.setItem("fs-archive", JSON.stringify(state.archive.slice(0, 300))); } catch (error) { console.error(error); }
  try { localStorage.setItem("fs-monitors", JSON.stringify(slim)); } catch (error) { console.error(error); }
  writeDb({ monitors: slim, incidents: state.incidents, archive: state.archive, users: state.users });
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
  return (json.Answer || []).filter((a) => a.type !== 5 || type === "CNAME").map((a) => String(a.data).replace(/^"|"$/g, ""));
}
async function pool(items, limit, fn) {
  const out = new Array(items.length);
  let cursor = 0;
  async function worker() {
    while (cursor < items.length) {
      const index = cursor++;
      out[index] = await fn(items[index]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}
async function collectZone(mon) {
  const host = mon.host;
  const names = new Set([host]);
  ["www", "mail", "ftp", "webmail", "smtp", "imap", "pop", "autodiscover", "cpanel", "webdisk", "localhost", "email", "blog", "shop", "api", "dev", "staging", "portal", "remote", "vpn", "owa", "lyncdiscover", "sip", "enterpriseregistration", "enterpriseenrollment", "msoid", "selector1._domainkey", "selector2._domainkey", "media", "rds", "mx", "mx1", "intranet", "office", "files"].forEach((label) => names.add(label + "." + host));
  (mon.dnsHosts || []).forEach((label) => {
    const clean = String(label).trim().toLowerCase().replace(/\.$/, "");
    if (!clean) return;
    names.add(clean.endsWith("." + host) || clean === host ? clean : clean + "." + host);
  });
  try {
    const found = await fetch("https://api.hackertarget.com/hostsearch/?q=" + encodeURIComponent(host));
    const text = await found.text();
    text.split(/\s+/).forEach((line) => {
      const name = line.split(",")[0].trim().toLowerCase();
      if (!/^[a-z0-9._-]+$/.test(name)) return;
      if (name === host || name.endsWith("." + host)) names.add(name);
    });
  } catch (error) {
    /* public name list is optional */
  }
  const records = [];
  const apexTypes = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"];
  for (const type of apexTypes) {
    const rows = await dns(host, type).catch(() => []);
    rows.forEach((data) => records.push({ host: "@", type, data }));
  }
  const others = [...names].filter((name) => name !== host).slice(0, 60);
  await pool(others, 6, async (name) => {
    const label = name.slice(0, -host.length - 1);
    for (const type of ["A", "AAAA", "CNAME", "MX", "TXT"]) {
      const rows = await dns(name, type).catch(() => []);
      if (!rows.length) continue;
      rows.forEach((data) => records.push({ host: label, type, data }));
      if (type === "CNAME") break;
    }
  });
  const srv = ["_sip._tls", "_sipfederationtls._tcp", "_autodiscover._tcp", "_submission._tcp", "_imaps._tcp", "_pop3s._tcp"];
  await pool(srv, 4, async (prefix) => {
    const rows = await dns(prefix + "." + host, "SRV").catch(() => []);
    rows.forEach((data) => records.push({ host: prefix, type: "SRV", data }));
  });
  const seen = new Set();
  return records.filter((row) => {
    const key = row.host + "|" + row.type + "|" + row.data;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
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
  (mon.dnsChanges || []).forEach((change) => list.push({ code: "dns-" + change.type, message: change.message || (mon.host + " " + change.type + " changed. Was: " + (change.old || "empty") + ". Now: " + (change.now || "empty") + ".") }));
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
    const flat = await collectZone(mon);
    const lines = flat.map((row) => row.host + " " + row.type + " " + row.data).sort();
    mon.dnsChanges = [];
    if (mon.dnsSnapList) {
      const old = new Set(mon.dnsSnapList);
      const now = new Set(lines);
      lines.filter((line) => !old.has(line)).forEach((line) => mon.dnsChanges.push({ type: "add-" + line.slice(0, 48), message: mon.host + " DNS added " + line }));
      mon.dnsSnapList.filter((line) => !now.has(line)).forEach((line) => mon.dnsChanges.push({ type: "del-" + line.slice(0, 48), message: mon.host + " DNS removed " + line }));
    }
    mon.dnsSnapList = lines;
    const apexA = flat.filter((row) => row.host === "@" && row.type === "A").map((row) => row.data);
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
      mail: await mail(mon.host, apexA).catch(() => null)
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
  if (mon.wp?.visits) mon.visits = mon.wp.visits;
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
  const visibleArchive = (state.archive || []).filter((item) => {
    const mon = state.monitors.find((m) => m.host === item.host && m.kind === item.kind);
    return mon ? allowed(mon) : state.user.role === "admin";
  });
  const grouped = (list, archived) => {
    const keys = [];
    list.forEach((item) => {
      const key = item.kind + "|" + item.host;
      if (!keys.includes(key)) keys.push(key);
    });
    if (!keys.length) return archived ? "<tr><td colspan='5'>No acknowledged incidents yet.</td></tr>" : "<tr><td colspan='5'>No open incidents.</td></tr>";
    return keys.map((key) => {
      const [kind, host] = [key.slice(0, key.indexOf("|")), key.slice(key.indexOf("|") + 1)];
      const rows = list.filter((item) => item.host === host && item.kind === kind);
      return `<tr><th colspan="5">${esc(host)} · ${esc(kind)}</th></tr>` + rows.map((item) => `<tr><td>${esc(new Date(item.at).toLocaleString())}</td><td>${esc(item.host)}</td><td>${esc(item.kind)}</td><td>${esc(item.message)}</td><td class="act">${archived ? esc((item.ackBy || "") + (item.ackAt ? " · " + new Date(item.ackAt).toLocaleString() : "")) : (canEditMon(state.monitors.find((m) => m.host === item.host && m.kind === item.kind) || { kind: item.kind, host: item.host }) ? `<button class="btn ghost small" data-ack="${item.id}" type="button">Acknowledge</button>` : "")}</td></tr>`).join("");
    }).join("");
  };
  $("incTable").innerHTML = `<tr><th>When</th><th>Name</th><th>Type</th><th>What happened</th><th class="act"></th></tr><tr><th colspan="5">Open</th></tr>` + grouped(visibleIncidents, false) + `<tr><th colspan="5">Archive</th></tr>` + grouped(visibleArchive, true);
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
  const labels = { overview: "Overview", dns: "DNS", mail: "Mail", certificate: "Certificate", registration: "Registration", wordpress: "WordPress", analytics: "Analytics", seo: "SEO", security: "Security", incidents: "Incidents" };
  const tabs = m.kind === "website"
    ? ["overview", "incidents", "dns", "mail", "certificate", "registration", "seo", "security", "wordpress", "analytics"]
    : ["overview", "incidents", "dns", "mail", "certificate", "registration", "seo"];
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
  if (state.tab === "incidents") return incidentPane(m);
  if (state.tab === "dns") return dnsPane(m);
  if (state.tab === "mail") return mailPane(m);
  if (state.tab === "certificate") return certPane(m);
  if (state.tab === "registration") {
    if (!r) return "<p>Run a check first.</p>";
    const d = r.rdap || {};
    if (d.error) return `<p>${esc(d.error)}</p>`;
    return table([["Name", d.name], ["Registrar", d.registrar], ["Status", d.status], ["Registered", d.registered], ["Updated", d.changed], ["Expires", d.expires], ["Name servers", (d.nameservers || []).join(", ")]]);
  }
  if (state.tab === "analytics") return analytics(m);
  return "";
}
function dnsPane(m) {
  const records = m.result?.records || [];
  const groups = {};
  records.forEach((row) => { (groups[row.type] = groups[row.type] || []).push(row); });
  const tables = Object.keys(groups).sort().map((type) => `<h3>${esc(type)} records (${groups[type].length})</h3><table><tr><th>Host</th><th>Value</th></tr>${groups[type].map((row) => `<tr><td>${esc(row.host || "@")}</td><td>${esc(row.data)}</td></tr>`).join("")}</table>`).join("");
  return `<button class="btn plum small" id="dnsCsv" type="button">Export DNS</button>
    <p>This works for any ending, including .com, .co.uk, .co.za, .net, .org and .eu. Public DNS does not hand over the whole zone, so names that exist only in the hosting panel have to be listed once.</p>
    <label for="dnsHosts">Extra hostnames, one per line</label>
    <textarea id="dnsHosts" rows="6" style="width:100%;border:1px solid var(--line);border-radius:10px;padding:8px;font:inherit">${esc((m.dnsHosts || []).join("\n"))}</textarea>
    <button class="btn ghost small" id="saveHosts" type="button" style="margin-top:8px">Save hostnames and scan</button>
    ${tables || "<p>No records yet. Press Check again.</p>"}`;
}
function incidentPane(m) {
  const open = state.incidents.filter((item) => item.host === m.host && item.kind === m.kind);
  const old = (state.archive || []).filter((item) => item.host === m.host && item.kind === m.kind);
  const openRows = open.map((item) => `<tr><td>${esc(new Date(item.at).toLocaleString())}</td><td>${esc(item.message)}</td><td class="act">${canEditMon(m) ? `<button class="btn ghost small" data-ack="${item.id}" type="button">Acknowledge</button>` : ""}</td></tr>`).join("");
  const oldRows = old.map((item) => `<tr><td>${esc(new Date(item.at).toLocaleString())}</td><td>${esc(item.message)}</td><td>${esc(item.ackBy || "")} · ${item.ackAt ? esc(new Date(item.ackAt).toLocaleString()) : ""}</td></tr>`).join("");
  return `<h3>Open</h3><table><tr><th>When</th><th>What happened</th><th class="act"></th></tr>${openRows || "<tr><td colspan='3'>No open incidents for this " + (m.kind === "website" ? "website" : "domain") + ".</td></tr>"}</table>
    <h3>Archive</h3><table><tr><th>When</th><th>What happened</th><th>Acknowledged</th></tr>${oldRows || "<tr><td colspan='3'>Nothing has been acknowledged yet.</td></tr>"}</table>`;
}
function mailPane(m) {
  const mail = m.result?.mail || {};
  const relay = m.relay ? `<p><b>${esc(m.relay.detail)}</b></p>` : "";
  return table([["SPF", mail.spf], ["SPF check", mail.spfNote], ["DMARC", mail.dmarc], ["DMARC check", mail.dmarcNote], ["DKIM selectors", mail.dkim], ["Blacklists", mail.blacklist]])
    + relay
    + (canEditMon(m) && m.kind === "website" ? `<button class="btn ghost small" id="relay" type="button">Test open relay</button>` : "");
}
function certPane(m) {
  const certs = m.result?.certs || [];
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
    <p>Page views and visitors are on the Analytics tab, not in this speed score.</p>
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
  const visits = m.visits || m.wp?.visits || null;
  const days = (visits?.days || []).slice().reverse().map((d) => `<tr><td>${esc(d.day)}</td><td>${d.views}</td><td>${d.visitors}</td></tr>`).join("");
  const pages = (visits?.pages || []).map((p) => `<tr><td>${esc(p.path)}</td><td>${p.views}</td></tr>`).join("");
  const jetpack = (visits?.jetpack || []).map((d) => `<tr><td>${esc(d.day)}</td><td>${d.views}</td></tr>`).join("");
  const refresh = m.secret ? `<button class="btn plum small" id="loadVisits" type="button">Refresh page views</button>` : `<p>Save the agent secret on the WordPress tab. Page views are read from the website, not from this browser.</p>`;
  return `${refresh}
    <div class="stats">${stat("Page views", visits ? visits.views : "—")}${stat("Visitors", visits ? visits.visitors : "—")}${stat("Uptime", uptime)}${stat("Average response", avg)}</div>
    <p>${esc(visits?.note || "Page views appear here after the new Sentinel file is on the website and someone opens a public page.")}</p>
    <h3>Daily visits</h3><table><tr><th>Day</th><th>Page views</th><th>Visitors</th></tr>${days || "<tr><td colspan='3'>No visits recorded yet.</td></tr>"}</table>
    <h3>Top pages</h3><table><tr><th>Page</th><th>Views</th></tr>${pages || "<tr><td colspan='2'>No pages recorded yet.</td></tr>"}</table>
    ${jetpack ? `<h3>Jetpack views</h3><table><tr><th>Day</th><th>Views</th></tr>${jetpack}</table>` : ""}
    <h3>Uptime checks</h3><table><tr><th>When</th><th>Result</th><th>Response</th></tr>${rows || "<tr><td colspan='3'>No checks yet.</td></tr>"}</table>`;
}
function wordpress(m) {
  const secret = `<label for="secret">Agent secret</label><input id="secret" value="${esc(m.secret || "")}" placeholder="Same secret you pasted in the PHP file" /><button class="btn plum small" id="saveSecret" type="button" style="margin-top:10px">Save secret</button>`;
  const intro = `<p>Upload <b>flotek-sentinel-agent.php</b> to <b>wp-content/mu-plugins/</b> on this WordPress site. Put a secret in that file, then paste the same secret here. Sentinel does not log in to wp-admin.</p>${secret}`;
  if (!m.wp) return intro + `<div style="height:10px"></div><button class="btn ghost small" id="loadWp" type="button">Load WordPress</button><p class="err">${esc(m.wpError || "")}</p>`;
  const w = m.wp;
  const users = (w.users || []).map((u) => `<tr><td>${esc(u.user_login)}</td><td>${esc(u.user_email)}</td><td>${esc((u.roles || []).join(", "))}</td><td class="act">${canEditMon(m) ? `<button class="btn ghost small" data-wpdel="${u.id}" type="button">Remove</button>` : ""}</td></tr>`).join("");
  const plugins = (w.plugins || []).map((p) => `<tr><td>${esc(p.name)}</td><td>${esc(p.version)}${p.has_update ? " → " + esc(p.new_version) : ""}</td><td>${p.active ? "Active" : "Off"}</td><td class="act">${p.has_update && canEditMon(m) ? `<button class="btn plum small" data-update="${esc(p.file)}" type="button">Update</button> ` : ""}${canEditMon(m) ? `<button class="btn ghost small" data-disable="${esc(p.file)}" type="button">Disable</button>` : ""}</td></tr>`).join("");
  const backups = (w.backups || []).map((b) => `<tr><td>${esc(b.filename)}</td><td>${esc(b.filesize)}</td><td>${esc(b.location || "wp-content/flotek-backups")}</td><td class="act">${canEditMon(m) ? `<button class="btn ghost small" data-restore="${esc(b.filename)}" type="button">Restore</button>` : ""}</td></tr>`).join("");
  const forms = canEditMon(m) ? `
    <h3>Plugin updates and backups</h3>
    <p>Each plugin with an update has its own Update button. Only that plugin is changed. Disable turns one plugin off if the new version breaks the site.</p>
    <div class="row"><button class="btn ghost small" id="makeBackup" type="button">Back up database</button><button class="btn ghost small" id="fullBackup" type="button">Back up files and database</button><button class="btn ghost small" id="recovery" type="button">${m.recovery ? "Recovery mode is on" : "Turn on recovery mode"}</button></div>
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
  $("pane").querySelectorAll("[data-ack]").forEach((b) => { b.onclick = () => acknowledge(b.dataset.ack); });
  if ($("dnsCsv")) $("dnsCsv").onclick = () => exportDns(m);
  if ($("saveHosts")) $("saveHosts").onclick = () => {
    m.dnsHosts = $("dnsHosts").value.split(/\n+/).map((line) => line.trim()).filter(Boolean);
    save();
    runCheck(m);
  };
  if ($("saveSecret")) $("saveSecret").onclick = () => { m.secret = $("secret").value.trim(); save(); m.wpError = "Secret saved in this browser."; openDrawer(m.id); };
  if ($("loadWp")) $("loadWp").onclick = () => go(() => loadWp(m));
  if ($("saveSettings")) $("saveSettings").onclick = () => go(async () => { await wpCall(m, "update-settings", "POST", { site_name: $("siteName").value, tagline: $("tagline").value }); await loadWp(m); });
  if ($("addWpUser")) $("addWpUser").onclick = () => go(async () => { await wpCall(m, "create-user", "POST", { username: $("wu").value, email: $("we").value, password: $("wpw").value, role: $("wr").value }); await loadWp(m); });
  if ($("loadVisits")) $("loadVisits").onclick = () => go(async () => { m.visits = await wpCall(m, "visits", "GET"); save(); openDrawer(m.id); });
  if ($("makeBackup")) $("makeBackup").onclick = () => go(async () => { await wpCall(m, "create-backup", "POST"); m.wpError = "Database backup saved in wp-content/flotek-backups/."; await loadWp(m); });
  if ($("recovery")) $("recovery").onclick = () => { m.recovery = !m.recovery; save(); m.wpError = m.recovery ? "Recovery mode is on. Plugin loads are skipped for Sentinel requests." : "Recovery mode is off."; openDrawer(m.id); };
  if ($("uploadBackup")) $("uploadBackup").onclick = () => go(() => uploadBackup(m));
  $("pane").querySelectorAll("[data-wpdel]").forEach((b) => { b.onclick = () => { if (confirm("Delete this WordPress user?")) go(async () => { await wpCall(m, "delete-user", "POST", { user_id: Number(b.dataset.wpdel) }); await loadWp(m); }); }; });
  $("pane").querySelectorAll("[data-disable]").forEach((b) => { b.onclick = () => go(async () => { await wpCall(m, "disable-plugin", "POST", { plugin: b.dataset.disable }); await loadWp(m); }); });
  $("pane").querySelectorAll("[data-update]").forEach((b) => { b.onclick = () => { const name = b.closest("tr") ? b.closest("tr").children[0].textContent : "this plugin"; if (confirm("Update only " + name + "? The other plugins stay as they are.")) go(async () => { const result = await wpCall(m, "update-plugin", "POST", { plugin: b.dataset.update }); m.wpError = result.detail || "Plugin updated."; await loadWp(m); }); }; });
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
  const lines = ["Type,Host,Value"].concat((m.result?.records || []).map((r) => r.type + "," + JSON.stringify(r.host || "@") + "," + JSON.stringify(r.data)));
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
  (r.records || []).forEach((row) => lines.push(row.type + "  " + (row.host || "@") + "  " + row.data));
  lines.push("", "Mail", "SPF " + (r.mail?.spf || "—"), "DMARC " + (r.mail?.dmarc || "—"), "DKIM " + (r.mail?.dkim || "—"), "Spamhaus " + (r.mail?.blacklist || "—"));
  if (r.cert) lines.push("", "Certificate", r.cert.issuer, "Expires " + r.cert.until, r.cert.days + " days left");
  if (r.rdap && !r.rdap.error) lines.push("", "Registration", "Registrar " + r.rdap.registrar, "Expires " + (r.rdap.expires || "—"), "Status " + r.rdap.status);
  const mine = state.incidents.filter((i) => i.host === m.host && i.kind === m.kind);
  const archived = (state.archive || []).filter((i) => i.host === m.host && i.kind === m.kind);
  lines.push("", "Open incidents");
  if (!mine.length) lines.push("None");
  mine.forEach((i) => lines.push(new Date(i.at).toLocaleString() + "  " + i.message));
  lines.push("", "Acknowledged archive");
  if (!archived.length) lines.push("None");
  archived.forEach((i) => lines.push(new Date(i.at).toLocaleString() + "  " + i.message + "  acknowledged " + (i.ackAt ? new Date(i.ackAt).toLocaleString() : "")));
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
function acknowledge(id) {
  if (!id) return;
  const item = state.incidents.find((i) => i.id === id);
  if (!item) return;
  const mon = state.monitors.find((m) => m.host === item.host && m.kind === item.kind);
  if (mon && !canEditMon(mon)) return;
  if (!mon && state.user.role !== "admin") return;
  if (mon) { mon.silenced = mon.silenced || {}; mon.silenced[item.code] = item.message; }
  state.archive = state.archive || [];
  state.archive.unshift({ ...item, ackAt: new Date().toISOString(), ackBy: state.user.username });
  state.incidents = state.incidents.filter((i) => i.id !== id);
  save();
  render();
  if (state.open) openDrawer(state.open);
}
$("incTable").onclick = (e) => { const button = e.target.closest("[data-ack]"); if (button) acknowledge(button.dataset.ack); };
$("pdfIncidents").onclick = () => {
  const lines = ["Flotek Sentinel incidents", new Date().toLocaleString(), ""];
  const rows = state.incidents.filter((item) => {
    const mon = state.monitors.find((m) => m.host === item.host && m.kind === item.kind);
    return mon ? allowed(mon) : state.user.role === "admin";
  });
  if (!rows.length) lines.push("No open incidents.");
  rows.forEach((i) => lines.push(new Date(i.at).toLocaleString() + "  " + i.kind + "  " + i.host + "  " + i.message));
  lines.push("", "Archive");
  const archived = (state.archive || []).filter((item) => {
    const mon = state.monitors.find((m) => m.host === item.host && m.kind === item.kind);
    return mon ? allowed(mon) : state.user.role === "admin";
  });
  if (!archived.length) lines.push("No acknowledged incidents.");
  archived.forEach((i) => lines.push(new Date(i.at).toLocaleString() + "  " + i.kind + "  " + i.host + "  " + i.message));
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
readDb().then((stored) => {
  if (!stored) return;
  const before = state.monitors.length;
  state.monitors = mergeMonitors([state.monitors, stored.monitors]);
  if (Array.isArray(stored.incidents) && stored.incidents.length > state.incidents.length) state.incidents = stored.incidents;
  if (Array.isArray(stored.archive) && stored.archive.length > state.archive.length) state.archive = stored.archive;
  if (state.monitors.length !== before) {
    save();
    render();
  }
});
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
