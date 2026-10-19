import { randomUUID } from "node:crypto";
import { getSql } from "@/lib/db";
import {
  assertRole,
  changeOwnPassword,
  createStaffUser,
  getHubSecret,
  getStaff,
  listStaff,
  removeStaffUser,
  resolveStaff,
  secretsMatch,
  setStaffRole,
  type Role,
  type Staff,
  validateNewUser,
} from "@/lib/sentinel/bootstrap.server";
import {
  assertPublicHost,
  checkHttp,
  inspectMail,
  inspectSsl,
  lookupRdap,
  normalizeHost,
  probeAgent,
  scanDns,
  type DnsRecord,
} from "@/lib/sentinel/checks.server";

type MonitorRow = {
  id: string;
  kind: "website" | "domain";
  name: string;
  target: string;
  host: string;
  paused: boolean;
  keyword: string | null;
  status: string;
  http_code: number | null;
  error_message: string | null;
  latency_ms: number | null;
  failure_streak: number;
  uptime_pct: number;
  samples: string;
  ssl: string | null;
  dns_records: string;
  dns_meta: string | null;
  whois: string | null;
  mail: string | null;
  diagnostic: string | null;
  headers: string | null;
  redirects: string | null;
  wp: string | null;
  agent_seen_at: string | null;
  created_by: string;
  created_at: string;
  last_check_at: string | null;
  dns_checked_at: string | null;
};

export type Monitor = Omit<MonitorRow, "samples" | "ssl" | "dns_records" | "dns_meta" | "whois" | "mail" | "diagnostic" | "headers" | "redirects" | "wp"> & {
  samples: { t: string; up: number; ms: number }[];
  ssl: Record<string, unknown> | null;
  dns_records: DnsRecord[];
  dns_meta: Record<string, unknown> | null;
  whois: Record<string, unknown> | null;
  mail: Record<string, unknown> | null;
  diagnostic: Record<string, unknown> | null;
  headers: { name: string; value: string }[];
  redirects: { url: string; status: number }[];
  wp: Record<string, unknown> | null;
  backups: { id: string; filename: string; filesize: string | null; location: string | null; created_at: string }[];
};

function parseJson<T>(value: string | null | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function present(row: MonitorRow, backups: Monitor["backups"]): Monitor {
  return {
    ...row,
    samples: parseJson(row.samples, []),
    ssl: parseJson(row.ssl, null),
    dns_records: parseJson(row.dns_records, []),
    dns_meta: parseJson(row.dns_meta, null),
    whois: parseJson(row.whois, null),
    mail: parseJson(row.mail, null),
    diagnostic: parseJson(row.diagnostic, null),
    headers: parseJson(row.headers, []),
    redirects: parseJson(row.redirects, []),
    wp: parseJson(row.wp, null),
    backups,
  };
}

async function loadBackups(monitorId?: string) {
  const sql = await getSql();
  if (monitorId) {
    return sql<{ id: string; monitor_id: string; filename: string; filesize: string | null; location: string | null; created_at: string }>`
      select id, monitor_id, filename, filesize, location, created_at from backups where monitor_id = ${monitorId} order by created_at desc
    `;
  }
  return sql<{ id: string; monitor_id: string; filename: string; filesize: string | null; location: string | null; created_at: string }>`
    select id, monitor_id, filename, filesize, location, created_at from backups order by created_at desc
  `;
}

async function readMonitor(id: string): Promise<Monitor | null> {
  const sql = await getSql();
  const rows = await sql<MonitorRow>`select * from monitors where id = ${id}`;
  const row = rows[0];
  if (!row) return null;
  const backups = await loadBackups(id);
  return present(row, backups);
}

async function sessionUser(userId: string) {
  const sql = await getSql();
  const rows = await sql<{ id: string; email: string; name: string }>`select id, email, name from "user" where id = ${userId}`;
  return rows[0] ?? { id: userId, email: null, name: null };
}

export async function loadConsole(userId: string) {
  const user = await sessionUser(userId);
  const staff = await resolveStaff(user);
  if (!staff) return { staff: null, monitors: [], incidents: [], secret: null, team: [] };
  const sql = await getSql();
  const rows = await sql<MonitorRow>`select * from monitors order by created_at desc`;
  const backups = await loadBackups();
  const monitors = rows.map((row) =>
    present(
      row,
      backups.filter((item) => item.monitor_id === row.id),
    ),
  );
  const incidents = await sql`
    select id, monitor_id, host, name, event, type, details, archived, acknowledged_at, acknowledged_by, created_at
    from incidents order by created_at desc limit 200
  `;
  const secret = staff.role === "viewer" ? null : await getHubSecret();
  const team = staff.role === "admin" ? await listStaff() : [];
  return { staff, monitors, incidents, secret, team };
}

function cleanTarget(kind: "website" | "domain", target: string) {
  const trimmed = target.trim();
  if (kind === "website") {
    const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    let url: URL;
    try {
      url = new URL(withScheme);
    } catch {
      throw new Error("Enter a full website address, such as https://example.co.uk.");
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("Only http and https websites can be monitored.");
    return { target: url.origin, host: normalizeHost(url.hostname), nameHost: url.hostname };
  }
  const host = normalizeHost(trimmed);
  return { target: host, host, nameHost: host };
}

export async function addMonitor(
  userId: string,
  input: { kind: "website" | "domain"; target: string; name?: string; keyword?: string },
) {
  const staff = await mustStaff(userId);
  assertRole(staff, ["admin", "operator"]);
  if (input.kind !== "website" && input.kind !== "domain") throw new Error("Choose a website or a domain.");
  const cleaned = cleanTarget(input.kind, input.target);
  await assertPublicHost(cleaned.host);
  const sql = await getSql();
  const duplicate = await sql<{ id: string }>`select id from monitors where host = ${cleaned.host} and kind = ${input.kind}`;
  if (duplicate[0]) throw new Error("That monitor is already on the fleet.");
  const id = randomUUID();
  const name = (input.name || cleaned.nameHost).trim().slice(0, 80);
  const keyword = input.keyword?.trim().slice(0, 120) || null;
  await sql`
    insert into monitors (id, kind, name, target, host, keyword, created_by, status)
    values (${id}, ${input.kind}, ${name}, ${cleaned.target}, ${cleaned.host}, ${keyword}, ${userId}, 'PENDING')
  `;
  await refreshMonitor(id, true);
  return readMonitor(id);
}

async function mustStaff(userId: string): Promise<Staff> {
  const user = await sessionUser(userId);
  const staff = await resolveStaff(user);
  if (!staff) throw new Error("This account is not on the Sentinel team.");
  return staff;
}

async function mustMonitor(id: string): Promise<Monitor> {
  const monitor = await readMonitor(id);
  if (!monitor) throw new Error("That monitor is no longer on the fleet.");
  return monitor;
}

export async function setPaused(userId: string, id: string, paused: boolean) {
  const staff = await mustStaff(userId);
  assertRole(staff, ["admin", "operator"]);
  const sql = await getSql();
  await sql`update monitors set paused = ${paused} where id = ${id}`;
  return readMonitor(id);
}

export async function removeMonitor(userId: string, id: string) {
  const staff = await mustStaff(userId);
  assertRole(staff, ["admin", "operator"]);
  const sql = await getSql();
  await sql`delete from backups where monitor_id = ${id}`;
  await sql`delete from incidents where monitor_id = ${id}`;
  await sql`delete from monitors where id = ${id}`;
  return { ok: true };
}

function pushSample(existing: string, up: number, ms: number) {
  const samples = parseJson<{ t: string; up: number; ms: number }[]>(existing, []);
  samples.push({ t: new Date().toISOString(), up, ms });
  const trimmed = samples.slice(-288);
  const upCount = trimmed.filter((sample) => sample.up === 1).length;
  const pct = trimmed.length ? Math.round((upCount / trimmed.length) * 100) : 100;
  return { json: JSON.stringify(trimmed), pct };
}

export async function refreshMonitor(id: string, deep: boolean) {
  const sql = await getSql();
  const rows = await sql<MonitorRow>`select * from monitors where id = ${id}`;
  const row = rows[0];
  if (!row || row.paused) return readMonitor(id);
  const target = row.kind === "website" ? row.target : `https://${row.host}`;
  const http = await checkHttp(target, row.keyword);
  let status = http.status;
  let streak = http.status === "OFFLINE" ? (row.failure_streak || 0) + 1 : 0;
  if (http.status === "OFFLINE" && streak < 2 && row.status === "ONLINE") status = "ONLINE";
  const confirmedDown = http.status === "OFFLINE" && streak >= 2;
  const sample = pushSample(row.samples, http.status === "ONLINE" ? 1 : 0, http.latency_ms);
  let ssl = row.ssl;
  let dnsRecords = row.dns_records;
  let dnsMeta = row.dns_meta;
  let whois = row.whois;
  let mail = row.mail;
  let dnsChecked = row.dns_checked_at;
  const staleDns = !row.dns_checked_at || Date.now() - new Date(row.dns_checked_at).getTime() > 6 * 60 * 60 * 1000;
  if (deep || staleDns || dnsRecords === "[]") {
    const dns = await scanDns(row.host);
    dnsRecords = JSON.stringify(dns.records);
    dnsMeta = JSON.stringify(dns.meta);
    whois = JSON.stringify(await lookupRdap(row.host));
    mail = JSON.stringify(await inspectMail(row.host));
    ssl = JSON.stringify(await inspectSsl(row.host));
    dnsChecked = new Date().toISOString();
  } else if (!ssl) {
    ssl = JSON.stringify(await inspectSsl(row.host));
  }
  let wp = row.wp;
  let agentSeen = row.agent_seen_at;
  let diagnostic = {
    summary: http.error_message,
    cause: http.status === "ONLINE" ? "none" : http.keyword_ok === false ? "keyword_missing" : "http",
  };
  if (row.kind === "website" && http.status === "OFFLINE") {
    const secret = await getHubSecret();
    const agent = await probeAgent(row.target, secret);
    if (agent.reachable) {
      wp = JSON.stringify(agent.body ?? {});
      agentSeen = new Date().toISOString();
      diagnostic = {
        summary: "The server answered the Sentinel agent, but the public page failed. This points at the site application, not a dead server.",
        cause: "application",
      };
    }
  }
  await sql`
    update monitors set
      status = ${confirmedDown || http.status === "ONLINE" ? http.status : status},
      http_code = ${http.http_code},
      error_message = ${http.error_message},
      latency_ms = ${http.latency_ms},
      failure_streak = ${streak},
      uptime_pct = ${sample.pct},
      samples = ${sample.json},
      ssl = ${ssl},
      dns_records = ${dnsRecords},
      dns_meta = ${dnsMeta},
      whois = ${whois},
      mail = ${mail},
      diagnostic = ${JSON.stringify(diagnostic)},
      headers = ${JSON.stringify(http.headers)},
      redirects = ${JSON.stringify(http.redirects)},
      wp = ${wp},
      agent_seen_at = ${agentSeen},
      last_check_at = ${new Date().toISOString()},
      dns_checked_at = ${dnsChecked}
    where id = ${id}
  `;
  if (confirmedDown && row.status !== "OFFLINE") {
    await addIncident(row, "SITE_DOWN", "OUTAGE", http.error_message);
  } else if (http.status === "ONLINE" && row.status === "OFFLINE") {
    await addIncident(row, "SITE_RECOVERED", "RECOVERY", `Back online in ${http.latency_ms} ms`);
  }
  return readMonitor(id);
}

async function addIncident(row: { id: string; host: string; name: string }, event: string, type: string, detail: string) {
  const sql = await getSql();
  await sql`
    insert into incidents (id, monitor_id, host, name, event, type, details)
    values (${randomUUID()}, ${row.id}, ${row.host}, ${row.name}, ${event}, ${type}, ${JSON.stringify({ message: detail })})
  `;
}

export async function runDueChecks(userId: string) {
  await mustStaff(userId);
  const sql = await getSql();
  const rows = await sql<{ id: string }>`select id from monitors where paused = false order by last_check_at asc nulls first limit 6`;
  for (const row of rows) {
    await refreshMonitor(row.id, false);
  }
  return loadConsole(userId);
}

export async function rescan(userId: string, id: string) {
  const staff = await mustStaff(userId);
  assertRole(staff, ["admin", "operator"]);
  await mustMonitor(id);
  return refreshMonitor(id, true);
}

export async function acknowledge(userId: string, id: string, archived: boolean) {
  const staff = await mustStaff(userId);
  assertRole(staff, ["admin", "operator"]);
  const sql = await getSql();
  if (archived) {
    await sql`
      update incidents set archived = true, acknowledged_at = ${new Date().toISOString()}, acknowledged_by = ${userId}
      where id = ${id}
    `;
  } else {
    await sql`
      update incidents set archived = false, acknowledged_at = null, acknowledged_by = null where id = ${id}
    `;
  }
  return { ok: true };
}

export async function teamAction(
  userId: string,
  action: "create" | "remove" | "role" | "password",
  payload: Record<string, string>,
) {
  const staff = await mustStaff(userId);
  if (action === "password") {
    await changeOwnPassword(userId, payload.current || "", payload.next || "");
    return { ok: true };
  }
  assertRole(staff, ["admin"]);
  if (action === "create") {
    const valid = validateNewUser({
      name: payload.name || "",
      username: payload.username || "",
      email: payload.email || "",
      password: payload.password || "",
      role: payload.role || "",
    });
    const created = await createStaffUser(valid);
    return { ok: true, user: created };
  }
  if (action === "remove") {
    await removeStaffUser(payload.userId || "", userId);
    return { ok: true };
  }
  const role = payload.role;
  if (role !== "admin" && role !== "operator" && role !== "viewer") throw new Error("Choose a role.");
  await setStaffRole(payload.userId || "", role, userId);
  return { ok: true };
}

async function agentCall(monitor: Monitor, path: string, body?: unknown, extraHeaders?: Record<string, string>) {
  if (monitor.kind !== "website") throw new Error("That action is only available for websites.");
  const secret = await getHubSecret();
  const response = await fetch(`${monitor.target.replace(/\/+$/, "")}/wp-json/flotek/v1/${path}`, {
    method: body ? "POST" : "GET",
    signal: AbortSignal.timeout(20000),
    headers: {
      "Content-Type": "application/json",
      "X-Hub-Secret": secret,
      "User-Agent": "FlotekSentinel/1.0",
      ...extraHeaders,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let parsed: Record<string, unknown> = {};
  try {
    parsed = JSON.parse(text) as Record<string, unknown>;
  } catch {
    parsed = { raw: text.slice(0, 300) };
  }
  if (!response.ok || parsed.success === false) {
    throw new Error(String(parsed.error || parsed.message || `The site agent returned ${response.status}`));
  }
  return parsed;
}

export async function wordpressAction(userId: string, id: string, action: string, payload: Record<string, string>) {
  const staff = await mustStaff(userId);
  assertRole(staff, ["admin", "operator"]);
  const monitor = await mustMonitor(id);
  await assertPublicHost(monitor.host);
  if (action === "refresh") {
    const health = await agentCall(monitor, "health");
    const sql = await getSql();
    await sql`update monitors set wp = ${JSON.stringify(health)}, agent_seen_at = ${new Date().toISOString()} where id = ${id}`;
    return readMonitor(id);
  }
  if (action === "backup") {
    const result = await agentCall(monitor, "create-backup", {});
    const sql = await getSql();
    await sql`
      insert into backups (id, monitor_id, filename, filesize, location)
      values (${randomUUID()}, ${id}, ${String(result.filename || "backup.sql")}, ${String(result.filesize || "")}, ${String(result.location || "")})
    `;
    return readMonitor(id);
  }
  if (action === "rollback") {
    if (!payload.filename) throw new Error("Choose a backup.");
    await agentCall(monitor, "rollback", { filename: payload.filename });
    return readMonitor(id);
  }
  if (action === "disable-plugin") {
    if (!payload.plugin) throw new Error("Choose a plugin.");
    await agentCall(monitor, "disable-plugin", { plugin: payload.plugin }, { "X-Flotek-Disable": payload.plugin });
    return wordpressAction(userId, id, "refresh", {});
  }
  if (action === "create-user") {
    await agentCall(monitor, "create-user", payload);
    return wordpressAction(userId, id, "refresh", {});
  }
  if (action === "reset-password") {
    await agentCall(monitor, "reset-password", payload);
    return { ok: true };
  }
  if (action === "delete-user") {
    await agentCall(monitor, "delete-user", payload);
    return wordpressAction(userId, id, "refresh", {});
  }
  if (action === "update-plugins") {
    await agentCall(monitor, "update-plugins", {});
    return wordpressAction(userId, id, "refresh", {});
  }
  throw new Error("Unknown website action.");
}

export async function registerFromAgent(secret: string, body: Record<string, unknown>) {
  const expected = await getHubSecret();
  if (!secretsMatch(secret, expected)) {
    const error = new Error("Unauthorized");
    (error as Error & { status: number }).status = 403;
    throw error;
  }
  const siteUrl = String(body.site_url || "");
  const cleaned = cleanTarget("website", siteUrl);
  await assertPublicHost(cleaned.host);
  const sql = await getSql();
  const existing = await sql<{ id: string }>`select id from monitors where host = ${cleaned.host} and kind = 'website'`;
  const wp = JSON.stringify({
    wp_version: body.wp_version,
    php_version: body.php_version,
    theme: body.theme,
    plugins: body.plugins,
    users: body.users,
    performance: body.performance,
    file_audit: body.file_audit,
  });
  if (existing[0]) {
    await sql`update monitors set wp = ${wp}, agent_seen_at = ${new Date().toISOString()}, name = coalesce(nullif(${String(body.site_name || "")}, ''), name) where id = ${existing[0].id}`;
    return { ok: true, id: existing[0].id };
  }
  const admin = await sql<{ user_id: string }>`select user_id from staff_profiles where role = 'admin' order by created_at asc limit 1`;
  const id = randomUUID();
  await sql`
    insert into monitors (id, kind, name, target, host, created_by, status, wp, agent_seen_at)
    values (${id}, 'website', ${String(body.site_name || cleaned.host).slice(0, 80)}, ${cleaned.target}, ${cleaned.host}, ${admin[0]?.user_id || "agent"}, 'PENDING', ${wp}, ${new Date().toISOString()})
  `;
  return { ok: true, id };
}

export async function recordAgentEvent(secret: string, body: Record<string, unknown>) {
  const expected = await getHubSecret();
  if (!secretsMatch(secret, expected)) throw new Error("Unauthorized");
  const host = normalizeHost(String(body.site_url || body.domain || ""));
  const sql = await getSql();
  const monitor = host
    ? (await sql<{ id: string; name: string }>`select id, name from monitors where host = ${host} limit 1`)[0]
    : undefined;
  await sql`
    insert into incidents (id, monitor_id, host, name, event, type, details)
    values (
      ${randomUUID()},
      ${monitor?.id || null},
      ${host},
      ${String(body.site_name || monitor?.name || host)},
      ${String(body.event || "AGENT_EVENT").slice(0, 80)},
      ${String(body.type || "SECURITY").slice(0, 40)},
      ${JSON.stringify(body.details || {})}
    )
  `;
  return { ok: true };
}

export async function buildReport(userId: string, id: string) {
  await mustStaff(userId);
  const monitor = await mustMonitor(id);
  return {
    generated_at: new Date().toISOString(),
    monitor: {
      name: monitor.name,
      host: monitor.host,
      kind: monitor.kind,
      status: monitor.status,
      uptime_pct: monitor.uptime_pct,
      latency_ms: monitor.latency_ms,
      last_check_at: monitor.last_check_at,
      error_message: monitor.error_message,
    },
    ssl: monitor.ssl,
    dns_records: monitor.dns_records,
    dns_meta: monitor.dns_meta,
    whois: monitor.whois,
    mail: monitor.mail,
    diagnostic: monitor.diagnostic,
  };
}

export type { Role, Staff };
