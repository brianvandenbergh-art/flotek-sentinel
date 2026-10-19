import { promises as dns } from "node:dns";
import net from "node:net";
import tls from "node:tls";

const LOOKUP_MS = 1600;
const COMMON_LABELS = [
  "www",
  "mail",
  "smtp",
  "imap",
  "pop",
  "webmail",
  "ftp",
  "autodiscover",
  "cpanel",
  "webdisk",
  "ns1",
  "ns2",
  "api",
  "app",
  "dev",
  "staging",
  "cdn",
  "blog",
  "shop",
  "portal",
  "remote",
  "vpn",
  "m",
  "status",
  "_dmarc",
  "selector1._domainkey",
  "selector2._domainkey",
  "google._domainkey",
  "k1._domainkey",
  "s1._domainkey",
  "s2._domainkey",
  "default._domainkey",
];

const APEX_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV", "NAPTR", "TLSA", "HTTPS", "SVCB"] as const;

export type DnsRecord = {
  type: string;
  host: string;
  value: string;
  priority: string;
  ttl: number | null;
};

export type SslInfo = {
  valid: boolean;
  days_left: number;
  issuer: string;
  valid_from: string | null;
  valid_to: string | null;
  names: string[];
};

export function normalizeHost(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/\/.*$/, "")
    .replace(/\.$/, "");
}

function isPrivateIp(ip: string): boolean {
  const kind = net.isIP(ip);
  if (kind === 6) {
    const n = ip.toLowerCase();
    return (
      n === "::1" ||
      n.startsWith("fe80:") ||
      n.startsWith("fc") ||
      n.startsWith("fd") ||
      n.startsWith("::ffff:127.") ||
      n.startsWith("::ffff:10.") ||
      n.startsWith("::ffff:192.168.") ||
      n.startsWith("::ffff:169.254.")
    );
  }
  if (kind !== 4) return true;
  const parts = ip.split(".").map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
  const a = parts[0] ?? 0;
  const b = parts[1] ?? 0;
  if (a === 10 || a === 127 || a === 0 || a >= 224) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

export async function assertPublicHost(host: string): Promise<void> {
  const name = normalizeHost(host);
  if (!name || name === "localhost" || name.endsWith(".local") || name.endsWith(".internal")) {
    throw new Error("That host is not a public website or domain.");
  }
  if (!/^[a-z0-9.-]+$/.test(name) || !name.includes(".")) {
    throw new Error("Enter a public domain, such as example.co.uk.");
  }
  if (net.isIP(name)) {
    if (isPrivateIp(name)) throw new Error("Private and local addresses cannot be monitored.");
    return;
  }
  let addresses: string[] = [];
  try {
    const looked = await dns.lookup(name, { all: true, verbatim: true });
    addresses = looked.map((row) => row.address);
  } catch {
    throw new Error("That domain did not resolve. Check the spelling and try again.");
  }
  if (addresses.length === 0 || addresses.some(isPrivateIp)) {
    throw new Error("That host does not point at a public address.");
  }
}

function withTimeout<T>(promise: Promise<T>, ms = LOOKUP_MS): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timeout")), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

async function pool<T>(items: T[], size: number, worker: (item: T) => Promise<void>) {
  let index = 0;
  const runners = Array.from({ length: Math.min(size, items.length) }, async () => {
    while (index < items.length) {
      const current = items[index];
      index += 1;
      if (current !== undefined) await worker(current);
    }
  });
  await Promise.all(runners);
}

function stringify(value: unknown): string {
  if (value === undefined || value === null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number") return String(value);
  if (Array.isArray(value)) return value.map((part) => stringify(part)).join("");
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function mapRecord(type: string, host: string, raw: unknown): DnsRecord {
  const record = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : { value: raw };
  let value = "";
  let priority = "-";
  if (type === "A" || type === "AAAA") value = stringify(record.address ?? raw);
  else if (type === "MX") {
    value = stringify(record.exchange);
    priority = stringify(record.priority);
  } else if (type === "SOA") {
    value = `${stringify(record.nsname)} ${stringify(record.hostmaster)} serial ${stringify(record.serial)}`;
  } else if (type === "CAA") {
    value = `${stringify(record.tag)} ${stringify(record.value)}`;
    priority = stringify(record.flags ?? record.critical);
  } else if (type === "SRV") {
    value = `${stringify(record.name)}:${stringify(record.port)} weight ${stringify(record.weight)}`;
    priority = stringify(record.priority);
  } else if (type === "TLSA") {
    value = `${stringify(record.certUsage)} ${stringify(record.selector)} ${stringify(record.matchingType)} ${stringify(record.certificate)}`;
  } else if (type === "NAPTR") {
    value = `${stringify(record.order)} ${stringify(record.preference)} ${stringify(record.flags)} ${stringify(record.service)} ${stringify(record.regexp)} ${stringify(record.replacement)}`;
  } else if (type === "HTTPS" || type === "SVCB") {
    value = stringify(raw);
  } else {
    value = stringify(record.value ?? record.exchange ?? record.nsname ?? raw);
  }
  return {
    type,
    host,
    value: value.slice(0, 500),
    priority: priority || "-",
    ttl: typeof record.ttl === "number" ? record.ttl : null,
  };
}

async function resolveTyped(name: string, type: string, resolver: typeof dns | dns.Resolver = dns): Promise<DnsRecord[]> {
  try {
    const values = await withTimeout(resolver.resolve(name, type));
    const list = Array.isArray(values) ? values : [values];
    return list.map((value) => mapRecord(type, name, value));
  } catch {
    return [];
  }
}

function relativeHost(name: string, apex: string): string {
  if (name === apex) return "@";
  return name.endsWith(`.${apex}`) ? name.slice(0, -(apex.length + 1)) : name;
}

export async function scanDns(apexInput: string): Promise<{
  records: DnsRecord[];
  meta: { coverage: string; nameservers: string[]; propagation: { resolver: string; addresses: string[] }[]; wildcard: string | null };
}> {
  const apex = normalizeHost(apexInput);
  const records: DnsRecord[] = [];
  let nameservers: string[] = [];
  try {
    nameservers = await withTimeout(dns.resolveNs(apex), 2500);
  } catch {
    nameservers = [];
  }

  let resolver: typeof dns | dns.Resolver = dns;
  if (nameservers.length) {
    const addresses: string[] = [];
    for (const ns of nameservers.slice(0, 4)) {
      try {
        addresses.push(...(await withTimeout(dns.resolve4(ns), 1500)));
      } catch {
        /* keep going */
      }
    }
    const publicNs = addresses.filter((ip) => !isPrivateIp(ip));
    if (publicNs.length) {
      const custom = new dns.Resolver();
      custom.setServers(Array.from(new Set(publicNs)).slice(0, 4));
      resolver = custom;
    }
  }

  const discovered = new Set<string>([apex, ...COMMON_LABELS.map((label) => `${label}.${apex}`)]);
  try {
    const response = await fetch(`https://crt.sh/?q=${encodeURIComponent(`%.${apex}`)}&output=json`, {
      signal: AbortSignal.timeout(5000),
      headers: { "User-Agent": "FlotekSentinel/1.0" },
    });
    if (response.ok) {
      const rows = (await response.json()) as { name_value?: string }[];
      for (const row of rows.slice(0, 80)) {
        for (const part of String(row.name_value || "").split(/\n+/)) {
          const name = normalizeHost(part.replace(/^\*\./, ""));
          if (name === apex || name.endsWith(`.${apex}`)) discovered.add(name);
          if (discovered.size > 48) break;
        }
      }
    }
  } catch {
    /* certificate logs are optional */
  }

  let wildcard: string | null = null;
  const wildcardName = `sentinel-${Date.now().toString(36)}.${apex}`;
  const wildcardA = await resolveTyped(wildcardName, "A", resolver);
  if (wildcardA[0]) wildcard = wildcardA[0].value;

  const names = Array.from(discovered);
  await pool(names, 8, async (name) => {
    const types = name === apex ? APEX_TYPES : name.includes("_") ? (["TXT", "CNAME", "A"] as const) : (["A", "AAAA", "CNAME"] as const);
    for (const type of types) {
      const found = await resolveTyped(name, type, resolver);
      for (const record of found) {
        if (wildcard && record.type === "A" && record.value === wildcard && name !== apex) continue;
        records.push({ ...record, host: relativeHost(name, apex) });
      }
    }
  });

  if (wildcard) {
    records.unshift({ type: "A", host: "*", value: wildcard, priority: "-", ttl: null });
  }

  const seen = new Set<string>();
  const unique = records.filter((record) => {
    const key = `${record.type}|${record.host}|${record.value}|${record.priority}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const propagation: { resolver: string; addresses: string[] }[] = [];
  for (const [label, server] of [
    ["Cloudflare", "1.1.1.1"],
    ["Google", "8.8.8.8"],
    ["Quad9", "9.9.9.9"],
  ] as const) {
    try {
      const probe = new dns.Resolver();
      probe.setServers([server]);
      const addresses = await withTimeout(probe.resolve4(apex), 2000);
      propagation.push({ resolver: label, addresses });
    } catch {
      propagation.push({ resolver: label, addresses: [] });
    }
  }

  return {
    records: unique,
    meta: {
      coverage:
        "Apex records, standard mail and web names, and hostnames seen in public certificate logs. DNS does not allow a full zone listing unless the provider permits a zone transfer, which most do not. This is every record Sentinel can see, not a registrar export.",
      nameservers,
      propagation,
      wildcard,
    },
  };
}

export async function inspectSsl(host: string): Promise<SslInfo> {
  const name = normalizeHost(host);
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host: name, port: 443, servername: name, timeout: 4000, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();
        const authorized = socket.authorized;
        socket.destroy();
        if (!cert || !cert.valid_to) {
          resolve({ valid: false, days_left: 0, issuer: "No certificate", valid_from: null, valid_to: null, names: [] });
          return;
        }
        const expiry = new Date(cert.valid_to);
        const days = Math.ceil((expiry.getTime() - Date.now()) / 86400000);
        const issuer = cert.issuer?.O || cert.issuer?.CN || "Certificate";
        const names = String(cert.subjectaltname || "")
          .split(", ")
          .map((part) => part.replace(/^DNS:/, ""))
          .filter(Boolean);
        resolve({
          valid: authorized && days > 0,
          days_left: Math.max(0, days),
          issuer,
          valid_from: cert.valid_from ? new Date(cert.valid_from).toISOString() : null,
          valid_to: expiry.toISOString(),
          names: names.slice(0, 24),
        });
      },
    );
    socket.on("error", () => resolve({ valid: false, days_left: 0, issuer: "No certificate", valid_from: null, valid_to: null, names: [] }));
    socket.on("timeout", () => {
      socket.destroy();
      resolve({ valid: false, days_left: 0, issuer: "No certificate", valid_from: null, valid_to: null, names: [] });
    });
  });
}

export type HttpResult = {
  status: "ONLINE" | "OFFLINE";
  http_code: number;
  error_message: string;
  latency_ms: number;
  final_url: string;
  redirects: { url: string; status: number }[];
  headers: { name: string; value: string }[];
  keyword_ok: boolean | null;
};

const HEADER_KEEP = ["server", "content-type", "cache-control", "strict-transport-security", "x-powered-by", "cf-ray", "x-cache"];

export async function checkHttp(target: string, keyword?: string | null): Promise<HttpResult> {
  const start = Date.now();
  const redirects: { url: string; status: number }[] = [];
  let current = target;
  try {
    for (let hop = 0; hop < 5; hop += 1) {
      const response = await fetch(current, {
        method: "GET",
        redirect: "manual",
        signal: AbortSignal.timeout(8000),
        headers: { "User-Agent": "FlotekSentinel/1.0 (+https://flotek.io)" },
      });
      const location = response.headers.get("location");
      if (location && response.status >= 300 && response.status < 400) {
        const next = new URL(location, current).toString();
        redirects.push({ url: current, status: response.status });
        await assertPublicHost(new URL(next).hostname);
        current = next;
        continue;
      }
      const latency = Date.now() - start;
      const ok = response.status >= 200 && response.status < 400;
      let keywordOk: boolean | null = null;
      if (keyword && keyword.trim()) {
        const text = (await response.text()).slice(0, 200_000);
        keywordOk = text.toLowerCase().includes(keyword.trim().toLowerCase());
      }
      const headers = HEADER_KEEP.map((name) => {
        const value = response.headers.get(name);
        return value ? { name, value: value.slice(0, 180) } : null;
      }).filter((row): row is { name: string; value: string } => Boolean(row));
      const online = ok && keywordOk !== false;
      return {
        status: online ? "ONLINE" : "OFFLINE",
        http_code: response.status,
        error_message: online
          ? `${response.status} ${response.statusText || "OK"}`
          : keywordOk === false
            ? `Page loaded but did not contain “${keyword.trim()}”`
            : `${response.status} ${response.statusText || "HTTP error"}`,
        latency_ms: latency,
        final_url: current,
        redirects,
        headers,
        keyword_ok: keywordOk,
      };
    }
    return {
      status: "OFFLINE",
      http_code: 310,
      error_message: "Too many redirects",
      latency_ms: Date.now() - start,
      final_url: current,
      redirects,
      headers: [],
      keyword_ok: null,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Request failed";
    return {
      status: "OFFLINE",
      http_code: message.toLowerCase().includes("timeout") || message.includes("abort") ? 408 : 503,
      error_message: message.includes("abort") ? "The site did not answer within 8 seconds" : message.slice(0, 220),
      latency_ms: Date.now() - start,
      final_url: current,
      redirects,
      headers: [],
      keyword_ok: null,
    };
  }
}

export async function lookupRdap(host: string) {
  const name = normalizeHost(host);
  try {
    const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(name)}`, {
      signal: AbortSignal.timeout(6000),
      headers: { Accept: "application/rdap+json, application/json" },
    });
    if (!response.ok) return { available: false, note: "No public registration record was returned." };
    const data = (await response.json()) as {
      status?: string[];
      nameservers?: { ldhName?: string }[];
      events?: { eventAction?: string; eventDate?: string }[];
      entities?: { roles?: string[]; vcardArray?: unknown[] }[];
    };
    const event = (action: string) => data.events?.find((item) => item.eventAction === action)?.eventDate ?? null;
    let registrar = "";
    for (const entity of data.entities || []) {
      if (entity.roles?.includes("registrar")) {
        const card = entity.vcardArray?.[1];
        if (Array.isArray(card)) {
          const fn = card.find((row) => Array.isArray(row) && row[0] === "fn");
          if (Array.isArray(fn)) registrar = String(fn[3] || "");
        }
      }
    }
    return {
      available: true,
      registrar: registrar || "Not published",
      created: event("registration"),
      expires: event("expiration"),
      changed: event("last changed"),
      statuses: data.status || [],
      nameservers: (data.nameservers || []).map((ns) => ns.ldhName).filter(Boolean) as string[],
    };
  } catch {
    return { available: false, note: "Registration lookup did not answer." };
  }
}

async function txt(name: string): Promise<string[]> {
  try {
    const rows = await withTimeout(dns.resolveTxt(name), 2000);
    return rows.map((parts) => parts.join(""));
  } catch {
    return [];
  }
}

export async function inspectMail(host: string) {
  const apex = normalizeHost(host);
  let mx: { exchange: string; priority: number }[] = [];
  try {
    mx = await withTimeout(dns.resolveMx(apex), 2500);
    mx.sort((a, b) => a.priority - b.priority);
  } catch {
    mx = [];
  }
  const txtApex = await txt(apex);
  const spf = txtApex.find((row) => row.toLowerCase().startsWith("v=spf1"));
  let spfStatus: "pass" | "weak" | "missing" = "missing";
  let spfNote = "No SPF record. Receiving mail servers cannot tell which servers may send for this domain.";
  if (spf) {
    if (/\+all\b/.test(spf)) {
      spfStatus = "weak";
      spfNote = "SPF ends in +all, so it allows any server to send. That does not protect the domain.";
    } else if (/\?all\b/.test(spf) || /~all\b/.test(spf)) {
      spfStatus = "weak";
      spfNote = "SPF is present but does not strictly reject other servers.";
    } else {
      spfStatus = "pass";
      spfNote = "SPF is published and ends with a strict rule.";
    }
  }
  const dmarcTxt = await txt(`_dmarc.${apex}`);
  const dmarc = dmarcTxt.find((row) => row.toLowerCase().includes("v=dmarc1"));
  let dmarcStatus: "pass" | "weak" | "missing" = "missing";
  let dmarcNote = "No DMARC record. There is no published policy for failed mail authentication.";
  if (dmarc) {
    const policy = /p=([a-z]+)/i.exec(dmarc)?.[1]?.toLowerCase();
    if (policy === "reject" || policy === "quarantine") {
      dmarcStatus = "pass";
      dmarcNote = `DMARC policy is ${policy}.`;
    } else {
      dmarcStatus = "weak";
      dmarcNote = "DMARC is published with a monitoring-only policy (p=none).";
    }
  }
  const selectors = ["selector1", "selector2", "google", "k1", "s1", "s2", "default"];
  const dkim: { selector: string; status: "found" | "missing"; record: string }[] = [];
  for (const selector of selectors) {
    const rows = await txt(`${selector}._domainkey.${apex}`);
    const hit = rows.find((row) => row.includes("v=DKIM1") || row.includes("p="));
    if (hit) dkim.push({ selector, status: "found", record: hit.slice(0, 240) });
  }
  const blacklist: { zone: string; listed: boolean | null; address: string }[] = [];
  const primary = mx[0];
  if (primary) {
    try {
      const addresses = await withTimeout(dns.resolve4(primary.exchange), 2000);
      const address = addresses[0];
      if (address) {
        const reversed = address.split(".").reverse().join(".");
        for (const zone of ["zen.spamhaus.org", "bl.spamcop.net"]) {
          try {
            const listed = await withTimeout(dns.resolve4(`${reversed}.${zone}`), 2000);
            const hit = listed.some((ip) => ip.startsWith("127.0.0."));
            blacklist.push({ zone, listed: hit, address });
          } catch {
            blacklist.push({ zone, listed: null, address });
          }
        }
      }
    } catch {
      /* no address for the mail host */
    }
  }
  return {
    mx: mx.slice(0, 8).map((row) => ({ exchange: row.exchange, priority: row.priority })),
    spf: { status: spfStatus, record: spf || "", note: spfNote },
    dmarc: { status: dmarcStatus, record: dmarc || "", note: dmarcNote },
    dkim,
    blacklist,
  };
}

export async function probeAgent(siteUrl: string, secret: string) {
  const endpoint = `${siteUrl.replace(/\/+$/, "")}/wp-json/flotek/v1/health`;
  try {
    const response = await fetch(endpoint, {
      signal: AbortSignal.timeout(5000),
      headers: { "X-Hub-Secret": secret, "User-Agent": "FlotekSentinel/1.0" },
    });
    if (!response.ok) return { reachable: false, reason: `Agent answered ${response.status}` };
    const body = (await response.json()) as Record<string, unknown>;
    return { reachable: true, body };
  } catch (error) {
    return { reachable: false, reason: error instanceof Error ? error.message.slice(0, 180) : "Agent did not answer" };
  }
}
