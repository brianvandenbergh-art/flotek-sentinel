import { useEffect, useMemo, useState, type FormEvent } from "react";
import { UserButton } from "@/lib/auth/gates";
import {
  createMonitor,
  deleteMonitor,
  getConsole,
  manageTeam,
  pauseMonitor,
  rescanMonitor,
  runChecks,
  runWordpress,
  setIncident,
  siteReport,
} from "@/lib/sentinel/fns";
import {
  Activity,
  AlertTriangle,
  Download,
  Globe,
  Lock,
  Mail,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Search,
  Server,
  Shield,
  Trash2,
  Users,
} from "lucide-react";

type Role = "admin" | "operator" | "viewer";
type Staff = { userId: string; email: string; username: string; name: string; role: Role };
type Sample = { t: string; up: number; ms: number };
type DnsRecord = { type: string; host: string; value: string; priority: string; ttl: number | null };
type Monitor = {
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
  uptime_pct: number;
  samples: Sample[];
  ssl: { valid?: boolean; days_left?: number; issuer?: string; valid_to?: string; names?: string[] } | null;
  dns_records: DnsRecord[];
  dns_meta: { coverage?: string; nameservers?: string[]; propagation?: { resolver: string; addresses: string[] }[] } | null;
  whois: { available?: boolean; registrar?: string; created?: string | null; expires?: string | null; statuses?: string[]; nameservers?: string[]; note?: string } | null;
  mail: {
    mx?: { exchange: string; priority: number }[];
    spf?: { status: string; record: string; note: string };
    dmarc?: { status: string; record: string; note: string };
    dkim?: { selector: string; status: string; record: string }[];
    blacklist?: { zone: string; listed: boolean | null; address: string }[];
  } | null;
  diagnostic: { summary?: string; cause?: string } | null;
  headers: { name: string; value: string }[];
  redirects: { url: string; status: number }[];
  wp: {
    wp_version?: string;
    php_version?: string;
    theme?: { name?: string; version?: string };
    plugins?: { file?: string; name?: string; version?: string; active?: boolean; has_update?: boolean; new_version?: string }[];
    users?: { id?: number; user_login?: string; user_email?: string; roles?: string[] }[];
    performance?: { memory?: string };
    backups?: { filename?: string; filesize?: string }[];
  } | null;
  agent_seen_at: string | null;
  last_check_at: string | null;
  backups: { id: string; filename: string; filesize: string | null; created_at: string }[];
};
type Incident = {
  id: string;
  monitor_id: string | null;
  host: string | null;
  name: string | null;
  event: string;
  type: string;
  details: string;
  archived: boolean;
  created_at: string;
};
type ConsoleData = {
  staff: Staff | null;
  monitors: Monitor[];
  incidents: Incident[];
  secret: string | null;
  team: Staff[];
};

type View = "overview" | "monitors" | "incidents" | "team" | "settings";

const NAV: { id: View; label: string; icon: typeof Activity }[] = [
  { id: "overview", label: "Overview", icon: Activity },
  { id: "monitors", label: "Monitors", icon: Globe },
  { id: "incidents", label: "Incidents", icon: AlertTriangle },
  { id: "team", label: "Team", icon: Users },
  { id: "settings", label: "Settings", icon: Lock },
];

function messageOf(error: unknown) {
  return error instanceof Error ? error.message : "Something went wrong.";
}

function when(value: string | null | undefined) {
  if (!value) return "Not checked yet";
  return new Date(value).toLocaleString();
}

function incidentText(details: string) {
  try {
    const parsed = JSON.parse(details) as { message?: string };
    return parsed.message || details;
  } catch {
    return details;
  }
}

export function Console() {
  const [data, setData] = useState<ConsoleData | null>(null);
  const [view, setView] = useState<View>("overview");
  const [error, setError] = useState("");
  const [openId, setOpenId] = useState<string | null>(null);

  async function reload(next?: ConsoleData) {
    const payload = (next || (await getConsole())) as ConsoleData;
    setData(payload);
    return payload;
  }

  useEffect(() => {
    let stop = false;
    reload().catch((error) => {
      if (!stop) setError(messageOf(error));
    });
    const timer = window.setInterval(() => {
      runChecks()
        .then((payload) => {
          if (!stop) setData(payload as ConsoleData);
        })
        .catch(() => {});
    }, 45000);
    return () => {
      stop = true;
      window.clearInterval(timer);
    };
  }, []);

  if (!data) {
    return (
      <main className="grid min-h-screen place-items-center bg-bg px-6 text-sm text-muted">
        {error || "Loading Sentinel…"}
      </main>
    );
  }

  if (!data.staff) {
    return <StaffSignIn />;
  }

  const staff = data.staff;
  const canManage = staff.role !== "viewer";
  const open = data.monitors.find((monitor) => monitor.id === openId) || null;

  return (
    <div className="min-h-screen bg-bg text-ink">
      <header className="sticky top-0 z-20 border-b border-line bg-surface/95 backdrop-blur">
        <div className="mx-auto flex max-w-6xl flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center">
          <div className="flex items-center gap-3">
            <img src="/brand/flotek-logo.svg" alt="Flotek group" className="h-7 w-auto" />
            <span className="rounded-full bg-plum-soft px-2.5 py-1 text-xs font-semibold text-plum">Sentinel</span>
          </div>
          <nav className="flex gap-1 overflow-x-auto sm:ml-4">
            {NAV.filter((item) => item.id !== "team" || staff.role === "admin").map((item) => {
              const Icon = item.icon;
              const active = view === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setView(item.id)}
                  className={`inline-flex h-10 shrink-0 items-center gap-1.5 rounded-full px-3 text-sm font-medium ${active ? "bg-plum text-white" : "text-muted hover:bg-plum-soft hover:text-ink"}`}
                >
                  <Icon className="size-4" aria-hidden />
                  {item.label}
                </button>
              );
            })}
          </nav>
          <div className="sm:ml-auto">
            <UserButton />
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6">
        {view === "overview" ? <Overview data={data} onOpen={(id) => { setOpenId(id); setView("monitors"); }} /> : null}
        {view === "monitors" ? (
          <Monitors
            monitors={data.monitors}
            canManage={canManage}
            onOpen={setOpenId}
            onChange={() => reload().catch((error) => setError(messageOf(error)))}
          />
        ) : null}
        {view === "incidents" ? (
          <Incidents
            incidents={data.incidents}
            canManage={canManage}
            onChange={() => reload().catch((error) => setError(messageOf(error)))}
          />
        ) : null}
        {view === "team" && staff.role === "admin" ? (
          <Team team={data.team} selfId={staff.userId} onChange={() => reload().catch((error) => setError(messageOf(error)))} />
        ) : null}
        {view === "settings" ? <Settings staff={staff} secret={data.secret} /> : null}
        {error ? <p className="mt-4 text-sm text-down">{error}</p> : null}
      </main>
      {open ? (
        <Detail
          monitor={open}
          canManage={canManage}
          incidents={data.incidents.filter((incident) => incident.monitor_id === open.id)}
          onClose={() => setOpenId(null)}
          onChange={() => reload().catch((error) => setError(messageOf(error)))}
        />
      ) : null}
    </div>
  );
}

function StaffSignIn() {
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/sentinel/login", {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ identifier, password }),
      });
      const body = (await response.json().catch(() => ({}))) as { error?: string; token?: string };
      if (!response.ok) {
        setError(body.error || "The username or password is not correct.");
        setBusy(false);
        return;
      }
      const token = response.headers.get("set-auth-token") || body.token;
      if (token) window.sessionStorage.setItem("grok-auth.bearer-token", token);
      window.location.assign("/");
    } catch {
      setError("Sign-in failed. Try again.");
      setBusy(false);
    }
  }

  return (
    <main className="grid min-h-screen place-items-center bg-bg px-4 py-10">
      <form onSubmit={submit} className="w-full max-w-md rounded-card border border-line bg-surface p-6 shadow-sm sm:p-8">
        <img src="/brand/flotek-logo.svg" alt="Flotek group" className="h-8 w-auto" />
        <h1 className="mt-6 text-2xl font-semibold text-ink">Sign in to Sentinel</h1>
        <p className="mt-2 text-sm leading-6 text-muted">
          Use the username an administrator issued. The fleet starts empty until someone adds a website or domain.
        </p>
        <label className="mt-6 block text-sm font-medium text-ink" htmlFor="staff-username">
          Username
          <input id="staff-username" autoComplete="username" value={identifier} onChange={(event) => setIdentifier(event.target.value)} className="mt-1.5 h-11 w-full rounded-xl border border-line bg-bg px-3 font-normal" required />
        </label>
        <label className="mt-4 block text-sm font-medium text-ink" htmlFor="staff-password">
          Password
          <input id="staff-password" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} className="mt-1.5 h-11 w-full rounded-xl border border-line bg-bg px-3 font-normal" required />
        </label>
        {error ? <p className="mt-4 text-sm text-down">{error}</p> : null}
        <button type="submit" disabled={busy} className="mt-6 h-11 w-full rounded-full bg-plum text-sm font-semibold text-white disabled:opacity-60">
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </main>
  );
}

function Overview({ data, onOpen }: { data: ConsoleData; onOpen: (id: string) => void }) {
  const monitors = data.monitors;
  const up = monitors.filter((monitor) => !monitor.paused && monitor.status === "ONLINE").length;
  const down = monitors.filter((monitor) => !monitor.paused && monitor.status === "OFFLINE").length;
  const paused = monitors.filter((monitor) => monitor.paused).length;
  const latencies = monitors.map((monitor) => monitor.latency_ms).filter((value): value is number => typeof value === "number");
  const average = latencies.length ? Math.round(latencies.reduce((sum, value) => sum + value, 0) / latencies.length) : null;
  const uptime = monitors.length ? Math.round(monitors.reduce((sum, monitor) => sum + (monitor.uptime_pct || 0), 0) / monitors.length) : null;
  const expiring = monitors.filter((monitor) => monitor.ssl && typeof monitor.ssl.days_left === "number" && monitor.ssl.days_left <= 30);
  const openIncidents = data.incidents.filter((incident) => !incident.archived).length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-ink sm:text-3xl">Fleet overview</h1>
        <p className="mt-1 max-w-2xl text-sm leading-6 text-muted">
          Nothing is preloaded. Checks run on websites and domains you add, and the numbers below are calculated from those checks.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Up" value={String(up)} hint={paused ? `${paused} paused` : "Answering"} tone="teal" />
        <Stat label="Down" value={String(down)} hint="Confirmed after two failed checks" tone={down ? "down" : "ink"} />
        <Stat label="Uptime" value={uptime === null ? "—" : `${uptime}%`} hint="From stored samples" tone="plum" />
        <Stat label="Response" value={average === null ? "—" : `${average} ms`} hint={`${openIncidents} open incidents`} tone="ink" />
      </div>
      {monitors.length === 0 ? (
        <Empty />
      ) : (
        <div className="grid gap-4 lg:grid-cols-5">
          <section className="rounded-3xl border border-line bg-surface p-4 lg:col-span-3">
            <h2 className="text-sm font-semibold">Monitors</h2>
            <ul className="mt-3 divide-y divide-line">
              {monitors.slice(0, 8).map((monitor) => (
                <li key={monitor.id}>
                  <button type="button" onClick={() => onOpen(monitor.id)} className="flex w-full items-center gap-3 py-3 text-left">
                    <StatusDot status={monitor.paused ? "PAUSED" : monitor.status} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-medium">{monitor.name}</span>
                      <span className="block truncate text-xs text-muted">{monitor.host}</span>
                    </span>
                    <span className="text-sm tabular-nums text-muted">{monitor.latency_ms ? `${monitor.latency_ms} ms` : "—"}</span>
                  </button>
                </li>
              ))}
            </ul>
          </section>
          <section className="space-y-4 lg:col-span-2">
            <div className="rounded-3xl border border-line bg-surface p-4">
              <h2 className="text-sm font-semibold">Certificates</h2>
              {expiring.length === 0 ? (
                <p className="mt-2 text-sm text-muted">No certificates expire in the next 30 days.</p>
              ) : (
                <ul className="mt-2 space-y-2 text-sm">
                  {expiring.map((monitor) => (
                    <li key={monitor.id} className="flex justify-between gap-3">
                      <span className="truncate">{monitor.host}</span>
                      <span className="tabular-nums text-warn">{monitor.ssl?.days_left} days</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div className="rounded-3xl border border-line bg-surface p-4">
              <h2 className="text-sm font-semibold">Latest incidents</h2>
              {data.incidents.filter((incident) => !incident.archived).slice(0, 4).length === 0 ? (
                <p className="mt-2 text-sm text-muted">No open incidents.</p>
              ) : (
                <ul className="mt-2 space-y-2 text-sm">
                  {data.incidents.filter((incident) => !incident.archived).slice(0, 4).map((incident) => (
                    <li key={incident.id}>
                      <span className="font-medium">{incident.name || incident.host}</span>
                      <span className="mt-0.5 block text-xs text-muted">{incident.event}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </section>
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, hint, tone }: { label: string; value: string; hint: string; tone: "teal" | "down" | "plum" | "ink" }) {
  const color = tone === "teal" ? "text-teal" : tone === "down" ? "text-down" : tone === "plum" ? "text-plum" : "text-ink";
  return (
    <div className="rounded-3xl border border-line bg-surface p-4">
      <p className="text-xs font-semibold tracking-wide text-muted uppercase">{label}</p>
      <p className={`mt-2 text-3xl font-semibold tabular-nums ${color}`}>{value}</p>
      <p className="mt-1 text-xs leading-5 text-muted">{hint}</p>
    </div>
  );
}

function Empty() {
  return (
    <div className="rounded-3xl border border-dashed border-line bg-surface px-6 py-14 text-center">
      <Server className="mx-auto size-8 text-plum" aria-hidden />
      <h2 className="mt-3 text-lg font-semibold">The fleet is empty</h2>
      <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-muted">
        Add a website to watch the page, certificate and WordPress agent, or add a domain to collect its DNS, registration and mail records.
      </p>
    </div>
  );
}

function StatusDot({ status }: { status: string }) {
  const color = status === "ONLINE" ? "bg-teal-bright" : status === "OFFLINE" ? "bg-down" : status === "PAUSED" ? "bg-warn" : "bg-line";
  return <span className={`size-2.5 shrink-0 rounded-full ${color}`} aria-hidden />;
}

function Monitors({
  monitors,
  canManage,
  onOpen,
  onChange,
}: {
  monitors: Monitor[];
  canManage: boolean;
  onOpen: (id: string) => void;
  onChange: () => void;
}) {
  const [kind, setKind] = useState<"website" | "domain">("website");
  const [query, setQuery] = useState("");
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState({ name: "", target: "", keyword: "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const visible = monitors.filter((monitor) => {
    if (monitor.kind !== kind) return false;
    const haystack = `${monitor.name} ${monitor.host}`.toLowerCase();
    return haystack.includes(query.trim().toLowerCase());
  });

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await createMonitor({ data: { kind, target: form.target, name: form.name, keyword: form.keyword } });
      setAdding(false);
      setForm({ name: "", target: "", keyword: "" });
      onChange();
    } catch (error) {
      setError(messageOf(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Monitors</h1>
          <p className="text-sm text-muted">{monitors.length === 0 ? "No monitors yet." : `${monitors.length} on the fleet.`}</p>
        </div>
        {canManage ? (
          <button type="button" onClick={() => setAdding(true)} className="inline-flex h-11 items-center justify-center gap-2 rounded-full bg-orange px-4 text-sm font-semibold text-white hover:bg-orange-deep">
            <Plus className="size-4" aria-hidden /> Add monitor
          </button>
        ) : null}
      </div>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="inline-flex rounded-full bg-surface p-1 border border-line">
          {(["website", "domain"] as const).map((value) => (
            <button
              key={value}
              type="button"
              onClick={() => setKind(value)}
              className={`h-9 rounded-full px-4 text-sm font-medium ${kind === value ? "bg-plum text-white" : "text-muted"}`}
            >
              {value === "website" ? "Websites" : "Domains"}
            </button>
          ))}
        </div>
        <label className="relative block flex-1">
          <Search className="pointer-events-none absolute top-3 left-3 size-4 text-muted" aria-hidden />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search name or domain" className="h-11 w-full rounded-full border border-line bg-surface pr-3 pl-9 text-sm" />
        </label>
      </div>
      {visible.length === 0 ? <Empty /> : (
        <div className="grid gap-3">
          {visible.map((monitor) => (
            <article key={monitor.id} className="rounded-3xl border border-line bg-surface p-4">
              <button type="button" onClick={() => onOpen(monitor.id)} className="flex w-full flex-col gap-3 text-left sm:flex-row sm:items-center">
                <StatusDot status={monitor.paused ? "PAUSED" : monitor.status} />
                <span className="min-w-0 flex-1">
                  <span className="block font-semibold">{monitor.name}</span>
                  <span className="block truncate text-sm text-muted">{monitor.kind === "website" ? monitor.target : monitor.host}</span>
                </span>
                <span className="grid grid-cols-3 gap-4 text-sm sm:w-72">
                  <Metric label="Uptime" value={`${monitor.uptime_pct}%`} />
                  <Metric label="Latency" value={monitor.latency_ms ? `${monitor.latency_ms} ms` : "—"} />
                  <Metric label="SSL" value={monitor.ssl?.days_left !== undefined ? `${monitor.ssl.days_left}d` : "—"} />
                </span>
              </button>
              <UptimeStrip samples={monitor.samples} />
              {monitor.status === "OFFLINE" && monitor.error_message ? <p className="mt-2 text-sm text-down">{monitor.error_message}</p> : null}
            </article>
          ))}
        </div>
      )}
      {adding ? (
        <div className="fixed inset-0 z-40 grid place-items-end bg-plum-deep/40 p-0 sm:place-items-center sm:p-4">
          <form onSubmit={submit} className="w-full max-w-md rounded-t-3xl bg-surface p-5 sm:rounded-3xl">
            <h2 className="text-lg font-semibold">Add {kind === "website" ? "a website" : "a domain"}</h2>
            <p className="mt-1 text-sm text-muted">Sentinel will check it immediately. Private and local addresses are refused.</p>
            <label className="mt-4 block text-sm font-medium">Name</label>
            <input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} className="mt-1 h-11 w-full rounded-xl border border-line px-3 text-sm" placeholder="Optional display name" />
            <label className="mt-3 block text-sm font-medium">{kind === "website" ? "Website URL" : "Domain"}</label>
            <input required value={form.target} onChange={(event) => setForm({ ...form, target: event.target.value })} className="mt-1 h-11 w-full rounded-xl border border-line px-3 text-sm" placeholder={kind === "website" ? "https://example.co.uk" : "example.co.uk"} />
            {kind === "website" ? (
              <>
                <label className="mt-3 block text-sm font-medium">Keyword on the page</label>
                <input value={form.keyword} onChange={(event) => setForm({ ...form, keyword: event.target.value })} className="mt-1 h-11 w-full rounded-xl border border-line px-3 text-sm" placeholder="Optional, such as the company name" />
              </>
            ) : null}
            {error ? <p className="mt-3 text-sm text-down">{error}</p> : null}
            <div className="mt-5 flex justify-end gap-2">
              <button type="button" onClick={() => setAdding(false)} className="h-11 rounded-full px-4 text-sm font-medium text-muted">Cancel</button>
              <button type="submit" disabled={busy} className="h-11 rounded-full bg-orange px-4 text-sm font-semibold text-white disabled:opacity-60">{busy ? "Checking…" : "Add and check"}</button>
            </div>
          </form>
        </div>
      ) : null}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <span>
      <span className="block text-[11px] tracking-wide text-muted uppercase">{label}</span>
      <span className="tabular-nums font-medium">{value}</span>
    </span>
  );
}

function UptimeStrip({ samples }: { samples: Sample[] }) {
  const points = samples.slice(-40);
  if (!points.length) return null;
  return (
    <div className="mt-3 flex h-2 gap-0.5" aria-hidden>
      {points.map((sample, index) => (
        <span key={`${sample.t}-${index}`} className={`h-full flex-1 rounded-sm ${sample.up ? "bg-teal-bright" : "bg-down"}`} />
      ))}
    </div>
  );
}

function Incidents({ incidents, canManage, onChange }: { incidents: Incident[]; canManage: boolean; onChange: () => void }) {
  const [archived, setArchived] = useState(false);
  const rows = incidents.filter((incident) => incident.archived === archived);
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Incidents</h1>
        <button type="button" onClick={() => setArchived((value) => !value)} className="h-10 rounded-full border border-line bg-surface px-4 text-sm font-medium">
          {archived ? "Show open" : "Show archive"}
        </button>
      </div>
      {rows.length === 0 ? <p className="text-sm text-muted">{archived ? "Nothing has been archived." : "No open incidents."}</p> : (
        <ul className="space-y-2">
          {rows.map((incident) => (
            <li key={incident.id} className="rounded-2xl border border-line bg-surface p-4">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                <div>
                  <p className="font-semibold">{incident.event.replace(/_/g, " ")}</p>
                  <p className="text-sm text-muted">{incident.name || incident.host} · {when(incident.created_at)}</p>
                  <p className="mt-1 text-sm">{incidentText(incident.details)}</p>
                </div>
                {canManage ? (
                  <button
                    type="button"
                    onClick={() => setIncident({ data: { id: incident.id, archived: !incident.archived } }).then(onChange)}
                    className="h-10 shrink-0 rounded-full border border-line px-3 text-sm font-medium"
                  >
                    {incident.archived ? "Restore" : "Acknowledge"}
                  </button>
                ) : null}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Team({ team, selfId, onChange }: { team: Staff[]; selfId: string; onChange: () => void }) {
  const [form, setForm] = useState({ name: "", username: "", email: "", password: "", role: "operator" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await manageTeam({ data: { action: "create", payload: form } });
      setForm({ name: "", username: "", email: "", password: "", role: "operator" });
      onChange();
    } catch (error) {
      setError(messageOf(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid gap-4 lg:grid-cols-5">
      <section className="rounded-3xl border border-line bg-surface p-5 lg:col-span-3">
        <h1 className="text-2xl font-semibold">Team</h1>
        <p className="mt-1 text-sm leading-6 text-muted">Administrators add people. Operators can change monitors. Viewers can look, not change.</p>
        <ul className="mt-4 divide-y divide-line">
          {team.map((person) => (
            <li key={person.userId} className="flex flex-col gap-2 py-3 sm:flex-row sm:items-center">
              <div className="min-w-0 flex-1">
                <p className="font-medium">{person.name}</p>
                <p className="truncate text-sm text-muted">{person.username} · {person.email}</p>
              </div>
              <select
                aria-label={`Role for ${person.name}`}
                value={person.role}
                disabled={person.userId === selfId && person.role === "admin"}
                onChange={(event) => manageTeam({ data: { action: "role", payload: { userId: person.userId, role: event.target.value } } }).then(onChange).catch((error) => setError(messageOf(error)))}
                className="h-10 rounded-xl border border-line bg-bg px-2 text-sm"
              >
                <option value="admin">Administrator</option>
                <option value="operator">Operator</option>
                <option value="viewer">Viewer</option>
              </select>
              {person.userId !== selfId ? (
                <button type="button" onClick={() => manageTeam({ data: { action: "remove", payload: { userId: person.userId } } }).then(onChange).catch((error) => setError(messageOf(error)))} className="inline-flex h-10 items-center gap-1 rounded-full px-3 text-sm text-down">
                  <Trash2 className="size-4" aria-hidden /> Remove
                </button>
              ) : null}
            </li>
          ))}
        </ul>
        {error ? <p className="mt-2 text-sm text-down">{error}</p> : null}
      </section>
      <form onSubmit={submit} className="rounded-3xl border border-line bg-surface p-5 lg:col-span-2">
        <h2 className="font-semibold">Add a person</h2>
        {(["name", "username", "email"] as const).map((field) => (
          <label key={field} className="mt-3 block text-sm font-medium capitalize">
            {field}
            <input required value={form[field]} onChange={(event) => setForm({ ...form, [field]: event.target.value })} className="mt-1 h-11 w-full rounded-xl border border-line px-3 text-sm font-normal" />
          </label>
        ))}
        <label className="mt-3 block text-sm font-medium">
          Password
          <input required type="password" autoComplete="new-password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} className="mt-1 h-11 w-full rounded-xl border border-line px-3 text-sm font-normal" />
        </label>
        <label className="mt-3 block text-sm font-medium">
          Role
          <select value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value })} className="mt-1 h-11 w-full rounded-xl border border-line bg-surface px-3 text-sm">
            <option value="admin">Administrator</option>
            <option value="operator">Operator</option>
            <option value="viewer">Viewer</option>
          </select>
        </label>
        <button type="submit" disabled={busy} className="mt-4 h-11 w-full rounded-full bg-plum text-sm font-semibold text-white disabled:opacity-60">{busy ? "Saving…" : "Create account"}</button>
      </form>
    </div>
  );
}

function Settings({ staff, secret }: { staff: Staff; secret: string | null }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState("");

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <section className="rounded-3xl border border-line bg-surface p-5">
        <h1 className="text-2xl font-semibold">Your account</h1>
        <p className="mt-1 text-sm text-muted">Signed in as {staff.name} ({staff.role}).</p>
        <form
          className="mt-4 space-y-3"
          onSubmit={(event) => {
            event.preventDefault();
            setError("");
            setNote("");
            manageTeam({ data: { action: "password", payload: { current, next } } })
              .then(() => {
                setCurrent("");
                setNext("");
                setNote("Password updated.");
              })
              .catch((error) => setError(messageOf(error)));
          }}
        >
          <label className="block text-sm font-medium">Current password
            <input type="password" autoComplete="current-password" value={current} onChange={(event) => setCurrent(event.target.value)} className="mt-1 h-11 w-full rounded-xl border border-line px-3" required />
          </label>
          <label className="block text-sm font-medium">New password
            <input type="password" autoComplete="new-password" value={next} onChange={(event) => setNext(event.target.value)} className="mt-1 h-11 w-full rounded-xl border border-line px-3" required />
          </label>
          {error ? <p className="text-sm text-down">{error}</p> : null}
          {note ? <p className="text-sm text-teal">{note}</p> : null}
          <button type="submit" className="h-11 rounded-full bg-plum px-4 text-sm font-semibold text-white">Change password</button>
        </form>
      </section>
      <section className="rounded-3xl border border-line bg-surface p-5">
        <h2 className="text-lg font-semibold">WordPress agent</h2>
        <p className="mt-1 text-sm leading-6 text-muted">
          Upload the agent to <span className="font-medium">wp-content/mu-plugins/</span> on a site you monitor. Paste the hub secret into the file. It is required for users, plugin updates, backups and recovery. Public uptime, DNS, certificates and mail do not need it.
        </p>
        <a href="/flotek-sentinel-agent.php" download className="mt-4 inline-flex h-11 items-center gap-2 rounded-full bg-orange px-4 text-sm font-semibold text-white">
          <Download className="size-4" aria-hidden /> Download agent
        </a>
        {secret ? (
          <div className="mt-4">
            <p className="text-xs font-semibold tracking-wide text-muted uppercase">Hub secret</p>
            <code className="mt-1 block overflow-x-auto rounded-xl bg-bg px-3 py-2 text-xs">{secret}</code>
          </div>
        ) : (
          <p className="mt-4 text-sm text-muted">Viewers cannot see the hub secret.</p>
        )}
      </section>
    </div>
  );
}

function Detail({
  monitor,
  canManage,
  incidents,
  onClose,
  onChange,
}: {
  monitor: Monitor;
  canManage: boolean;
  incidents: Incident[];
  onClose: () => void;
  onChange: () => void;
}) {
  const [tab, setTab] = useState("Overview");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const tabs = ["Overview", "DNS", "Registration", "Mail", ...(monitor.kind === "website" ? ["WordPress"] : []), "Events"];
  const types = useMemo(() => Array.from(new Set(monitor.dns_records.map((record) => record.type))), [monitor.dns_records]);
  const [dnsType, setDnsType] = useState("ALL");
  const [dnsQuery, setDnsQuery] = useState("");
  const records = monitor.dns_records.filter((record) => (dnsType === "ALL" || record.type === dnsType) && `${record.host} ${record.value}`.toLowerCase().includes(dnsQuery.toLowerCase()));

  async function act(label: string, work: () => Promise<unknown>) {
    setBusy(label);
    setError("");
    try {
      await work();
      onChange();
    } catch (error) {
      setError(messageOf(error));
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="fixed inset-0 z-30 flex justify-end bg-plum-deep/40">
      <aside className="flex h-full w-full flex-col overflow-y-auto bg-bg shadow-xl sm:max-w-2xl">
        <div className="sticky top-0 z-10 border-b border-line bg-surface px-4 py-4">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <StatusDot status={monitor.paused ? "PAUSED" : monitor.status} />
                <h2 className="truncate text-lg font-semibold">{monitor.name}</h2>
              </div>
              <p className="truncate text-sm text-muted">{monitor.target}</p>
            </div>
            <button type="button" onClick={onClose} className="h-10 rounded-full px-3 text-sm font-medium text-muted">Close</button>
          </div>
          <div className="mt-3 flex gap-1 overflow-x-auto">
            {tabs.map((item) => (
              <button key={item} type="button" onClick={() => setTab(item)} className={`h-9 shrink-0 rounded-full px-3 text-sm ${tab === item ? "bg-plum text-white" : "bg-plum-soft text-ink"}`}>{item}</button>
            ))}
          </div>
        </div>
        <div className="space-y-4 p-4">
          {error ? <p className="text-sm text-down">{error}</p> : null}
          {canManage ? (
            <div className="flex flex-wrap gap-2">
              <button type="button" disabled={!!busy} onClick={() => act("check", () => rescanMonitor({ data: { id: monitor.id } }))} className="inline-flex h-10 items-center gap-1.5 rounded-full border border-line bg-surface px-3 text-sm font-medium">
                <RefreshCw className="size-4" aria-hidden /> {busy === "check" ? "Checking…" : "Check now"}
              </button>
              <button type="button" onClick={() => act("pause", () => pauseMonitor({ data: { id: monitor.id, paused: !monitor.paused } }))} className="inline-flex h-10 items-center gap-1.5 rounded-full border border-line bg-surface px-3 text-sm font-medium">
                {monitor.paused ? <Play className="size-4" /> : <Pause className="size-4" />} {monitor.paused ? "Resume" : "Pause"}
              </button>
              <button type="button" onClick={() => act("report", async () => {
                const report = await siteReport({ data: { id: monitor.id } });
                const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
                const link = document.createElement("a");
                link.href = URL.createObjectURL(blob);
                link.download = `sentinel-${monitor.host}.json`;
                link.click();
                URL.revokeObjectURL(link.href);
              })} className="inline-flex h-10 items-center gap-1.5 rounded-full border border-line bg-surface px-3 text-sm font-medium">
                <Download className="size-4" /> Report
              </button>
              <button type="button" onClick={() => { if (confirm(`Remove ${monitor.name} from Sentinel?`)) void act("delete", async () => { await deleteMonitor({ data: { id: monitor.id } }); onClose(); }); }} className="inline-flex h-10 items-center gap-1.5 rounded-full px-3 text-sm font-medium text-down">
                <Trash2 className="size-4" /> Remove
              </button>
            </div>
          ) : null}

          {tab === "Overview" ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <Info label="Status" value={monitor.paused ? "Paused" : monitor.status} />
                <Info label="Last check" value={when(monitor.last_check_at)} />
                <Info label="HTTP" value={monitor.http_code ? String(monitor.http_code) : "—"} />
                <Info label="Latency" value={monitor.latency_ms ? `${monitor.latency_ms} ms` : "—"} />
              </div>
              {monitor.diagnostic?.summary ? <p className="rounded-2xl bg-surface p-3 text-sm border border-line">{monitor.diagnostic.summary}</p> : null}
              <UptimeStrip samples={monitor.samples} />
              <div className="rounded-2xl border border-line bg-surface p-4">
                <div className="flex items-center gap-2 text-sm font-semibold"><Lock className="size-4 text-plum" /> Certificate</div>
                <p className="mt-2 text-sm">{monitor.ssl ? `${monitor.ssl.days_left ?? 0} days · ${monitor.ssl.issuer || "Unknown issuer"}` : "No certificate recorded yet."}</p>
                {monitor.ssl?.valid_to ? <p className="text-xs text-muted">Expires {when(monitor.ssl.valid_to)}</p> : null}
                {monitor.ssl?.names?.length ? <p className="mt-2 text-xs leading-5 text-muted">{monitor.ssl.names.join(", ")}</p> : null}
              </div>
              {monitor.redirects.length ? (
                <div className="rounded-2xl border border-line bg-surface p-4 text-sm">
                  <p className="font-semibold">Redirects</p>
                  {monitor.redirects.map((hop) => <p key={hop.url} className="mt-1 truncate text-muted">{hop.status} {hop.url}</p>)}
                </div>
              ) : null}
              {monitor.headers.length ? (
                <div className="rounded-2xl border border-line bg-surface p-4 text-sm">
                  <p className="font-semibold">Response headers</p>
                  {monitor.headers.map((header) => <p key={header.name} className="mt-1 text-muted"><span className="text-ink">{header.name}</span> {header.value}</p>)}
                </div>
              ) : null}
            </div>
          ) : null}

          {tab === "DNS" ? (
            <div className="space-y-3">
              <p className="text-sm leading-6 text-muted">{monitor.dns_meta?.coverage}</p>
              <p className="text-sm">{monitor.dns_records.length} records visible to Sentinel.</p>
              <div className="flex flex-wrap gap-1">
                {["ALL", ...types].map((type) => (
                  <button key={type} type="button" onClick={() => setDnsType(type)} className={`h-8 rounded-full px-3 text-xs font-semibold ${dnsType === type ? "bg-plum text-white" : "bg-surface border border-line"}`}>{type}</button>
                ))}
              </div>
              <input value={dnsQuery} onChange={(event) => setDnsQuery(event.target.value)} placeholder="Filter records" className="h-10 w-full rounded-xl border border-line bg-surface px-3 text-sm" />
              <div className="overflow-x-auto rounded-2xl border border-line bg-surface">
                <table className="w-full min-w-[32rem] text-left text-sm">
                  <thead className="text-xs tracking-wide text-muted uppercase">
                    <tr><th className="p-3">Type</th><th className="p-3">Host</th><th className="p-3">Value</th><th className="p-3">Priority</th></tr>
                  </thead>
                  <tbody>
                    {records.map((record, index) => (
                      <tr key={`${record.type}-${record.host}-${index}`} className="border-t border-line">
                        <td className="p-3 font-semibold text-plum">{record.type}</td>
                        <td className="p-3">{record.host}</td>
                        <td className="max-w-xs truncate p-3">{record.value}</td>
                        <td className="p-3 tabular-nums">{record.priority}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {monitor.dns_meta?.propagation ? (
                <div className="rounded-2xl border border-line bg-surface p-4 text-sm">
                  <p className="font-semibold">Public resolvers</p>
                  {monitor.dns_meta.propagation.map((row) => (
                    <p key={row.resolver} className="mt-1 text-muted">{row.resolver}: {row.addresses.length ? row.addresses.join(", ") : "No answer"}</p>
                  ))}
                </div>
              ) : null}
              <button type="button" onClick={() => {
                const blob = new Blob([JSON.stringify(monitor.dns_records, null, 2)], { type: "application/json" });
                const link = document.createElement("a");
                link.href = URL.createObjectURL(blob);
                link.download = `dns-${monitor.host}.json`;
                link.click();
              }} className="inline-flex h-10 items-center gap-2 rounded-full border border-line bg-surface px-3 text-sm"><Download className="size-4" /> Export DNS</button>
            </div>
          ) : null}

          {tab === "Registration" ? (
            <div className="rounded-2xl border border-line bg-surface p-4 text-sm">
              {monitor.whois?.available === false ? <p>{monitor.whois.note}</p> : (
                <dl className="space-y-2">
                  <Row label="Registrar" value={monitor.whois?.registrar || "—"} />
                  <Row label="Created" value={monitor.whois?.created ? when(monitor.whois.created) : "—"} />
                  <Row label="Expires" value={monitor.whois?.expires ? when(monitor.whois.expires) : "—"} />
                  <Row label="Status" value={(monitor.whois?.statuses || []).join(", ") || "—"} />
                  <Row label="Nameservers" value={(monitor.whois?.nameservers || monitor.dns_meta?.nameservers || []).join(", ") || "—"} />
                </dl>
              )}
            </div>
          ) : null}

          {tab === "Mail" ? (
            <div className="space-y-3 text-sm">
              <MailCard title="SPF" status={monitor.mail?.spf?.status} note={monitor.mail?.spf?.note} record={monitor.mail?.spf?.record} />
              <MailCard title="DMARC" status={monitor.mail?.dmarc?.status} note={monitor.mail?.dmarc?.note} record={monitor.mail?.dmarc?.record} />
              <div className="rounded-2xl border border-line bg-surface p-4">
                <p className="flex items-center gap-2 font-semibold"><Mail className="size-4 text-plum" /> MX</p>
                {(monitor.mail?.mx || []).length === 0 ? <p className="mt-2 text-muted">No MX records.</p> : monitor.mail?.mx?.map((row) => (
                  <p key={row.exchange} className="mt-1 text-muted">{row.priority} {row.exchange}</p>
                ))}
              </div>
              <div className="rounded-2xl border border-line bg-surface p-4">
                <p className="font-semibold">DKIM selectors checked</p>
                {(monitor.mail?.dkim || []).length === 0 ? <p className="mt-2 text-muted">None of the common selectors published a key. A custom selector can still exist.</p> : monitor.mail?.dkim?.map((row) => (
                  <p key={row.selector} className="mt-1 text-muted">{row.selector}: found</p>
                ))}
              </div>
              <div className="rounded-2xl border border-line bg-surface p-4">
                <p className="font-semibold">Blocklists</p>
                {(monitor.mail?.blacklist || []).length === 0 ? <p className="mt-2 text-muted">No mail address to check.</p> : monitor.mail?.blacklist?.map((row) => (
                  <p key={row.zone} className="mt-1 text-muted">{row.zone}: {row.listed === null ? "No public answer" : row.listed ? "Listed" : "Not listed"} ({row.address})</p>
                ))}
              </div>
            </div>
          ) : null}

          {tab === "WordPress" ? <Wordpress monitor={monitor} canManage={canManage} busy={busy} act={act} /> : null}

          {tab === "Events" ? (
            incidents.length === 0 ? <p className="text-sm text-muted">No incidents for this monitor.</p> : (
              <ul className="space-y-2">
                {incidents.map((incident) => (
                  <li key={incident.id} className="rounded-2xl border border-line bg-surface p-3 text-sm">
                    <p className="font-medium">{incident.event}</p>
                    <p className="text-muted">{when(incident.created_at)}</p>
                    <p className="mt-1">{incidentText(incident.details)}</p>
                  </li>
                ))}
              </ul>
            )
          ) : null}
        </div>
      </aside>
    </div>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-line bg-surface p-3">
      <p className="text-xs tracking-wide text-muted uppercase">{label}</p>
      <p className="mt-1 text-sm font-medium">{value}</p>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-0.5 sm:flex-row sm:justify-between">
      <dt className="text-muted">{label}</dt>
      <dd className="font-medium sm:text-right">{value}</dd>
    </div>
  );
}

function MailCard({ title, status, note, record }: { title: string; status?: string; note?: string; record?: string }) {
  const tone = status === "pass" ? "text-teal" : status === "weak" ? "text-warn" : "text-down";
  return (
    <div className="rounded-2xl border border-line bg-surface p-4">
      <p className="font-semibold">{title} <span className={`text-xs uppercase ${tone}`}>{status || "unknown"}</span></p>
      <p className="mt-1 text-muted">{note || "Not checked yet."}</p>
      {record ? <p className="mt-2 overflow-x-auto text-xs">{record}</p> : null}
    </div>
  );
}

function Wordpress({
  monitor,
  canManage,
  busy,
  act,
}: {
  monitor: Monitor;
  canManage: boolean;
  busy: string;
  act: (label: string, work: () => Promise<unknown>) => Promise<void>;
}) {
  const [userForm, setUserForm] = useState({ username: "", email: "", role: "editor", password: "" });
  const wp = monitor.wp;
  return (
    <div className="space-y-3 text-sm">
      <div className="rounded-2xl border border-line bg-surface p-4">
        <div className="flex items-center gap-2 font-semibold"><Shield className="size-4 text-plum" /> Agent</div>
        <p className="mt-2 text-muted">{monitor.agent_seen_at ? `Last seen ${when(monitor.agent_seen_at)}` : "No agent report yet. Install the file from Settings, then check again."}</p>
        {wp ? <p className="mt-1">WordPress {wp.wp_version || "—"} · PHP {wp.php_version || "—"} · {wp.theme?.name} {wp.theme?.version}</p> : null}
        {canManage ? (
          <div className="mt-3 flex flex-wrap gap-2">
            <button type="button" disabled={!!busy} onClick={() => act("agent", () => runWordpress({ data: { id: monitor.id, action: "refresh" } }))} className="h-10 rounded-full bg-plum px-3 font-medium text-white">Read agent</button>
            <button type="button" disabled={!!busy} onClick={() => act("backup", () => runWordpress({ data: { id: monitor.id, action: "backup" } }))} className="h-10 rounded-full border border-line px-3 font-medium">Create database backup</button>
            <button type="button" disabled={!!busy} onClick={() => act("updates", () => runWordpress({ data: { id: monitor.id, action: "update-plugins" } }))} className="h-10 rounded-full border border-line px-3 font-medium">Update plugins</button>
          </div>
        ) : null}
      </div>
      <div className="rounded-2xl border border-line bg-surface p-4">
        <p className="font-semibold">Plugins</p>
        {(wp?.plugins || []).length === 0 ? <p className="mt-2 text-muted">No plugin list yet.</p> : wp?.plugins?.map((plugin) => (
          <div key={plugin.file || plugin.name} className="mt-3 flex flex-col gap-2 border-t border-line pt-3 sm:flex-row sm:items-center">
            <div className="min-w-0 flex-1">
              <p className="font-medium">{plugin.name}</p>
              <p className="text-xs text-muted">{plugin.version}{plugin.has_update ? ` · update ${plugin.new_version}` : ""} · {plugin.active ? "Active" : "Inactive"}</p>
            </div>
            {canManage && plugin.file ? (
              <button type="button" className="h-9 rounded-full px-3 text-down" onClick={() => act("disable", () => runWordpress({ data: { id: monitor.id, action: "disable-plugin", payload: { plugin: plugin.file || "" } } }))}>Disable</button>
            ) : null}
          </div>
        ))}
      </div>
      <div className="rounded-2xl border border-line bg-surface p-4">
        <p className="font-semibold">Users on the site</p>
        {(wp?.users || []).map((user) => (
          <div key={user.id} className="mt-3 flex flex-col gap-2 border-t border-line pt-3 sm:flex-row sm:items-center">
            <div className="min-w-0 flex-1">
              <p className="font-medium">{user.user_login}</p>
              <p className="text-xs text-muted">{user.user_email} · {(user.roles || []).join(", ")}</p>
            </div>
            {canManage ? (
              <div className="flex gap-2">
                <button type="button" className="h-9 rounded-full border border-line px-3" onClick={() => {
                  const password = window.prompt(`New password for ${user.user_login}`);
                  if (password) act("reset", () => runWordpress({ data: { id: monitor.id, action: "reset-password", payload: { user_id: String(user.id), new_password: password } } }));
                }}>Reset</button>
                <button type="button" className="h-9 rounded-full px-3 text-down" onClick={() => {
                  if (confirm(`Delete ${user.user_login} on the website?`)) act("user-delete", () => runWordpress({ data: { id: monitor.id, action: "delete-user", payload: { user_id: String(user.id) } } }));
                }}>Delete</button>
              </div>
            ) : null}
          </div>
        ))}
        {canManage ? (
          <form className="mt-4 grid gap-2 sm:grid-cols-2" onSubmit={(event) => {
            event.preventDefault();
            act("user", () => runWordpress({ data: { id: monitor.id, action: "create-user", payload: userForm } }));
          }}>
            <input required placeholder="Username" value={userForm.username} onChange={(event) => setUserForm({ ...userForm, username: event.target.value })} className="h-10 rounded-xl border border-line px-3" />
            <input required type="email" placeholder="Email" value={userForm.email} onChange={(event) => setUserForm({ ...userForm, email: event.target.value })} className="h-10 rounded-xl border border-line px-3" />
            <input required type="password" placeholder="Password" value={userForm.password} onChange={(event) => setUserForm({ ...userForm, password: event.target.value })} className="h-10 rounded-xl border border-line px-3" />
            <select value={userForm.role} onChange={(event) => setUserForm({ ...userForm, role: event.target.value })} className="h-10 rounded-xl border border-line px-3">
              <option value="administrator">Administrator</option>
              <option value="editor">Editor</option>
              <option value="author">Author</option>
              <option value="contributor">Contributor</option>
              <option value="subscriber">Subscriber</option>
            </select>
            <button type="submit" className="h-10 rounded-full bg-plum px-3 font-medium text-white sm:col-span-2">Add website user</button>
          </form>
        ) : null}
      </div>
      <div className="rounded-2xl border border-line bg-surface p-4">
        <p className="font-semibold">Backups stored on the website</p>
        <p className="mt-1 text-xs leading-5 text-muted">These files live on the site. If the server itself is offline, Sentinel cannot restore them. Use this when the page is broken but the agent still answers.</p>
        {(monitor.backups.length ? monitor.backups : (wp?.backups || []).map((item, index) => ({ id: String(index), filename: item.filename || "", filesize: item.filesize || null, created_at: "" }))).map((backup) => (
          <div key={backup.id + backup.filename} className="mt-3 flex items-center justify-between gap-3 border-t border-line pt-3">
            <div>
              <p className="font-medium">{backup.filename}</p>
              <p className="text-xs text-muted">{backup.filesize}</p>
            </div>
            {canManage ? (
              <button type="button" className="h-9 rounded-full px-3 text-down" onClick={() => {
                if (confirm(`Restore ${backup.filename}? This replaces the database on the website.`)) {
                  act("rollback", () => runWordpress({ data: { id: monitor.id, action: "rollback", payload: { filename: backup.filename } } }));
                }
              }}>Restore</button>
            ) : null}
          </div>
        ))}
      </div>
    </div>
  );
}
