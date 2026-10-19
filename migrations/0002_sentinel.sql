-- Flotek Sentinel. The fleet is a shared company record.
-- Access is not public: every server function requires a signed-in user
-- who also has a row in staff_profiles. Roles gate what that person may do.

create table if not exists staff_profiles (
  user_id text primary key,
  email text not null unique,
  username text not null unique,
  name text not null,
  role text not null check (role in ('admin', 'operator', 'viewer')),
  created_at timestamptz not null default now()
);

create table if not exists app_settings (
  key text primary key,
  value text not null
);

create table if not exists monitors (
  id text primary key,
  kind text not null check (kind in ('website', 'domain')),
  name text not null,
  target text not null,
  host text not null,
  paused boolean not null default false,
  keyword text,
  status text not null default 'PENDING',
  http_code integer,
  error_message text,
  latency_ms integer,
  failure_streak integer not null default 0,
  uptime_pct integer not null default 100,
  samples text not null default '[]',
  ssl text,
  dns_records text not null default '[]',
  dns_meta text,
  whois text,
  mail text,
  diagnostic text,
  headers text,
  redirects text,
  wp text,
  agent_seen_at timestamptz,
  created_by text not null,
  created_at timestamptz not null default now(),
  last_check_at timestamptz,
  dns_checked_at timestamptz
);

create index if not exists monitors_host_idx on monitors (host);

create table if not exists incidents (
  id text primary key,
  monitor_id text,
  host text,
  name text,
  event text not null,
  type text not null,
  details text not null default '{}',
  archived boolean not null default false,
  acknowledged_at timestamptz,
  acknowledged_by text,
  created_at timestamptz not null default now()
);

create index if not exists incidents_archived_idx on incidents (archived, created_at desc);

create table if not exists backups (
  id text primary key,
  monitor_id text not null,
  filename text not null,
  filesize text,
  location text,
  created_at timestamptz not null default now()
);
