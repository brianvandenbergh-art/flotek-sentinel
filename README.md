# Flotek Sentinel

Website and domain monitoring for Flotek. The fleet starts empty. Nothing is preloaded.

## Sign in

- Username: Flotek
- Password: set `FLOTEK_ADMIN_PASSWORD` in the server environment before the first launch. It is not stored in this repository because the repository is public.
- Only an administrator can open Team and add people.
- Roles: Administrator, Operator, Viewer.

The password is hashed before it is stored. Change it under Settings after the first sign-in.

## Run

```bash
npm install
npm run dev
```

The app uses port 8080. When `DATABASE_URL` is set it uses Postgres. Without that, it uses a local database.

## WordPress sites

1. Sign in and open Settings.
2. Copy the hub secret.
3. Upload `public/flotek-sentinel-agent.php` to `wp-content/mu-plugins/` on the WordPress site.
4. Paste the hub secret into `FLOTEK_SENTINEL_SECRET` in that file.
5. Add the website under Monitors.

Uptime, DNS, certificates, registration and mail checks work without the agent. WordPress users, updates, backups and recovery need it.

## What was removed

Client sites and domains are not hard-coded. Add each website or domain from Monitors.
