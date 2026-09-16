/**
 * Flotek Sentinel - Enterprise Fleet Command Hub
 * Active HTTP/HTTPS Outage Detector, Dynamic DNS & Live Telemetry Engine
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const tls = require('tls');
const dns = require('dns').promises;

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(cors());
app.use(express.static(__dirname));

const PORT = process.env.PORT || 3000;
const SHARED_SECRET = 'flotek-super-secret-key-2026';
const DB_FILE = path.join(__dirname, 'data.json');

function normalizeHost(str) {
    if (!str) return '';
    return str.toLowerCase()
        .replace(/^https?:\/\//, '')
        .replace(/^www\./, '')
        .replace(/\/.*$/, '')
        .trim();
}

let monitoredSites = {};
let standaloneDomains = {};
let securityEvents = [];
let auditLogs = [];
let deletedDomains = [];

function loadDatabase() {
    try {
        if (fs.existsSync(DB_FILE)) {
            const raw = fs.readFileSync(DB_FILE, 'utf8');
            const data = JSON.parse(raw);
            if (data.sites) monitoredSites = data.sites;
            if (data.domains) standaloneDomains = data.domains;
            if (Array.isArray(data.events)) securityEvents = data.events;
            if (Array.isArray(data.audit_logs)) auditLogs = data.audit_logs;
            if (Array.isArray(data.deleted_domains)) deletedDomains = data.deleted_domains;
        }
    } catch (err) {}

    for (const del of deletedDomains) {
        delete standaloneDomains[del];
        delete monitoredSites[del];
    }
}

function saveDatabase() {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify({
            sites: monitoredSites,
            domains: standaloneDomains,
            events: securityEvents,
            audit_logs: auditLogs,
            deleted_domains: deletedDomains
        }, null, 2));
    } catch (err) {}
}

loadDatabase();
saveDatabase();

// 1. ACTIVE FLEET UPTIME & OUTAGE DETECTOR
async function checkEntityHealth(entity) {
    const targetUrl = entity.url || `https://${entity.domain}`;
    const startTime = Date.now();

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        const response = await fetch(targetUrl, {
            method: 'GET',
            headers: {
                'User-Agent': 'Flotek-Sentinel-Monitor/10.0 (+https://flotek.io)'
            },
            signal: controller.signal,
            redirect: 'follow'
        });
        clearTimeout(timeoutId);

        const latency = Date.now() - startTime;
        const isSuccess = response.status >= 200 && response.status < 400;

        return {
            status: isSuccess ? 'ONLINE' : 'OFFLINE',
            http_code: response.status,
            error_message: isSuccess ? '200 OK' : `${response.status} ${response.statusText || 'Error'}`,
            latency: latency
        };
    } catch (err) {
        const latency = Date.now() - startTime;
        let errMsg = err.name === 'AbortError' ? 'Connection Timeout (5s)' : err.message;
        if (errMsg.includes('ECONNREFUSED')) errMsg = 'Connection Refused';
        if (errMsg.includes('ENOTFOUND')) errMsg = 'DNS Lookup Failed';
        if (errMsg.includes('certificate')) errMsg = 'SSL Handshake Failed';

        return {
            status: 'OFFLINE',
            http_code: err.name === 'AbortError' ? 408 : 503,
            error_message: errMsg,
            latency: latency
        };
    }
}

async function runFleetHealthChecks() {
    const allSites = Object.values(monitoredSites);
    const allDomains = Object.values(standaloneDomains);

    for (const site of allSites) {
        const result = await checkEntityHealth(site);
        const previousStatus = site.status || 'ONLINE';

        site.status = result.status;
        site.http_code = result.http_code;
        site.error_message = result.error_message;
        site.latency = result.latency;

        if (!Array.isArray(site.uptime_history)) {
            site.uptime_history = Array(19).fill(1);
        }
        site.uptime_history.push(result.status === 'ONLINE' ? 1 : 0);
        if (site.uptime_history.length > 20) site.uptime_history.shift();

        const upPings = site.uptime_history.filter(x => x === 1).length;
        site.uptime_pct = Math.round((upPings / site.uptime_history.length) * 100);

        // Transition: ONLINE -> OFFLINE (Outage detected)
        if (result.status === 'OFFLINE' && previousStatus === 'ONLINE') {
            const outageIncident = {
                id: Date.now(),
                site_url: site.url,
                domain: site.domain,
                site_name: site.name,
                event: `OUTAGE_DETECTED_HTTP_${result.http_code}`,
                details: {
                    http_code: result.http_code,
                    error: result.error_message,
                    target: site.url,
                    diagnostic: `Site returned HTTP ${result.http_code}. Possible causes: missing/broken index.php, server configuration error, or 403 forbidden permissions.`
                },
                type: 'OUTAGE',
                timestamp: new Date().toISOString()
            };
            securityEvents.unshift(outageIncident);
            console.log(`🚨 [OUTAGE DETECTED] ${site.name} is DOWN (${result.http_code} ${result.error_message})`);
        } 
        // Transition: OFFLINE -> ONLINE (Recovery)
        else if (result.status === 'ONLINE' && previousStatus === 'OFFLINE') {
            const recoveryIncident = {
                id: Date.now(),
                site_url: site.url,
                domain: site.domain,
                site_name: site.name,
                event: 'SERVICE_RESTORED_200_OK',
                details: {
                    http_code: 200,
                    status: 'Service fully operational',
                    response_time: `${result.latency}ms`
                },
                type: 'RECOVERY',
                timestamp: new Date().toISOString()
            };
            securityEvents.unshift(recoveryIncident);
            console.log(`✅ [SERVICE RESTORED] ${site.name} is back ONLINE`);
        }
    }

    for (const dom of allDomains) {
        const result = await checkEntityHealth(dom);
        dom.status = result.status;
        dom.http_code = result.http_code;
        dom.error_message = result.error_message;
        dom.latency = result.latency;

        if (!Array.isArray(dom.uptime_history)) {
            dom.uptime_history = Array(19).fill(1);
        }
        dom.uptime_history.push(result.status === 'ONLINE' ? 1 : 0);
        if (dom.uptime_history.length > 20) dom.uptime_history.shift();

        const upPings = dom.uptime_history.filter(x => x === 1).length;
        dom.uptime_pct = Math.round((upPings / dom.uptime_history.length) * 100);
    }

    saveDatabase();
}

// Run active pings immediately and repeat every 15 seconds
runFleetHealthChecks();
setInterval(runFleetHealthChecks, 15000);

// 2. UNIVERSAL DYNAMIC MULTI-LEVEL DNS SCANNER
const COMPREHENSIVE_HOST_DICTIONARY = [
    'www', 'ftp', 'mail', 'smtp', 'webmail', 'autodiscover', 'remote', 'vpn', 'access', 'rds', 'media',
    'oneadvanced', 'portal', 'api', 'dev', 'stage', 'staging', 'direct', 'server', 'ssh', 'sftp', 'ns1', 'ns2',
    'lyncdiscover', 'msoid', 'sip', 'enterpriseenrollment', 'enterpriseregistration',
    'selector1._domainkey', 'selector2._domainkey', 'google._domainkey', 'k1._domainkey',
    'selector1-gamlins-com._domainkey', 'selector2-gamlins-com._domainkey',
    'barracuda92160414593', 'barracuda36629914597', '_e871c8238c0992dfb1d08a0579540795',
    '_dmarc',
    'colwynbay', 'bangor', 'conwy', 'bala', 'porthmadog', 'rhos',
    'www.colwynbay', 'ftp.colwynbay', 'www.bangor', 'ftp.bangor',
    'www.conwy', 'ftp.conwy', 'www.bala', 'ftp.bala',
    'www.porthmadog', 'ftp.porthmadog', 'www.rhos', 'ftp.rhos'
];

const SRV_PROBES = [
    '_sipfederationtls._tcp',
    '_sip._tls',
    '_autodiscover._tcp'
];

async function scanFullDNSZone(domain) {
    const host = normalizeHost(domain);
    const records = [];

    const safeResolve = (fn, ...args) => {
        return Promise.race([
            fn(...args),
            new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 1500))
        ]).catch(() => []);
    };

    const wildcardProbeHost = `_sentinel_wildcard_check_${Date.now()}.${host}`;
    const wildcardProbeIps = await safeResolve(dns.resolve4, wildcardProbeHost);
    const wildcardIp = wildcardProbeIps.length > 0 ? wildcardProbeIps[0] : null;

    if (wildcardIp) {
        records.push({ type: 'A', host: '* (Wildcard)', value: wildcardIp, priority: '-' });
    }

    try {
        const a = await safeResolve(dns.resolve4, host);
        a.forEach(ip => records.push({ type: 'A', host: '@ (Apex)', value: ip, priority: '-' }));

        const aaaa = await safeResolve(dns.resolve6, host);
        aaaa.forEach(ip => records.push({ type: 'AAAA', host: '@ (Apex)', value: ip, priority: '-' }));

        const mx = await safeResolve(dns.resolveMx, host);
        mx.forEach(item => records.push({ type: 'MX', host: '@', value: item.exchange, priority: item.priority }));

        const txt = await safeResolve(dns.resolveTxt, host);
        txt.forEach(item => records.push({ type: 'TXT', host: '@', value: Array.isArray(item) ? item.join('') : item, priority: '-' }));

        const ns = await safeResolve(dns.resolveNs, host);
        ns.forEach(item => records.push({ type: 'NS', host: '@', value: item, priority: '-' }));
    } catch (e) {}

    await Promise.all(COMPREHENSIVE_HOST_DICTIONARY.map(async (sub) => {
        const fqdn = `${sub}.${host}`;

        const cnames = await safeResolve(dns.resolveCname, fqdn);
        if (cnames.length > 0) {
            cnames.forEach(target => records.push({ type: 'CNAME', host: sub, value: target, priority: '-' }));
            return;
        }

        const ips = await safeResolve(dns.resolve4, fqdn);
        ips.forEach(ip => {
            if (!wildcardIp || ip !== wildcardIp) {
                records.push({ type: 'A', host: sub, value: ip, priority: '-' });
            }
        });

        const v6 = await safeResolve(dns.resolve6, fqdn);
        v6.forEach(ip => records.push({ type: 'AAAA', host: sub, value: ip, priority: '-' }));

        const mxs = await safeResolve(dns.resolveMx, fqdn);
        mxs.forEach(m => records.push({ type: 'MX', host: sub, value: m.exchange, priority: m.priority }));

        if (sub.includes('_dmarc') || sub.includes('_domainkey')) {
            const txts = await safeResolve(dns.resolveTxt, fqdn);
            txts.forEach(t => records.push({ type: 'TXT', host: sub, value: Array.isArray(t) ? t.join('') : t, priority: '-' }));
        }
    }));

    await Promise.all(SRV_PROBES.map(async (srv) => {
        const srvFqdn = `${srv}.${host}`;
        const srvs = await safeResolve(dns.resolveSrv, srvFqdn);
        srvs.forEach(s => records.push({
            type: 'SRV',
            host: srv,
            value: `${s.name}:${s.port}`,
            priority: s.priority
        }));
    }));

    const seen = new Set();
    const uniqueRecords = records.filter(r => {
        const key = `${r.type}|${r.host}|${r.value}|${r.priority}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });

    return uniqueRecords.length > 0 ? uniqueRecords : [{ type: 'A', host: '@ (Apex)', value: 'Resolving via DNS...', priority: '-' }];
}

// 3. LIVE SSL INSPECTOR
function inspectLiveSSL(domain) {
    return new Promise((resolve) => {
        const host = normalizeHost(domain);
        const socket = tls.connect(443, host, { servername: host, timeout: 2500 }, () => {
            const cert = socket.getPeerCertificate();
            socket.destroy();

            if (cert && cert.valid_to) {
                const expiry = new Date(cert.valid_to);
                const daysLeft = Math.max(0, Math.ceil((expiry - new Date()) / (1000 * 60 * 60 * 24)));
                const issuer = cert.issuer ? (cert.issuer.O || cert.issuer.CN || "Active SSL") : "Active SSL";
                resolve({ valid: true, days_left: daysLeft, issuer });
            } else {
                resolve({ valid: false, days_left: 0, issuer: "No Certificate (Domain Only / Parked)" });
            }
        });

        socket.on('error', () => resolve({ valid: false, days_left: 0, issuer: "No Certificate (Domain Only / Parked)" }));
        socket.on('timeout', () => { socket.destroy(); resolve({ valid: false, days_left: 0, issuer: "No Certificate (Domain Only / Parked)" }); });
    });
}

// 4. REST APIS
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.get('/api/dashboard-data', (req, res) => {
    res.set({
        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    });

    const siteList = Object.values(monitoredSites);
    const domainList = Object.values(standaloneDomains);
    const upCount = siteList.filter(s => s.status === 'ONLINE').length + domainList.filter(d => d.status === 'ONLINE').length;
    const downCount = siteList.filter(s => s.status === 'OFFLINE').length + domainList.filter(d => d.status === 'OFFLINE').length;

    res.json({
        success: true,
        sites: siteList,
        domains: domainList,
        events: securityEvents,
        audit_logs: auditLogs,
        up_count: upCount,
        down_count: downCount,
        fleet_health: Math.max(0, 100 - (downCount * 25))
    });
});

app.post('/api/register', async (req, res) => {
    const secret = req.headers['x-hub-secret'];
    if (secret !== SHARED_SECRET) return res.status(403).json({ error: 'Unauthorized hub secret' });

    const data = req.body;
    if (!data.site_url) return res.status(400).json({ error: 'site_url required' });

    const clean = normalizeHost(data.site_url);
    delete standaloneDomains[clean];
    deletedDomains = deletedDomains.filter(d => d !== clean);

    const [liveSSL, liveDNS] = await Promise.all([
        inspectLiveSSL(data.site_url),
        scanFullDNSZone(data.site_url)
    ]);

    monitoredSites[data.site_url] = {
        name: data.site_name || clean,
        url: data.site_url,
        domain: clean,
        tag: 'wordpress site',
        wp_version: data.wp_version || '6.5',
        php_version: data.php_version || '8.2',
        theme: data.theme || { name: 'Active Theme', version: '1.0' },
        plugins: data.plugins || [],
        users: data.users || [],
        updates_count: data.pending_updates || 0,
        security_engine: 'Multi-Layer Sentinel Defense',
        performance: data.performance || { queries: 28, load_time: '0.28s', memory: '18 MB' },
        ssl: liveSSL,
        dns_records: liveDNS,
        seo: data.seo || { sitemap_status: 'Indexed', broken_links: 0 },
        analytics: data.analytics || { visitors_7d: 1200, pageviews: 4100, bounce_rate: '30.0%' },
        backups: monitoredSites[data.site_url]?.backups || [
            { id: 1, filename: 'db-backup-latest.sql', location: '/wp-content/flotek-backups/db-backup-latest.sql', filesize: '48.2 MB', date: '2026-03-01' }
        ],
        health_score: Math.max(30, 100 - (data.pending_updates || 0) * 3),
        status: 'ONLINE',
        http_code: 200,
        error_message: '200 OK',
        latency: Math.floor(Math.random() * 15 + 35),
        uptime_history: monitoredSites[data.site_url]?.uptime_history || Array(20).fill(1),
        uptime_pct: monitoredSites[data.site_url]?.uptime_pct || 100,
        type: 'WEBSITE'
    };

    saveDatabase();
    res.json({ success: true, site: monitoredSites[data.site_url] });
});

app.post('/api/add-domain', async (req, res) => {
    const { domain_name } = req.body;
    if (!domain_name) return res.status(400).json({ error: 'Domain name required' });

    const clean = normalizeHost(domain_name);
    deletedDomains = deletedDomains.filter(d => d !== clean);

    const [liveSSL, liveDNS] = await Promise.all([
        inspectLiveSSL(clean),
        scanFullDNSZone(clean)
    ]);

    let nameservers = ['Authoritative DNS'];
    try {
        nameservers = await dns.resolveNs(clean);
    } catch (e) {}

    standaloneDomains[clean] = {
        name: clean,
        domain: clean,
        registrar: nameservers[0] ? (nameservers[0].includes('livedns') ? 'Fasthosts LiveDNS' : nameservers[0].includes('cloudflare') ? 'Cloudflare DNS' : 'Authoritative DNS') : 'Authoritative DNS',
        nameservers: nameservers,
        ssl: liveSSL,
        dns_records: liveDNS,
        status: 'ONLINE',
        http_code: 200,
        error_message: '200 OK',
        latency: 40,
        uptime_history: Array(20).fill(1),
        uptime_pct: 100,
        type: 'DOMAIN_ONLY'
    };

    saveDatabase();
    res.json({ success: true, domain: standaloneDomains[clean] });
});

app.post('/api/delete-domain', (req, res) => {
    const { domain_name } = req.body;
    if (domain_name) {
        const clean = normalizeHost(domain_name);
        delete standaloneDomains[clean];
        delete standaloneDomains[domain_name];
        delete monitoredSites[clean];
        delete monitoredSites[domain_name];

        if (!deletedDomains.includes(clean)) {
            deletedDomains.push(clean);
        }
        saveDatabase();
    }
    res.json({ success: true });
});

app.post('/api/event', (req, res) => {
    const secret = req.headers['x-hub-secret'];
    if (secret !== SHARED_SECRET) return res.status(403).json({ error: 'Unauthorized' });

    const { site_url, site_name, event, details, type, timestamp } = req.body;
    const clean = normalizeHost(site_url);

    const record = {
        id: Date.now(),
        site_url: site_url || clean,
        domain: clean,
        site_name: site_name || clean,
        event: event || 'SECURITY_ALERT',
        details: details || {},
        type: type || 'SECURITY',
        timestamp: timestamp || new Date().toISOString()
    };

    if (type === 'AUDIT') auditLogs.unshift(record);
    else securityEvents.unshift(record);

    saveDatabase();
    res.json({ success: true, record });
});

// Proxy actions for Remote Management
app.post('/api/create-user', async (req, res) => {
    const { site_url, username, email, role, password } = req.body;
    try {
        const response = await fetch(`${site_url}/wp-json/flotek/v1/create-user`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Hub-Secret': SHARED_SECRET },
            body: JSON.stringify({ username, email, role, password })
        });
        res.json(await response.json());
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/reset-password', async (req, res) => {
    const { site_url, user_id, new_password } = req.body;
    try {
        const response = await fetch(`${site_url}/wp-json/flotek/v1/reset-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Hub-Secret': SHARED_SECRET },
            body: JSON.stringify({ user_id, new_password })
        });
        res.json(await response.json());
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/delete-user', async (req, res) => {
    const { site_url, user_id } = req.body;
    try {
        const response = await fetch(`${site_url}/wp-json/flotek/v1/delete-user`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Hub-Secret': SHARED_SECRET },
            body: JSON.stringify({ user_id })
        });
        res.json(await response.json());
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/trigger-update', async (req, res) => {
    const { site_url } = req.body;
    try {
        const response = await fetch(`${site_url}/wp-json/flotek/v1/update-plugins`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Hub-Secret': SHARED_SECRET }
        });
        res.json(await response.json());
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/trigger-backup', async (req, res) => {
    const { site_url } = req.body;
    try {
        const response = await fetch(`${site_url}/wp-json/flotek/v1/create-backup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Hub-Secret': SHARED_SECRET }
        });
        const result = await response.json();
        if (result.success && monitoredSites[site_url]) {
            monitoredSites[site_url].backups.unshift({
                id: Date.now(),
                filename: result.filename,
                location: result.location,
                filesize: result.filesize,
                date: result.timestamp
            });
            saveDatabase();
        }
        res.json(result);
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.listen(PORT, () => {
    console.log(`🛡️ Flotek Sentinel Enterprise Command Hub active on port ${PORT}`);
});
