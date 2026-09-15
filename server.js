/**
 * Flotek Sentinel - Enterprise Fleet Command Hub
 * Universal Dynamic DNS Zone Discovery & SSL Telemetry Engine
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

// 1. DEFAULT FLEET
const INITIAL_SITES = {
    'https://grandprixexpress.com': {
        name: 'Grand Prix Express',
        url: 'https://grandprixexpress.com',
        domain: 'grandprixexpress.com',
        tag: 'wordpress site',
        wp_version: '6.5.2',
        php_version: '8.2.18',
        theme: { name: 'ServerEast Fleet', version: '1.2.0' },
        plugins: [
            { name: 'Meta Box', version: '5.6.17', has_update: true, new_version: '5.15.0' },
            { name: 'Redirection', version: '5.3.10', has_update: true, new_version: '5.10.0' },
            { name: 'Wordfence Security', version: '7.11.0', has_update: false },
            { name: 'All-In-One Security (AIOS)', version: '5.2.5', has_update: false },
            { name: 'Flotek Sentinel Agent', version: '8.5.0', has_update: false }
        ],
        users: [
            { id: 1, user_login: 'garry', user_email: 'garry.whitney@grandprixexpress.com', roles: ['editor'], registered: '2025-01-10' },
            { id: 2, user_login: 'oes-admin', user_email: 'paul.hesketh@oes-uk.com', roles: ['administrator'], registered: '2024-11-20' }
        ],
        updates_count: 12,
        security_engine: 'AIOS + Wordfence',
        performance: { queries: 28, load_time: '0.28s', memory: '18 MB' },
        ssl: { valid: true, days_left: 84, issuer: "Cloudflare / Let's Encrypt" },
        dns_records: [],
        seo: { sitemap_status: 'Indexed (22 URLs Valid)', broken_links: 0 },
        analytics: { visitors_7d: 1840, pageviews: 5620, bounce_rate: '28.4%' },
        backups: [
            { id: 1, filename: 'db-backup-latest.sql', location: '/wp-content/flotek-backups/db-backup-latest.sql', filesize: '48.2 MB', date: '2026-03-01' }
        ],
        health_score: 94,
        status: 'ONLINE',
        latency: 37,
        type: 'WEBSITE'
    },
    'https://gamlins.com': {
        name: 'Gamlins Solicitors',
        url: 'https://gamlins.com',
        domain: 'gamlins.com',
        tag: 'wordpress site',
        wp_version: '6.4.3',
        php_version: '8.2.20',
        theme: { name: 'Gamlins Solicitors Enterprise', version: '2.1.0' },
        plugins: [
            { name: 'Advanced Custom Fields Pro', version: '6.1.0', has_update: true, new_version: '6.3.2' },
            { name: 'Contact Form 7', version: '5.8.0', has_update: true, new_version: '5.9.4' },
            { name: 'WP Rocket', version: '3.14.0', has_update: false },
            { name: 'Flotek Sentinel Agent', version: '8.5.0', has_update: false }
        ],
        users: [
            { id: 1, user_login: 'gamlins-admin', user_email: 'info@gamlins.com', roles: ['administrator'], registered: '2024-08-15' },
            { id: 2, user_login: 'reception', user_email: 'reception@gamlins.com', roles: ['author'], registered: '2025-02-01' }
        ],
        updates_count: 22,
        security_engine: 'Enterprise WAF Active',
        performance: { queries: 34, load_time: '0.31s', memory: '24 MB' },
        ssl: { valid: true, days_left: 156, issuer: "Sectigo Limited" },
        dns_records: [],
        seo: { sitemap_status: 'Indexed (184 URLs Valid)', broken_links: 0 },
        analytics: { visitors_7d: 4280, pageviews: 14350, bounce_rate: '21.6%' },
        backups: [
            { id: 1, filename: 'db-backup-latest.sql', location: '/wp-content/flotek-backups/db-backup-latest.sql', filesize: '62.4 MB', date: '2026-03-01' }
        ],
        health_score: 91,
        status: 'ONLINE',
        latency: 48,
        type: 'WEBSITE'
    }
};

const INITIAL_DOMAINS = {
    'flotek.io': {
        name: 'Flotek Group HQ',
        domain: 'flotek.io',
        registrar: 'Cloudflare / Authoritative DNS',
        nameservers: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
        ssl: { valid: true, days_left: 210, issuer: "DigiCert Global Root CA" },
        dns_records: [],
        type: 'DOMAIN_ONLY',
        status: 'ONLINE'
    },
    'gamlins.co.uk': {
        name: 'gamlins.co.uk',
        domain: 'gamlins.co.uk',
        registrar: 'Fasthosts LiveDNS',
        nameservers: ['ns1.livedns.co.uk', 'ns2.livedns.co.uk'],
        ssl: { valid: false, days_left: 0, issuer: 'No Certificate (Domain Only / Parked)' },
        dns_records: [],
        type: 'DOMAIN_ONLY',
        status: 'ONLINE'
    },
    'moolawise.co.za': {
        name: 'moolawise.co.za',
        domain: 'moolawise.co.za',
        registrar: 'ZADNS / Absolute Hosting',
        nameservers: ['ns21.zadns.co.za', 'ns22.zadns.co.za'],
        ssl: { valid: false, days_left: 0, issuer: 'No Certificate (Domain Only / Parked)' },
        dns_records: [],
        type: 'DOMAIN_ONLY',
        status: 'ONLINE'
    }
};

let monitoredSites = { ...INITIAL_SITES };
let standaloneDomains = { ...INITIAL_DOMAINS };
let securityEvents = [];
let auditLogs = [];

function loadDatabase() {
    try {
        if (fs.existsSync(DB_FILE)) {
            const raw = fs.readFileSync(DB_FILE, 'utf8');
            const data = JSON.parse(raw);
            if (data.sites && Object.keys(data.sites).length > 0) monitoredSites = data.sites;
            if (data.domains && Object.keys(data.domains).length > 0) standaloneDomains = data.domains;
            if (Array.isArray(data.events) && data.events.length > 0) securityEvents = data.events;
            if (Array.isArray(data.audit_logs)) auditLogs = data.audit_logs;
        }
    } catch (err) {}
    delete monitoredSites['https://flotek.io'];
    delete monitoredSites['flotek.io'];
}

function saveDatabase() {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify({
            sites: monitoredSites,
            domains: standaloneDomains,
            events: securityEvents,
            audit_logs: auditLogs
        }, null, 2));
    } catch (err) {}
}

loadDatabase();
saveDatabase();

// 2. UNIVERSAL DYNAMIC MULTI-LEVEL DNS SCANNER
const COMPREHENSIVE_HOST_DICTIONARY = [
    // Standard Services
    'www', 'ftp', 'mail', 'smtp', 'webmail', 'autodiscover', 'remote', 'vpn', 'access', 'rds', 'media',
    'oneadvanced', 'portal', 'api', 'dev', 'stage', 'staging', 'direct', 'server', 'ssh', 'sftp', 'ns1', 'ns2',
    // Microsoft 365, Lync & Teams
    'lyncdiscover', 'msoid', 'sip', 'enterpriseenrollment', 'enterpriseregistration',
    // DKIM Selectors & Security
    'selector1._domainkey', 'selector2._domainkey', 'google._domainkey', 'k1._domainkey',
    'selector1-gamlins-com._domainkey', 'selector2-gamlins-com._domainkey',
    'barracuda92160414593', 'barracuda36629914597', '_e871c8238c0992dfb1d08a0579540795',
    '_dmarc',
    // Regional & Branch Locations (Single & Multi-level)
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

    // 1. Wildcard DNS detection
    const wildcardProbeHost = `_sentinel_wildcard_check_${Date.now()}.${host}`;
    const wildcardProbeIps = await safeResolve(dns.resolve4, wildcardProbeHost);
    const wildcardIp = wildcardProbeIps.length > 0 ? wildcardProbeIps[0] : null;

    if (wildcardIp) {
        records.push({ type: 'A', host: '* (Wildcard)', value: wildcardIp, priority: '-' });
    }

    // 2. Query Apex Records (@)
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

    // 3. Probing Host Dictionary (A, AAAA, CNAME, MX, TXT)
    await Promise.all(COMPREHENSIVE_HOST_DICTIONARY.map(async (sub) => {
        const fqdn = `${sub}.${host}`;

        // CNAME query
        const cnames = await safeResolve(dns.resolveCname, fqdn);
        if (cnames.length > 0) {
            cnames.forEach(target => records.push({ type: 'CNAME', host: sub, value: target, priority: '-' }));
            return;
        }

        // A Record
        const ips = await safeResolve(dns.resolve4, fqdn);
        ips.forEach(ip => {
            if (!wildcardIp || ip !== wildcardIp) {
                records.push({ type: 'A', host: sub, value: ip, priority: '-' });
            }
        });

        // AAAA Record (IPv6)
        const v6 = await safeResolve(dns.resolve6, fqdn);
        v6.forEach(ip => records.push({ type: 'AAAA', host: sub, value: ip, priority: '-' }));

        // Subdomain & Branch MX Routing
        const mxs = await safeResolve(dns.resolveMx, fqdn);
        mxs.forEach(m => records.push({ type: 'MX', host: sub, value: m.exchange, priority: m.priority }));

        // Subdomain TXT
        if (sub.includes('_dmarc') || sub.includes('_domainkey')) {
            const txts = await safeResolve(dns.resolveTxt, fqdn);
            txts.forEach(t => records.push({ type: 'TXT', host: sub, value: Array.isArray(t) ? t.join('') : t, priority: '-' }));
        }
    }));

    // 4. SRV Records Probing
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

    // 5. De-duplicate and Sort
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

// Background initial scan
(async () => {
    for (const url in monitoredSites) {
        if (!monitoredSites[url].dns_records || monitoredSites[url].dns_records.length === 0) {
            monitoredSites[url].dns_records = await scanFullDNSZone(url);
        }
    }
    for (const dom in standaloneDomains) {
        if (!standaloneDomains[dom].dns_records || standaloneDomains[dom].dns_records.length === 0) {
            standaloneDomains[dom].dns_records = await scanFullDNSZone(dom);
        }
    }
    saveDatabase();
})();

// 4. REST APIS
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.get('/api/dashboard-data', (req, res) => {
    res.set({
        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    });

    res.json({
        success: true,
        sites: Object.values(monitoredSites),
        domains: Object.values(standaloneDomains),
        events: securityEvents,
        audit_logs: auditLogs,
        fleet_health: 99
    });
});

app.post('/api/register', async (req, res) => {
    const secret = req.headers['x-hub-secret'];
    if (secret !== SHARED_SECRET) return res.status(403).json({ error: 'Unauthorized hub secret' });

    const data = req.body;
    if (!data.site_url) return res.status(400).json({ error: 'site_url required' });

    const clean = normalizeHost(data.site_url);
    delete standaloneDomains[clean];

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
        latency: Math.floor(Math.random() * 15 + 35),
        type: 'WEBSITE'
    };

    saveDatabase();
    res.json({ success: true, site: monitoredSites[data.site_url] });
});

app.post('/api/add-domain', async (req, res) => {
    const { domain_name } = req.body;
    if (!domain_name) return res.status(400).json({ error: 'Domain name required' });

    const clean = normalizeHost(domain_name);
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
        type: 'DOMAIN_ONLY',
        status: 'ONLINE'
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

// WordPress Remote Proxy Actions
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
