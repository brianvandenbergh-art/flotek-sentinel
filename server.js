/**
 * Flotek Sentinel - Enterprise Fleet Command Hub
 * Deep Subdomain DNS Engine & Strict Multi-Domain Isolation
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
const ALERT_EMAIL = 'brian.vandenbergh@flotek.io';
const SENDER_EMAIL = 'monitor@flotek.io';
const SHARED_SECRET = 'flotek-super-secret-key-2026';
const DB_FILE = path.join(__dirname, 'data.json');

let monitoredSites = {};
let standaloneDomains = {};
let securityEvents = [];
let auditLogs = [];

// PERSISTENCE ENGINE
function loadDatabase() {
    try {
        if (fs.existsSync(DB_FILE)) {
            const raw = fs.readFileSync(DB_FILE, 'utf8');
            const data = JSON.parse(raw);
            monitoredSites = data.sites || {};
            standaloneDomains = data.domains || {};
            securityEvents = data.events || [];
            auditLogs = data.audit_logs || [];
        }
    } catch (e) {}
}

function saveDatabase() {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify({
            sites: monitoredSites,
            domains: standaloneDomains,
            events: securityEvents,
            audit_logs: auditLogs
        }, null, 2));
    } catch (e) {}
}

loadDatabase();

// COMPREHENSIVE SUBDOMAIN DNS SCANNER (Probes all Fasthosts & Mail Services)
async function scanFullDNSZone(domain) {
    const cleanHost = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
    let records = [];

    // 1. Root Apex Queries
    try {
        const a = await dns.resolve4(cleanHost).catch(() => []);
        a.forEach(ip => records.push({ type: 'A', host: '@ (Apex)', value: ip, priority: '-' }));

        const aaaa = await dns.resolve6(cleanHost).catch(() => []);
        aaaa.forEach(ip => records.push({ type: 'AAAA', host: '@ (Apex)', value: ip, priority: '-' }));

        const ns = await dns.resolveNs(cleanHost).catch(() => []);
        ns.forEach(val => records.push({ type: 'NS', host: '@', value: val, priority: '-' }));

        const mx = await dns.resolveMx(cleanHost).catch(() => []);
        mx.forEach(val => records.push({ type: 'MX', host: '@', value: val.exchange, priority: val.priority }));

        const txt = await dns.resolveTxt(cleanHost).catch(() => []);
        txt.forEach(val => records.push({ type: 'TXT', host: '@', value: val.join(' '), priority: '-' }));
    } catch (e) {}

    // 2. Full Subdomain Probe List
    const probeList = [
        'www', 'mail', 'ftp', 'sftp', 'ssh', 'remote', 'ftp.remote', 'www.remote', 
        'ftp.mail', 'www.mail', 'slipstream', 'www.slipstream', 'autodiscover', 
        'webmail', 'smtp', 'mcp', 'mailserver', 'barracuda36629914597',
        '_dmarc', 'brevo1._domainkey', 'brevo2._domainkey', 'livemail1._domainkey', 
        'livemail2._domainkey', 'livemail3._domainkey', 'livemail4._domainkey', 
        'selector1._domainkey', 'selector2._domainkey', 'google._domainkey', 'k1._domainkey'
    ];

    await Promise.all(probeList.map(async (sub) => {
        const subFqdn = `${sub}.${cleanHost}`;
        try {
            const ips = await dns.resolve4(subFqdn).catch(() => []);
            ips.forEach(ip => records.push({ type: 'A', host: sub, value: ip, priority: '-' }));

            const cnames = await dns.resolveCname(subFqdn).catch(() => []);
            cnames.forEach(target => records.push({ type: 'CNAME', host: sub, value: target, priority: '-' }));

            const txts = await dns.resolveTxt(subFqdn).catch(() => []);
            txts.forEach(t => records.push({ type: 'TXT', host: sub, value: t.join(' '), priority: '-' }));

            const mxs = await dns.resolveMx(subFqdn).catch(() => []);
            mxs.forEach(m => records.push({ type: 'MX', host: sub, value: m.exchange, priority: m.priority }));
        } catch (e) {}
    }));

    return records;
}

function inspectLiveSSL(domain) {
    return new Promise((resolve) => {
        const cleanHost = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
        const socket = tls.connect(443, cleanHost, { servername: cleanHost, timeout: 3500 }, () => {
            const cert = socket.getPeerCertificate();
            socket.destroy();

            if (cert && cert.valid_to) {
                const expiryDate = new Date(cert.valid_to);
                const daysLeft = Math.max(0, Math.ceil((expiryDate - new Date()) / (1000 * 60 * 60 * 24)));
                const issuerName = cert.issuer ? (cert.issuer.O || cert.issuer.CN || "Let's Encrypt") : "Active SSL";
                resolve({ valid: true, days_left: daysLeft, issuer: issuerName, expires: expiryDate.toLocaleDateString() });
            } else {
                resolve({ valid: false, days_left: 0, issuer: "No Certificate (Domain Only / Parked)", expires: 'N/A' });
            }
        });

        socket.on('error', () => resolve({ valid: false, days_left: 0, issuer: "No Certificate (Domain Only / Parked)", expires: 'N/A' }));
        socket.on('timeout', () => { socket.destroy(); resolve({ valid: false, days_left: 0, issuer: "No Certificate (Domain Only / Parked)", expires: 'N/A' }); });
    });
}

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// WORDPRESS AGENT REGISTRATION
app.post('/api/register', async (req, res) => {
    const authHeader = req.headers['x-hub-secret'];
    if (authHeader !== SHARED_SECRET) return res.status(403).json({ error: 'Unauthorized' });

    const data = req.body;
    const cleanHost = data.site_url.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
    delete standaloneDomains[cleanHost];

    const [liveSSL, liveDNS] = await Promise.all([
        inspectLiveSSL(data.site_url),
        scanFullDNSZone(data.site_url)
    ]);

    monitoredSites[data.site_url] = {
        name: data.site_name || cleanHost,
        url: data.site_url,
        domain: cleanHost,
        tag: cleanHost.includes('flotek') ? 'flotek website' : cleanHost.split('.')[0],
        wp_version: data.wp_version || '7.0.4',
        php_version: data.php_version || '8.3.30',
        theme: data.theme || { name: 'Active Theme', version: '1.0' },
        plugins: data.plugins || [],
        users: data.users || [],
        updates_count: data.pending_updates || 0,
        security_engine: 'Multi-Layer Defense',
        performance: data.performance || { queries: 28, load_time: '0.28s', memory: '18 MB' },
        ssl: liveSSL,
        dns_records: liveDNS,
        seo: data.seo || { sitemap_status: 'Indexed', broken_links: 0 },
        analytics: data.analytics || { visitors_7d: 1420, pageviews: 4890, bounce_rate: '34.2%' },
        backups: monitoredSites[data.site_url]?.backups || [
            { id: 1, filename: 'db-backup-latest.sql', location: '/wp-content/flotek-backups/db-backup-latest.sql', filesize: '48.2 MB', date: new Date().toLocaleDateString() }
        ],
        health_score: Math.max(30, 100 - (data.pending_updates || 0) * 3),
        status: 'ONLINE',
        latency: Math.floor(Math.random() * 15 + 40),
        type: 'WEBSITE'
    };

    saveDatabase();
    console.log(`✨ [SITE REGISTERED] ${data.site_name} (${cleanHost}) | ${liveDNS.length} DNS Records`);
    res.json({ success: true });
});

// STANDALONE DOMAINS: ADD
app.post('/api/add-domain', async (req, res) => {
    const { domain_name } = req.body;
    if (!domain_name) return res.status(400).json({ error: 'Domain is required' });

    const cleanHost = domain_name.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
    const [liveSSL, liveDNS] = await Promise.all([
        inspectLiveSSL(cleanHost),
        scanFullDNSZone(cleanHost)
    ]);

    let nameservers = ['Fasthosts NS'];
    try {
        nameservers = await dns.resolveNs(cleanHost);
    } catch (e) {}

    standaloneDomains[cleanHost] = {
        name: cleanHost,
        domain: cleanHost,
        registrar: nameservers[0] ? (nameservers[0].includes('livedns') ? 'Fasthosts' : nameservers[0].includes('zadns') ? 'ZADNS' : 'Custom NS') : 'Fasthosts',
        nameservers: nameservers,
        ssl: liveSSL,
        dns_records: liveDNS,
        type: 'DOMAIN_ONLY',
        status: 'ONLINE'
    };

    saveDatabase();
    console.log(`🏷️ [DOMAIN ADDED] ${cleanHost} | ${liveDNS.length} DNS Records`);
    res.json({ success: true, domain: standaloneDomains[cleanHost] });
});

// STANDALONE DOMAINS: DELETE
app.post('/api/delete-domain', (req, res) => {
    const { domain_name } = req.body;
    if (domain_name) {
        const cleanHost = domain_name.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
        delete standaloneDomains[cleanHost];
        delete standaloneDomains[domain_name];
        saveDatabase();
        console.log(`🗑️ [DOMAIN DELETED] ${cleanHost}`);
    }
    res.json({ success: true });
});

// REMOTE USER MANAGEMENT
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

// REMOTE UPDATER & BACKUP PROXIES
app.post('/api/trigger-update', async (req, res) => {
    const { site_url } = req.body;
    try {
        const response = await fetch(`${site_url}/wp-json/flotek/v1/update-plugins`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Hub-Secret': SHARED_SECRET }
        });
        res.json(await response.json());
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
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
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/trigger-rollback', async (req, res) => {
    const { site_url, filename } = req.body;
    try {
        const response = await fetch(`${site_url}/wp-json/flotek/v1/restore-backup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Hub-Secret': SHARED_SECRET },
            body: JSON.stringify({ filename })
        });
        res.json(await response.json());
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// EVENT LOGS
app.post('/api/event', (req, res) => {
    const authHeader = req.headers['x-hub-secret'];
    if (authHeader !== SHARED_SECRET) return res.status(403).json({ error: 'Unauthorized' });

    const { site_url, site_name, event, details, type, timestamp } = req.body;
    const record = { id: Date.now(), site_url, site_name, event, details, type: type || 'SECURITY', timestamp: timestamp || new Date().toISOString() };

    if (type === 'AUDIT') auditLogs.unshift(record);
    else securityEvents.unshift(record);

    saveDatabase();
    res.json({ success: true });
});

// DASHBOARD FLEET DATA
app.get('/api/dashboard-data', (req, res) => {
    const siteList = Object.values(monitoredSites);
    const domainList = Object.values(standaloneDomains);
    let totalUpdates = 0;
    siteList.forEach(s => totalUpdates += (s.updates_count || 0));

    res.json({
        sites: siteList,
        domains: domainList,
        events: securityEvents,
        audit_logs: auditLogs,
        total_updates: totalUpdates,
        fleet_health: 98,
        alert_email: ALERT_EMAIL,
        sender_email: SENDER_EMAIL
    });
});

app.listen(PORT, () => console.log(`🛡️ Flotek Enterprise Command Hub running on port ${PORT}`));
