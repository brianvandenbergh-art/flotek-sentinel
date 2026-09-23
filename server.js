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
const net = require('net');
const { execFile } = require('child_process');
const { promisify } = require('util');

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

// 1. COMPLETE PERMANENT FLEET REGISTRY (5 WordPress Sites, 3 Standalone Domains)
const DEFAULT_SITES = {
    'https://davidmanning.co.uk': {
        name: 'David Manning & Co.',
        url: 'https://davidmanning.co.uk',
        domain: 'davidmanning.co.uk',
        tag: 'wordpress site',
        wp_version: '6.5.2',
        php_version: '8.2.18',
        theme: { name: 'David Manning Theme', version: '1.0.0' },
        plugins: [
            { name: 'Wordfence Security', version: '7.11.0', has_update: false },
            { name: 'Flotek Sentinel Agent', version: '8.7.0', has_update: false }
        ],
        users: [{ id: 1, user_login: 'admin', user_email: 'info@davidmanning.co.uk', roles: ['administrator'], registered: '2024-05-10' }],
        updates_count: 14,
        security_engine: 'Sentinel Agent Active',
        performance: { queries: 24, load_time: '0.22s', memory: '16 MB' },
        ssl: { valid: true, days_left: 88, issuer: "Let's Encrypt" },
        dns_records: [],
        seo: { sitemap_status: 'Indexed (10 URLs Valid)', broken_links: 0 },
        analytics: { visitors_7d: 640, pageviews: 1980, bounce_rate: '41.2%' },
        backups: [{ id: 1, filename: 'db-backup-latest.sql', location: '/wp-content/flotek-backups/db-backup-latest.sql', filesize: '24.2 MB', date: '2026-03-01' }],
        status: 'ONLINE',
        http_code: 200,
        error_message: '200 OK',
        latency: 41,
        uptime_history: Array(20).fill(1),
        uptime_pct: 100,
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
            { name: 'Flotek Sentinel Agent', version: '8.7.0', has_update: false }
        ],
        users: [
            { id: 1, user_login: 'gamlins-admin', user_email: 'info@gamlins.com', roles: ['administrator'], registered: '2024-08-15' },
            { id: 2, user_login: 'reception', user_email: 'reception@gamlins.com', roles: ['author'], registered: '2025-02-01' }
        ],
        updates_count: 23,
        security_engine: 'Enterprise WAF Active',
        performance: { queries: 34, load_time: '0.31s', memory: '24 MB' },
        ssl: { valid: true, days_left: 156, issuer: "Sectigo Limited" },
        dns_records: [],
        seo: { sitemap_status: 'Indexed (184 URLs Valid)', broken_links: 0 },
        analytics: { visitors_7d: 4280, pageviews: 14350, bounce_rate: '21.6%' },
        backups: [{ id: 1, filename: 'db-backup-latest.sql', location: '/wp-content/flotek-backups/db-backup-latest.sql', filesize: '62.4 MB', date: '2026-03-01' }],
        status: 'ONLINE',
        http_code: 200,
        error_message: '200 OK',
        latency: 43,
        uptime_history: Array(20).fill(1),
        uptime_pct: 100,
        type: 'WEBSITE'
    },
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
            { name: 'Flotek Sentinel Agent', version: '8.7.0', has_update: false }
        ],
        users: [
            { id: 1, user_login: 'garry', user_email: 'garry.whitney@grandprixexpress.com', roles: ['editor'], registered: '2025-01-10' },
            { id: 2, user_login: 'oes-admin', user_email: 'paul.hesketh@oes-uk.com', roles: ['administrator'], registered: '2024-11-20' }
        ],
        updates_count: 13,
        security_engine: 'AIOS + Wordfence',
        performance: { queries: 28, load_time: '0.28s', memory: '18 MB' },
        ssl: { valid: true, days_left: 84, issuer: "Cloudflare / Let's Encrypt" },
        dns_records: [],
        seo: { sitemap_status: 'Indexed (22 URLs Valid)', broken_links: 0 },
        analytics: { visitors_7d: 1840, pageviews: 5620, bounce_rate: '28.4%' },
        backups: [{ id: 1, filename: 'db-backup-latest.sql', location: '/wp-content/flotek-backups/db-backup-latest.sql', filesize: '48.2 MB', date: '2026-03-01' }],
        status: 'ONLINE',
        http_code: 200,
        error_message: '200 OK',
        latency: 41,
        uptime_history: Array(20).fill(1),
        uptime_pct: 100,
        type: 'WEBSITE'
    },
    'https://theflyshop.co.uk': {
        name: 'The Fly Shop',
        url: 'https://theflyshop.co.uk',
        domain: 'theflyshop.co.uk',
        tag: 'wordpress site',
        wp_version: '6.5.3',
        php_version: '8.2.19',
        theme: { name: 'Astra Pro', version: '4.6.0' },
        plugins: [
            { name: 'WooCommerce', version: '8.8.0', has_update: true, new_version: '8.9.2' },
            { name: 'Flotek Sentinel Agent', version: '8.7.0', has_update: false }
        ],
        users: [{ id: 1, user_login: 'shopadmin', user_email: 'info@theflyshop.co.uk', roles: ['administrator'], registered: '2024-02-14' }],
        updates_count: 3,
        security_engine: 'Sentinel Agent Active',
        performance: { queries: 32, load_time: '0.26s', memory: '22 MB' },
        ssl: { valid: true, days_left: 112, issuer: "cPanel / Sectigo" },
        dns_records: [],
        seo: { sitemap_status: 'Indexed (64 URLs Valid)', broken_links: 0 },
        analytics: { visitors_7d: 2940, pageviews: 8400, bounce_rate: '31.5%' },
        backups: [{ id: 1, filename: 'db-backup-latest.sql', location: '/wp-content/flotek-backups/db-backup-latest.sql', filesize: '54.0 MB', date: '2026-03-01' }],
        status: 'ONLINE',
        http_code: 200,
        error_message: '200 OK',
        latency: 46,
        uptime_history: Array(20).fill(1),
        uptime_pct: 100,
        type: 'WEBSITE'
    },
    'https://localconnectsa.co.za': {
        name: 'Local Connect SA',
        url: 'https://localconnectsa.co.za',
        domain: 'localconnectsa.co.za',
        tag: 'wordpress site',
        wp_version: '6.5.0',
        php_version: '8.1.28',
        theme: { name: 'Local Connect Theme', version: '1.0.0' },
        plugins: [
            { name: 'Elementor', version: '3.20.0', has_update: true, new_version: '3.21.0' },
            { name: 'Flotek Sentinel Agent', version: '8.7.0', has_update: false }
        ],
        users: [{ id: 1, user_login: 'localadmin', user_email: 'admin@localconnectsa.co.za', roles: ['administrator'], registered: '2024-06-01' }],
        updates_count: 15,
        security_engine: 'Sentinel Agent Active',
        performance: { queries: 26, load_time: '0.35s', memory: '20 MB' },
        ssl: { valid: true, days_left: 74, issuer: "Let's Encrypt" },
        dns_records: [],
        seo: { sitemap_status: 'Indexed (18 URLs Valid)', broken_links: 0 },
        analytics: { visitors_7d: 1120, pageviews: 3450, bounce_rate: '36.8%' },
        backups: [{ id: 1, filename: 'db-backup-latest.sql', location: '/wp-content/flotek-backups/db-backup-latest.sql', filesize: '32.1 MB', date: '2026-03-01' }],
        status: 'ONLINE',
        http_code: 200,
        error_message: '200 OK',
        latency: 37,
        uptime_history: Array(20).fill(1),
        uptime_pct: 100,
        type: 'WEBSITE'
    }
};

const DEFAULT_DOMAINS = {
    'flotek.io': {
        name: 'Flotek Group HQ',
        domain: 'flotek.io',
        registrar: 'Cloudflare / Authoritative DNS',
        nameservers: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
        ssl: { valid: true, days_left: 210, issuer: "DigiCert Global Root CA" },
        dns_records: [],
        status: 'ONLINE',
        http_code: 200,
        error_message: '200 OK',
        latency: 35,
        uptime_history: Array(20).fill(1),
        uptime_pct: 100,
        type: 'DOMAIN_ONLY'
    },
    'gamlins.co.uk': {
        name: 'gamlins.co.uk',
        domain: 'gamlins.co.uk',
        registrar: 'Fasthosts LiveDNS',
        nameservers: ['ns1.livedns.co.uk', 'ns2.livedns.co.uk'],
        ssl: { valid: false, days_left: 0, issuer: 'No Certificate (Domain Only / Parked)' },
        dns_records: [],
        status: 'ONLINE',
        http_code: 200,
        error_message: '200 OK',
        latency: 40,
        uptime_history: Array(20).fill(1),
        uptime_pct: 100,
        type: 'DOMAIN_ONLY'
    },
    'unifabs.eu': {
        name: 'unifabs.eu',
        domain: 'unifabs.eu',
        registrar: 'European Registrar / Wildcard DNS',
        nameservers: ['ns1.unifabs.eu', 'ns2.unifabs.eu'],
        ssl: { valid: true, days_left: 92, issuer: "Let's Encrypt" },
        dns_records: [],
        status: 'ONLINE',
        http_code: 200,
        error_message: '200 OK',
        latency: 38,
        uptime_history: Array(20).fill(1),
        uptime_pct: 100,
        type: 'DOMAIN_ONLY'
    }
};

let monitoredSites = { ...DEFAULT_SITES };
let standaloneDomains = { ...DEFAULT_DOMAINS };
let securityEvents = [];
let auditLogs = [];
let archivedEvents = [];
let deletedDomains = ['moolawise.co.za']; // Permanently blacklisted
const execFileAsync = promisify(execFile);
const DNS_SCAN_INTERVAL_MS = 5 * 60 * 1000;
let lastDnsScanAt = 0;

function loadDatabase() {
    try {
        if (fs.existsSync(DB_FILE)) {
            const raw = fs.readFileSync(DB_FILE, 'utf8');
            const data = JSON.parse(raw);
            if (data.sites && Object.keys(data.sites).length > 0) {
                monitoredSites = { ...DEFAULT_SITES, ...data.sites };
            }
            if (data.domains && Object.keys(data.domains).length > 0) {
                standaloneDomains = { ...DEFAULT_DOMAINS, ...data.domains };
            }
            if (Array.isArray(data.events)) securityEvents = data.events;
            if (Array.isArray(data.audit_logs)) auditLogs = data.audit_logs;
            if (Array.isArray(data.archived_events)) archivedEvents = data.archived_events;
            if (Array.isArray(data.deleted_domains)) {
                deletedDomains = Array.from(new Set([...deletedDomains, ...data.deleted_domains]));
            }
        }
    } catch (err) {}

    // Never resurrect blacklisted/deleted domains
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
            archived_events: archivedEvents,
            deleted_domains: deletedDomains
        }, null, 2));
    } catch (err) {}
}

loadDatabase();
saveDatabase();

// 2. ACTIVE SERVER, HTTP AND WORDPRESS HEALTH DETECTOR
function normalizeErrorMessage(error) {
    let message = error && error.message ? error.message : String(error || 'Unknown error');
    if (message.includes('ECONNREFUSED')) return 'Connection refused by target';
    if (message.includes('ENOTFOUND')) return 'DNS lookup failed';
    if (message.toLowerCase().includes('certificate')) return 'SSL handshake failed';
    return message.slice(0, 240);
}

async function checkHttpHealth(entity) {
    const targetUrl = entity.url || `https://${entity.domain}`;
    const startTime = Date.now();
    let controller;
    let timeoutId;

    try {
        controller = new AbortController();
        timeoutId = setTimeout(() => controller.abort(), 7000);
        const response = await fetch(targetUrl, {
            method: 'GET',
            headers: { 'User-Agent': 'Flotek-Sentinel-Monitor/11.0 (+https://flotek.io)' },
            signal: controller.signal,
            redirect: 'follow'
        });
        const latency = Date.now() - startTime;
        const isSuccess = response.status >= 200 && response.status < 400;
        return {
            status: isSuccess ? 'ONLINE' : 'OFFLINE',
            http_code: response.status,
            error_message: isSuccess ? `${response.status} ${response.statusText || 'OK'}` : `${response.status} ${response.statusText || 'HTTP error'}`,
            latency
        };
    } catch (err) {
        return {
            status: 'OFFLINE',
            http_code: err.name === 'AbortError' ? 408 : 503,
            error_message: err.name === 'AbortError' ? 'HTTP request timed out after 7s' : normalizeErrorMessage(err),
            latency: Date.now() - startTime
        };
    } finally {
        if (timeoutId) clearTimeout(timeoutId);
    }
}

function tcpProbe(address, port, timeoutMs = 2500) {
    return new Promise(resolve => {
        const socket = net.createConnection({ host: address, port, timeout: timeoutMs });
        let settled = false;
        const finish = result => {
            if (settled) return;
            settled = true;
            socket.destroy();
            resolve(result);
        };
        socket.once('connect', () => finish({ reachable: true, method: 'tcp', address, port }));
        socket.once('timeout', () => finish({ reachable: false, method: 'tcp', address, port, error: 'TCP connection timed out' }));
        socket.once('error', error => finish({ reachable: false, method: 'tcp', address, port, error: normalizeErrorMessage(error) }));
    });
}

async function pingAddress(address) {
    try {
        await execFileAsync('ping', process.platform === 'win32'
            ? ['-n', '1', '-w', '2500', address]
            : ['-c', '1', '-W', '2', address], { timeout: 3500, maxBuffer: 1024 * 32 });
        return { reachable: true, method: 'icmp', address };
    } catch (error) {
        return { reachable: false, method: 'icmp', address, error: normalizeErrorMessage(error) };
    }
}

async function checkServerReachability(host) {
    const addresses = [];
    try { addresses.push(...await dns.resolve4(host)); } catch (e) {}
    try { addresses.push(...await dns.resolve6(host)); } catch (e) {}
    const uniqueAddresses = Array.from(new Set(addresses)).slice(0, 4);

    if (uniqueAddresses.length === 0) {
        return { reachable: false, state: 'DNS_UNRESOLVED', error: 'No A or AAAA address resolved', addresses: [] };
    }

    for (const address of uniqueAddresses) {
        const icmp = await pingAddress(address);
        if (icmp.reachable) {
            return { ...icmp, state: 'REACHABLE', addresses: uniqueAddresses };
        }
        const tlsProbe = await tcpProbe(address, 443);
        if (tlsProbe.reachable) {
            return { ...tlsProbe, state: 'REACHABLE', addresses: uniqueAddresses };
        }
        const httpProbe = await tcpProbe(address, 80);
        if (httpProbe.reachable) {
            return { ...httpProbe, state: 'REACHABLE', addresses: uniqueAddresses };
        }
    }

    return {
        reachable: false,
        state: 'SERVER_UNREACHABLE',
        addresses: uniqueAddresses,
        error: 'ICMP and TCP probes could not reach the resolved server'
    };
}

async function checkWordPressAgent(entity) {
    if (!entity.url || entity.type === 'DOMAIN_ONLY') return { reachable: false, reason: 'Not a WordPress monitor' };
    const endpoint = `${entity.url.replace(/\/+$/, '')}/wp-json/flotek/v1/health`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4500);
    try {
        const response = await fetch(endpoint, {
            method: 'GET',
            headers: { 'X-Hub-Secret': SHARED_SECRET, 'User-Agent': 'Flotek-Sentinel-Monitor/11.0' },
            signal: controller.signal,
            redirect: 'follow'
        });
        let body = null;
        try { body = await response.json(); } catch (e) {}
        return { reachable: response.ok, http_code: response.status, body, reason: response.ok ? null : `${response.status} ${response.statusText || 'Agent error'}` };
    } catch (error) {
        return { reachable: false, reason: normalizeErrorMessage(error) };
    } finally {
        clearTimeout(timeoutId);
    }
}

async function checkEntityHealth(entity) {
    const host = normalizeHost(entity.url || entity.domain);
    const [http, server] = await Promise.all([checkHttpHealth(entity), checkServerReachability(host)]);
    let agent = null;

    // Only ask the WordPress agent for evidence when the public HTTP check failed.
    // This prevents the outage message from guessing about files on every normal ping.
    if (http.status === 'OFFLINE' && server.state === 'REACHABLE' && entity.type !== 'DOMAIN_ONLY') {
        agent = await checkWordPressAgent(entity);
    }

    let cause = 'none';
    let summary = 'HTTP endpoint responded successfully.';
    const dnsChanged = entity.dns_changes && (
        (entity.dns_changes.added && entity.dns_changes.added.length) ||
        (entity.dns_changes.removed && entity.dns_changes.removed.length)
    );
    if (http.status === 'OFFLINE') {
        if (server.state === 'DNS_UNRESOLVED') {
            cause = dnsChanged ? 'dns_change_correlated' : 'dns_resolution_failure';
            summary = dnsChanged
                ? `DNS changed and now no A or AAAA address resolves for ${host}. Removed records: ${entity.dns_changes.removed.map(record => record.type + ' ' + record.host + ' ' + record.value).join(', ') || 'none'}.`
                : `DNS did not resolve ${host} to an A or AAAA address; the web server could not be reached.`;
        } else if (server.state === 'SERVER_UNREACHABLE') {
            cause = dnsChanged ? 'dns_change_and_server_unreachable' : 'server_unreachable';
            summary = dnsChanged
                ? `DNS changed and the resolved server (${(server.addresses || []).join(', ')}) is now unreachable. Added: ${entity.dns_changes.added.length}; removed: ${entity.dns_changes.removed.length}. File changes were not checked because the server could not be reached.`
                : `The resolved server (${(server.addresses || []).join(', ')}) did not answer ICMP or TCP probes. File changes were not checked because the server could not be reached.`;
        } else if (agent && agent.reachable && agent.body && agent.body.file_audit && agent.body.file_audit.changes && agent.body.file_audit.changes.length) {
            cause = 'verified_file_change';
            summary = `The server is reachable, but WordPress reported file changes: ${agent.body.file_audit.changes.map(change => change.path + ' (' + change.change + ')').join(', ')}.`;
        } else if (agent && agent.reachable) {
            cause = 'wordpress_runtime_failure';
            summary = dnsChanged
                ? `The server is reachable and the Sentinel agent responded, but the public HTTP endpoint returned ${http.http_code}. DNS also changed since the last scan; review the DNS diff before treating this as a file issue.`
                : `The server is reachable and the Sentinel agent responded, but the public HTTP endpoint returned ${http.http_code}. This is an application/web-server response, not proof of a file change.`;
        } else {
            cause = http.http_code >= 500 ? 'http_server_error' : 'http_request_failure';
            summary = `The server was reachable, but the public HTTP endpoint returned ${http.http_code} (${http.error_message}). No file change was confirmed.`;
        }
    }

    return {
        ...http,
        server_reachability: server,
        agent_health: agent,
        diagnostic: { cause, summary, checked_at: new Date().toISOString() }
    };
}

function updateUptime(entity, result) {
    if (!Array.isArray(entity.uptime_history)) entity.uptime_history = Array(19).fill(1);
    entity.uptime_history.push(result.status === 'ONLINE' ? 1 : 0);
    if (entity.uptime_history.length > 20) entity.uptime_history.shift();
    const upPings = entity.uptime_history.filter(x => x === 1).length;
    entity.uptime_pct = Math.round((upPings / entity.uptime_history.length) * 100);
}

function addIncident(entity, result, previousStatus) {
    if (result.status === 'OFFLINE' && previousStatus === 'ONLINE') {
        const outageIncident = {
            id: Date.now() + Math.floor(Math.random() * 1000),
            site_url: entity.url || `https://${entity.domain}`,
            domain: entity.domain,
            site_name: entity.name,
            event: `OUTAGE_DETECTED_${result.diagnostic.cause.toUpperCase()}`,
            details: {
                http_code: result.http_code,
                error: result.error_message,
                target: entity.url || `https://${entity.domain}`,
                cause: result.diagnostic.cause,
                diagnostic: result.diagnostic.summary,
                server_reachability: result.server_reachability,
                agent_health: result.agent_health || 'Not queried'
            },
            type: 'OUTAGE',
            timestamp: new Date().toISOString()
        };
        securityEvents.unshift(outageIncident);
        console.log(`🚨 [OUTAGE DETECTED] ${entity.name} - ${result.diagnostic.summary}`);
    } else if (result.status === 'ONLINE' && previousStatus === 'OFFLINE') {
        securityEvents.unshift({
            id: Date.now() + Math.floor(Math.random() * 1000),
            site_url: entity.url || `https://${entity.domain}`,
            domain: entity.domain,
            site_name: entity.name,
            event: 'SERVICE_RESTORED',
            details: {
                http_code: result.http_code,
                status: 'Service fully operational',
                response_time: `${result.latency}ms`,
                previous_cause: entity.diagnostic ? entity.diagnostic.cause : 'unknown'
            },
            type: 'RECOVERY',
            timestamp: new Date().toISOString()
        });
        console.log(`✅ [SERVICE RESTORED] ${entity.name} is back ONLINE`);
    }
}

async function runFleetHealthChecks() {
    const entities = [...Object.values(monitoredSites), ...Object.values(standaloneDomains)];
    await Promise.all(entities.map(async entity => {
        const result = await checkEntityHealth(entity);
        const previousStatus = entity.status || 'ONLINE';
        entity.status = result.status;
        entity.http_code = result.http_code;
        entity.error_message = result.error_message;
        entity.latency = result.latency;
        entity.server_reachability = result.server_reachability;
        entity.diagnostic = result.diagnostic;
        entity.last_check_at = new Date().toISOString();
        if (result.agent_health) entity.agent_health = result.agent_health;
        if (result.agent_health && result.agent_health.body && result.agent_health.body.file_audit) {
            entity.file_audit = result.agent_health.body.file_audit;
        }
        updateUptime(entity, result);
        addIncident(entity, result, previousStatus);
    }));
    saveDatabase();
}

// Start active server and HTTP pings immediately.
runFleetHealthChecks().catch(error => console.error('[health-check]', error.message));
setInterval(() => runFleetHealthChecks().catch(error => console.error('[health-check]', error.message)), 15000);

// 3. UNIVERSAL DYNAMIC DNS SCANNER
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

async function scanKnownDNSZone(domain) {
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

// Node's legacy per-type probes miss valid records such as CAA, SOA, DS,
// DNSKEY, NAPTR, TLSA, HTTPS and SVCB. Resolve the apex and common discovered
// names with resolveAny plus explicit record types. DNS has no safe universal
// zone-enumeration API, so the result is labelled as resolver-visible rather
// than pretending that an empty probe means the zone is empty.
const EXTENDED_DNS_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'SRV', 'NAPTR', 'DS', 'DNSKEY', 'TLSA', 'HTTPS', 'SVCB', 'PTR'];

function stringifyDnsValue(value) {
    if (value === undefined || value === null) return '-';
    if (Array.isArray(value)) return value.join('');
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
}

function mapDnsRecord(record, host, typeOverride) {
    const type = typeOverride || record.type || 'UNKNOWN';
    let value = '-';
    let priority = '-';
    if (type === 'A' || type === 'AAAA') value = record.address || record.value || record;
    else if (type === 'CNAME' || type === 'NS' || type === 'PTR') value = record.value || record;
    else if (type === 'MX') { value = record.exchange; priority = record.priority; }
    else if (type === 'TXT') value = stringifyDnsValue(record.entries || record.value);
    else if (type === 'SOA') value = `${record.nsname} | ${record.hostmaster} | serial ${record.serial}`;
    else if (type === 'CAA') { value = `${record.tag} ${record.value}`; priority = record.flags; }
    else if (type === 'SRV') { value = `${record.name}:${record.port} (weight ${record.weight})`; priority = record.priority; }
    else if (type === 'NAPTR') value = `${record.order} ${record.preference} "${record.flags}" "${record.service}" "${record.regexp}" ${record.replacement}`;
    else if (type === 'DS') value = `${record.keyTag} ${record.algorithm} ${record.digestType} ${record.digest}`;
    else if (type === 'DNSKEY') value = `${record.flags} ${record.protocol} ${record.algorithm} ${record.key}`;
    else if (type === 'TLSA') value = `${record.certUsage} ${record.selector} ${record.matchingType} ${record.certificate}`;
    else if (type === 'HTTPS' || type === 'SVCB') value = `${record.priority} ${record.name} ${stringifyDnsValue(record.alpn || record.params || record.value)}`;
    else value = stringifyDnsValue(record.value || record);

    return {
        type,
        host,
        value: stringifyDnsValue(value),
        priority: priority === undefined ? '-' : priority,
        ttl: record.ttl || null
    };
}

async function resolveDnsName(name, includeExtendedTypes) {
    const records = [];
    const seen = new Set();
    const push = record => {
        const key = `${record.type}|${record.host}|${record.value}|${record.priority}`;
        if (!seen.has(key)) {
            seen.add(key);
            records.push(record);
        }
    };

    try {
        const anyRecords = await Promise.race([
            dns.resolveAny(name),
            new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 2500))
        ]);
        for (const record of anyRecords || []) push(mapDnsRecord(record, name, record.type));
    } catch (e) {}

    const typesToProbe = includeExtendedTypes
        ? EXTENDED_DNS_TYPES
        : ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'CAA', 'HTTPS', 'SVCB'];
    await Promise.all(typesToProbe.map(async type => {
        try {
            const values = await Promise.race([
                dns.resolve(name, type),
                new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 1800))
            ]);
            for (const value of values || []) push(mapDnsRecord(value, name, type));
        } catch (e) {}
    }));

    return records;
}

async function scanFullDNSZone(domain) {
    const host = normalizeHost(domain);
    const candidateNames = Array.from(new Set([
        host,
        ...COMPREHENSIVE_HOST_DICTIONARY.map(label => `${label}.${host}`)
    ]));
    const chunks = await Promise.all(candidateNames.map((name, index) => resolveDnsName(name, index === 0)));
    const records = chunks.flat();
    const seen = new Set();
    const uniqueRecords = records.filter(record => {
        const key = `${record.type}|${record.host}|${record.value}|${record.priority}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });

    return uniqueRecords.length ? uniqueRecords : [{
        type: 'A',
        host: '@ (Apex)',
        value: 'No resolver-visible records returned',
        priority: '-'
    }];
}

function canonicalDnsRecord(record) {
    return `${record.type}|${record.host}|${record.value}|${record.priority}`;
}

function compareDnsRecords(previous, current) {
    const oldSet = new Set((previous || []).map(canonicalDnsRecord));
    const newSet = new Set((current || []).map(canonicalDnsRecord));
    return {
        added: (current || []).filter(record => !oldSet.has(canonicalDnsRecord(record))),
        removed: (previous || []).filter(record => !newSet.has(canonicalDnsRecord(record)))
    };
}

async function refreshEntityDNS(entity) {
    const previous = Array.isArray(entity.dns_records) ? entity.dns_records : [];
    const current = await scanFullDNSZone(entity.domain || entity.url);
    const changes = entity.dns_scanner_version === 2
        ? compareDnsRecords(previous, current)
        : { added: [], removed: [] };
    entity.dns_records = current;
    entity.dns_scanner_version = 2;
    entity.dns_last_checked = new Date().toISOString();
    entity.dns_scan = {
        coverage: 'Apex plus resolver-visible common/discovered hostnames; DNS does not provide safe universal zone enumeration',
        record_count: current.length
    };
    entity.dns_changes = changes;

    // An empty legacy snapshot is not treated as a deletion storm on first scan.
    if (previous.length > 0 && (changes.added.length || changes.removed.length)) {
        securityEvents.unshift({
            id: Date.now() + Math.floor(Math.random() * 1000),
            site_url: entity.url || `https://${entity.domain}`,
            domain: entity.domain,
            site_name: entity.name,
            event: 'DNS_CHANGE_DETECTED',
            details: {
                added: changes.added,
                removed: changes.removed,
                diagnostic: `${changes.added.length} record(s) added and ${changes.removed.length} record(s) removed since the last DNS scan.`,
                dns_last_checked: entity.dns_last_checked
            },
            type: 'DNS',
            timestamp: new Date().toISOString()
        });
    }
}

async function runFleetDNSChecks() {
    const entities = [...Object.values(monitoredSites), ...Object.values(standaloneDomains)];
    await Promise.all(entities.map(entity => refreshEntityDNS(entity).catch(error => {
        entity.dns_scan_error = normalizeErrorMessage(error);
    })));
    lastDnsScanAt = Date.now();
    saveDatabase();
}

// 4. LIVE SSL INSPECTOR
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

// Always refresh the DNS snapshot on startup so older incomplete snapshots are
// upgraded. Repeat less often than the HTTP ping because DNS answers are
// cached and a full multi-type scan is intentionally more expensive.
runFleetDNSChecks().catch(error => console.error('[dns-scan]', error.message));
setInterval(() => runFleetDNSChecks().catch(error => console.error('[dns-scan]', error.message)), DNS_SCAN_INTERVAL_MS);

// 5. REST APIS
app.get('/', (req, res) => {
    // The uploaded dashboard is HTML even when it is named index.php.
    // Support both names so deployment does not fail on a harmless extension mismatch.
    const dashboardFile = fs.existsSync(path.join(__dirname, 'index.html')) ? 'index.html' : 'index.php';
    res.sendFile(path.join(__dirname, dashboardFile));
});

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
        archived_events: archivedEvents,
        up_count: upCount,
        down_count: downCount,
        fleet_health: Math.max(0, 100 - (downCount * 25))
    });
});

// Acknowledging an alert removes it from the active stream without deleting it.
// The complete record, including the original evidence, is retained in the archive.
app.post('/api/events/:id/acknowledge', (req, res) => {
    const id = String(req.params.id);
    const collections = [
        { name: 'events', list: securityEvents },
        { name: 'audit_logs', list: auditLogs }
    ];
    let found = null;
    let source = null;
    for (const collection of collections) {
        const index = collection.list.findIndex(event => String(event.id) === id);
        if (index !== -1) {
            found = collection.list.splice(index, 1)[0];
            source = collection.name;
            break;
        }
    }
    if (!found) return res.status(404).json({ success: false, error: 'Active event not found' });

    found.acknowledged_at = new Date().toISOString();
    found.acknowledged_by = req.body && req.body.acknowledged_by ? String(req.body.acknowledged_by).slice(0, 120) : 'dashboard';
    found.original_collection = source;
    archivedEvents.unshift(found);
    saveDatabase();
    res.json({ success: true, event: found });
});

app.post('/api/events/:id/restore', (req, res) => {
    const id = String(req.params.id);
    const index = archivedEvents.findIndex(event => String(event.id) === id);
    if (index === -1) return res.status(404).json({ success: false, error: 'Archived event not found' });

    const restored = archivedEvents.splice(index, 1)[0];
    delete restored.acknowledged_at;
    delete restored.acknowledged_by;
    const target = restored.original_collection === 'audit_logs' ? auditLogs : securityEvents;
    target.unshift(restored);
    saveDatabase();
    res.json({ success: true, event: restored });
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
        file_audit: data.file_audit || monitoredSites[data.site_url]?.file_audit || null,
        agent_version: data.agent_version || monitoredSites[data.site_url]?.agent_version || null,
        backups: monitoredSites[data.site_url]?.backups || [
            { id: 1, filename: 'db-backup-latest.sql', location: '/wp-content/flotek-backups/db-backup-latest.sql', filesize: '48.2 MB', date: '2026-03-01' }
        ],
        health_score: Math.max(30, 100 - (data.pending_updates || 0) * 3),
        status: monitoredSites[data.site_url]?.status || 'ONLINE',
        http_code: monitoredSites[data.site_url]?.http_code || 200,
        error_message: monitoredSites[data.site_url]?.error_message || '200 OK',
        latency: monitoredSites[data.site_url]?.latency || 40,
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

// UNIFIED PERMANENT DELETION ROUTE (Websites & Domains)
app.post('/api/delete-domain', (req, res) => {
    const { domain_name } = req.body;
    if (domain_name) {
        const clean = normalizeHost(domain_name);

        // Delete from standalone domains
        delete standaloneDomains[clean];
        delete standaloneDomains[domain_name];

        // Delete from monitored websites
        delete monitoredSites[clean];
        delete monitoredSites[domain_name];
        for (const key in monitoredSites) {
            if (normalizeHost(key) === clean) {
                delete monitoredSites[key];
            }
        }

        // Add to permanent deletion blocklist
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
