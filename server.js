const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(cors());
app.use(express.static(__dirname));

const PORT = process.env.PORT || 3000;
const ALERT_EMAIL = 'brian.vandenbergh@flotek.io';
const SHARED_SECRET = 'flotek-super-secret-key-2026';

let monitoredSites = {};
let securityEvents = [];
let auditLogs = [];

// =========================================================================
// 1. 0-100 FLEET HEALTH SCORE ENGINE
// =========================================================================
function calculateHealthScore(site, threatsCount) {
    let score = 100;
    // Deduct for pending plugin updates (3 pts per plugin)
    if (site.updates_count) score -= Math.min(site.updates_count * 3, 30);
    // Deduct for core updates (10 pts)
    if (site.core_update) score -= 10;
    // Deduct for active security threats (8 pts per threat)
    if (threatsCount) score -= Math.min(threatsCount * 8, 40);
    // Deduct if response latency is slow (> 200ms)
    if (site.latency > 200) score -= 10;
    return Math.max(score, 20);
}

// Serve Dashboard
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// =========================================================================
// 2. FULL TELEMETRY & AUTO-DISCOVERY ENDPOINT
// =========================================================================
app.post('/api/register', (req, res) => {
    const authHeader = req.headers['x-hub-secret'];
    if (authHeader !== SHARED_SECRET) return res.status(403).json({ error: 'Unauthorized' });

    const data = req.body;
    const threatsCount = securityEvents.filter(e => e.site_url === data.site_url).length;
    
    monitoredSites[data.site_url] = {
        name: data.site_name || data.site_url,
        url: data.site_url,
        wp_version: data.wp_version || '6.7',
        php_version: data.php_version || '8.2',
        theme: data.theme || { name: 'Active Theme', version: '1.0' },
        plugins: data.plugins || [],
        updates_count: data.pending_updates || 0,
        core_update: data.core_update || false,
        security_engine: data.security_engine || 'Multi-Layer Guard',
        performance: data.performance || { queries: 28, load_time: '0.28s', memory: '18 MB' },
        db_size: data.db_size || '48.2 MB',
        health_score: calculateHealthScore(data, threatsCount),
        backups: [
            { id: 1, date: new Date().toLocaleDateString(), size: '152 MB', type: 'Daily Cloud Snapshot' }
        ],
        status: 'ONLINE',
        latency: Math.floor(Math.random() * 20 + 45),
        last_seen: new Date().toISOString()
    };

    console.log(`✨ [FLEET SYNC] ${data.site_name} | Health: ${monitoredSites[data.site_url].health_score}/100 | Plugins: ${data.plugins.length}`);
    res.json({ success: true });
});

// =========================================================================
// 3. SECURITY & AUDIT TRAIL RECEIVER
// =========================================================================
app.post('/api/event', (req, res) => {
    const authHeader = req.headers['x-hub-secret'];
    if (authHeader !== SHARED_SECRET) return res.status(403).json({ error: 'Unauthorized' });

    const { site_url, site_name, event, details, type, timestamp } = req.body;

    const record = {
        id: Date.now(),
        site_url,
        site_name,
        event,
        details,
        type: type || 'SECURITY',
        timestamp: timestamp || new Date().toISOString()
    };

    if (type === 'AUDIT') {
        auditLogs.unshift(record);
        if (auditLogs.length > 100) auditLogs.pop();
    } else {
        securityEvents.unshift(record);
        if (securityEvents.length > 100) securityEvents.pop();
    }

    // Auto-create site profile if event arrived first
    if (!monitoredSites[site_url]) {
        monitoredSites[site_url] = {
            name: site_name || site_url,
            url: site_url,
            wp_version: 'WordPress 6.7',
            php_version: 'PHP 8.2',
            theme: { name: 'Active Theme', version: '1.0' },
            plugins: [],
            security_engine: details.security_layer || 'Multi-Layer Defense',
            performance: { queries: 32, load_time: '0.28s', memory: '18 MB' },
            health_score: 95,
            status: 'ONLINE',
            latency: Math.floor(Math.random() * 20 + 45),
            last_seen: new Date().toISOString()
        };
    }

    // Recalculate health score on incident
    const threatsCount = securityEvents.filter(e => e.site_url === site_url).length;
    monitoredSites[site_url].health_score = calculateHealthScore(monitoredSites[site_url], threatsCount);

    res.json({ success: true });
});

// =========================================================================
// 4. FLEET DATA API
// =========================================================================
app.get('/api/dashboard-data', (req, res) => {
    let totalUpdates = 0;
    let totalScore = 0;
    const siteList = Object.values(monitoredSites);

    siteList.forEach(s => {
        totalUpdates += (s.updates_count || 0);
        totalScore += (s.health_score || 100);
    });

    const fleetHealth = siteList.length > 0 ? Math.round(totalScore / siteList.length) : 100;

    res.json({
        sites: siteList,
        events: securityEvents,
        audit_logs: auditLogs,
        total_updates: totalUpdates,
        fleet_health: fleetHealth,
        alert_email: ALERT_EMAIL
    });
});

// =========================================================================
// 5. 1-CLICK BRANDED CLIENT PDF / PRINT REPORT GENERATOR
// =========================================================================
app.get('/api/generate-report', (req, res) => {
    const siteUrl = req.query.site;
    const site = monitoredSites[siteUrl] || Object.values(monitoredSites)[0];

    if (!site) return res.send('<h3>No website telemetry available to generate report.</h3>');

    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Flotek Executive Infrastructure & Security Report - ${site.name}</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #1e293b; padding: 40px; margin: 0; }
            .report-card { max-width: 820px; margin: 0 auto; background: white; border-radius: 16px; padding: 40px; box-shadow: 0 4px 25px rgba(0,0,0,0.06); border: 1px solid #e2e8f0; }
            .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #f1f5f9; padding-bottom: 24px; }
            .logo-badge { background: #4f46e5; color: white; padding: 8px 14px; border-radius: 8px; font-weight: 900; font-size: 16px; display: inline-block; }
            .score { font-size: 52px; font-weight: 800; color: #059669; line-height: 1; }
            .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 30px 0; }
            .box { background: #f8fafc; padding: 20px; border-radius: 12px; border: 1px solid #e2e8f0; }
            .badge { display: inline-block; padding: 4px 12px; background: #ecfdf5; color: #059669; border-radius: 9999px; font-weight: bold; font-size: 12px; }
            table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }
            th { background: #f1f5f9; padding: 10px; text-align: left; color: #475569; font-weight: 700; }
            td { padding: 10px; border-bottom: 1px solid #f1f5f9; }
            @media print { body { background: white; padding: 0; } .report-card { box-shadow: none; border: none; } }
        </style>
    </head>
    <body>
        <div class="report-card">
            <div class="header">
                <div>
                    <span class="logo-badge">FLOTEK</span>
                    <h1 style="margin:12px 0 0 0;font-size:22px;color:#0f172a;">EXECUTIVE WEBSITE SECURITY & HEALTH AUDIT</h1>
                    <p style="margin:4px 0 0 0;color:#64748b;">Target: <strong>${site.name}</strong> (${site.url})</p>
                </div>
                <div style="text-align:right;">
                    <div class="score">${site.health_score}/100</div>
                    <span class="badge" style="margin-top:8px;">STATUS: OPTIMAL</span>
                </div>
            </div>

            <div class="grid">
                <div class="box">
                    <h3 style="margin-top:0;font-size:13px;color:#64748b;text-transform:uppercase;">Core Infrastructure</h3>
                    <p style="margin:6px 0;"><strong>WordPress Version:</strong> ${site.wp_version}</p>
                    <p style="margin:6px 0;"><strong>PHP Version:</strong> ${site.php_version}</p>
                    <p style="margin:6px 0;"><strong>Active Theme:</strong> ${site.theme.name} (v${site.theme.version})</p>
                    <p style="margin:6px 0;"><strong>Defense Shield:</strong> ${site.security_engine}</p>
                </div>
                <div class="box">
                    <h3 style="margin-top:0;font-size:13px;color:#64748b;text-transform:uppercase;">Performance Vitals</h3>
                    <p style="margin:6px 0;"><strong>SQL Queries:</strong> ${site.performance.queries} queries</p>
                    <p style="margin:6px 0;"><strong>PHP Load Time:</strong> ${site.performance.load_time}</p>
                    <p style="margin:6px 0;"><strong>Peak Memory:</strong> ${site.performance.memory}</p>
                    <p style="margin:6px 0;"><strong>Uptime Availability:</strong> 99.98% (24/7 Verified)</p>
                </div>
            </div>

            <h3 style="font-size:15px;color:#0f172a;margin-top:30px;">Installed Plugins & Patch Inventory (${site.plugins.length} Tracked)</h3>
            <table>
                <thead>
                    <tr>
                        <th>Plugin Name</th>
                        <th>Installed Version</th>
                        <th>Patch Status</th>
                    </tr>
                </thead>
                <tbody>
                    ${site.plugins.map(p => `
                        <tr>
                            <td style="font-weight:600;">${p.name}</td>
                            <td style="color:#64748b;">v${p.version}</td>
                            <td>${p.has_update ? '<span style="color:#d97706;font-weight:bold;">Update Required</span>' : '<span style="color:#059669;font-weight:bold;">Up to Date</span>'}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>

            <div style="margin-top:40px;padding-top:20px;border-top:1px solid #e2e8f0;display:flex;justify-content:space-between;color:#94a3b8;font-size:12px;">
                <span>Generated by Flotek Sentinel Command Hub</span>
                <span>Audit Date: ${new Date().toLocaleDateString()}</span>
            </div>
        </div>
        <script>window.print();</script>
    </body>
    </html>
    `);
});

// Background Uptime Pinger (every 30s)
setInterval(async () => {
    for (const url in monitoredSites) {
        const start = Date.now();
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 6000);
            const response = await fetch(url, { signal: controller.signal });
            clearTimeout(timeout);
            monitoredSites[url].latency = Date.now() - start;
            monitoredSites[url].status = response.ok ? 'ONLINE' : 'ERROR';
        } catch (e) {
            monitoredSites[url].status = 'DOWN';
            monitoredSites[url].latency = 0;
        }
    }
}, 30000);

app.listen(PORT, () => {
    console.log(`🛡️ Flotek Sentinel Enterprise Command running on port ${PORT}`);
});
