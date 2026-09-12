const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static('public'));

const PORT = 3000;
const ALERT_EMAIL = 'brian.vandenbergh@flotek.io';
const SHARED_SECRET = 'flotek-super-secret-key-2026';

let monitoredSites = {};
let securityEvents = [];

// ===================================================
// AUTO-DISCOVERY ENDPOINT
// ===================================================
app.post('/api/register', async (req, res) => {
    const authHeader = req.headers['x-hub-secret'];
    if (authHeader !== SHARED_SECRET) return res.status(403).json({ error: 'Unauthorized' });

    const { site_url, site_name, wp_version, php_version, plugins, admin_email } = req.body;
    
    monitoredSites[site_url] = {
        name: site_name || site_url,
        url: site_url,
        wp_version: wp_version || '6.7',
        php_version: php_version || '8.2',
        plugins: plugins || [],
        admin_email: admin_email || '',
        status: 'ONLINE',
        latency: Math.floor(Math.random() * 30 + 60), // ms
        last_seen: new Date().toISOString()
    };

    console.log(`✨ [AUTO-DISCOVERY] Registered: ${site_url} with ${plugins ? plugins.length : 0} plugins.`);
    res.json({ success: true, message: 'Connected' });
});

// ===================================================
// SECURITY EVENT ENDPOINT
// ===================================================
app.post('/api/event', async (req, res) => {
    const authHeader = req.headers['x-hub-secret'];
    if (authHeader !== SHARED_SECRET) return res.status(403).json({ error: 'Unauthorized' });

    const { site_url, site_name, event, details, timestamp } = req.body;

    const eventRecord = {
        id: Date.now(),
        site_url,
        site_name,
        event,
        details,
        timestamp: timestamp || new Date().toISOString()
    };

    securityEvents.unshift(eventRecord);
    if (securityEvents.length > 50) securityEvents.pop();

    console.log(`🚨 [ALERT] ${event} on ${site_name}`);
    res.json({ success: true });
});

// ===================================================
// DASHBOARD DATA ENDPOINT
// ===================================================
app.get('/api/dashboard-data', (req, res) => {
    res.json({
        sites: Object.values(monitoredSites),
        events: securityEvents,
        alert_email: ALERT_EMAIL
    });
});

// Real Latency & Uptime Pinger (every 30s)
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
    console.log(`🛡️ Flotek Sentinel Enterprise running at http://localhost:${PORT}`);
});