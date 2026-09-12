const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

// Serve index.html directly from current folder
app.use(express.static(__dirname));

const PORT = process.env.PORT || 3000;
const ALERT_EMAIL = 'brian.vandenbergh@flotek.io';
const SHARED_SECRET = 'flotek-super-secret-key-2026';

let monitoredSites = {};
let securityEvents = [];

// Explicit root route so your dashboard always loads
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// AUTO-DISCOVERY ENDPOINT
app.post('/api/register', (req, res) => {
    const authHeader = req.headers['x-hub-secret'];
    if (authHeader !== SHARED_SECRET) return res.status(403).json({ error: 'Unauthorized' });

    const { site_url, site_name, wp_version, php_version, plugins, security_engine } = req.body;
    
    monitoredSites[site_url] = {
        name: site_name || site_url,
        url: site_url,
        wp_version: wp_version || '6.7',
        php_version: php_version || '8.2',
        plugins: plugins || [],
        security_engine: security_engine || 'Native Guard',
        status: 'ONLINE',
        latency: Math.floor(Math.random() * 30 + 55),
        last_seen: new Date().toISOString()
    };

    console.log(`✨ [AUTO-DISCOVERY] Registered: ${site_url}`);
    res.json({ success: true });
});

// SECURITY EVENT ENDPOINT
app.post('/api/event', (req, res) => {
    const authHeader = req.headers['x-hub-secret'];
    if (authHeader !== SHARED_SECRET) return res.status(403).json({ error: 'Unauthorized' });

    const { site_url, site_name, event, details, timestamp } = req.body;

    securityEvents.unshift({
        id: Date.now(),
        site_url,
        site_name,
        event,
        details,
        timestamp: timestamp || new Date().toISOString()
    });

    if (securityEvents.length > 50) securityEvents.pop();
    res.json({ success: true });
});

// DASHBOARD DATA ENDPOINT
app.get('/api/dashboard-data', (req, res) => {
    res.json({
        sites: Object.values(monitoredSites),
        events: securityEvents,
        alert_email: ALERT_EMAIL
    });
});

app.listen(PORT, () => {
    console.log(`🛡️ Flotek Sentinel running on port ${PORT}`);
});
