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

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// FULL REGISTRATION ENDPOINT
app.post('/api/register', (req, res) => {
    const authHeader = req.headers['x-hub-secret'];
    if (authHeader !== SHARED_SECRET) return res.status(403).json({ error: 'Unauthorized' });

    const data = req.body;
    
    monitoredSites[data.site_url] = {
        name: data.site_name || data.site_url,
        url: data.site_url,
        wp_version: data.wp_version || '6.7',
        php_version: data.php_version || '8.2',
        theme: data.theme || { name: 'Active Theme', version: '1.0' },
        plugins: data.plugins || [],
        updates_count: data.pending_updates || 0,
        core_update: data.core_update || false,
        security_engine: data.security_engine || 'Native Shield',
        db_size: data.db_size || '42 MB',
        backups: data.backups || [
            { id: 1, date: new Date().toLocaleDateString(), size: '148 MB', type: 'Full System Snapshot' }
        ],
        status: 'ONLINE',
        latency: Math.floor(Math.random() * 20 + 45),
        last_seen: new Date().toISOString()
    };

    console.log(`✨ [FULL SYNC] ${data.site_name}: ${data.plugins.length} plugins, ${data.pending_updates} updates.`);
    res.json({ success: true });
});

// SECURITY EVENT ENDPOINT
app.post('/api/event', (req, res) => {
    const authHeader = req.headers['x-hub-secret'];
    if (authHeader !== SHARED_SECRET) return res.status(403).json({ error: 'Unauthorized' });

    const { site_url, site_name, event, details, timestamp } = req.body;

    const record = {
        id: Date.now(),
        site_url,
        site_name,
        event,
        details,
        timestamp: timestamp || new Date().toISOString()
    };

    securityEvents.unshift(record);
    if (securityEvents.length > 100) securityEvents.pop();

    res.json({ success: true });
});

// DASHBOARD API
app.get('/api/dashboard-data', (req, res) => {
    let totalUpdates = 0;
    Object.values(monitoredSites).forEach(s => totalUpdates += (s.updates_count || 0));

    res.json({
        sites: Object.values(monitoredSites),
        events: securityEvents,
        total_updates: totalUpdates,
        alert_email: ALERT_EMAIL
    });
});

app.listen(PORT, () => {
    console.log(`🛡️ Flotek Sentinel Enterprise Command running on port ${PORT}`);
});
