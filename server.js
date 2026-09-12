const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const path = require('path');
const dns = require('dns').promises;

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
// EMAIL TRANSPORTER CONFIGURATION (Configure SMTP or Brevo/Sendgrid)
// =========================================================================
// Tip: To send real emails, set your SMTP host & password here or use Brevo/M365
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.office365.com',
    port: 587,
    secure: false,
    auth: {
        user: process.env.SMTP_USER || 'alerts@flotek.io',
        pass: process.env.SMTP_PASS || 'your-password'
    }
});

async function sendEmailAlert(subject, body) {
    try {
        console.log(`[EMAIL QUEUED] ${subject} -> ${ALERT_EMAIL}`);
        if (process.env.SMTP_USER && process.env.SMTP_PASS) {
            await transporter.sendMail({
                from: '"Flotek Sentinel" <alerts@flotek.io>',
                to: ALERT_EMAIL,
                subject: `[Flotek Sentinel] ${subject}`,
                html: body
            });
        }
    } catch (e) {
        console.error('[EMAIL ERROR]', e.message);
    }
}

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

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
        users: data.users || [],
        updates_count: data.pending_updates || 0,
        security_engine: data.security_engine || 'Multi-Layer Defense',
        performance: data.performance || { queries: 28, load_time: '0.28s', memory: '18 MB' },
        ssl: { valid: true, issuer: "Cloudflare / Let's Encrypt", days_left: 84 },
        dns: { a_records: ['104.21.48.1'], ns_records: ['ns1.flotek.io'], status: 'Propagated' },
        backups: [
            { id: 1, filename: 'db-backup-latest.sql', location: '/wp-content/flotek-backups/db-backup-latest.sql', filesize: '48 MB', date: new Date().toLocaleDateString() }
        ],
        health_score: 95,
        status: 'ONLINE',
        latency: Math.floor(Math.random() * 20 + 45),
        last_seen: new Date().toISOString()
    };

    console.log(`✨ [SYNC] ${data.site_name}: ${data.plugins.length} plugins, ${data.users.length} users reported.`);
    res.json({ success: true });
});

// PROXY: TRIGGER REMOTE PLUGIN UPDATE ON WORDPRESS SITE
app.post('/api/trigger-update', async (req, res) => {
    const { site_url } = req.body;
    try {
        const wpEndpoint = `${site_url}/wp-json/flotek/v1/update-plugins`;
        const response = await fetch(wpEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Hub-Secret': SHARED_SECRET
            }
        });
        const result = await response.json();
        res.json(result);
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// PROXY: TRIGGER REMOTE FTP BACKUP CREATION ON WORDPRESS SITE
app.post('/api/trigger-backup', async (req, res) => {
    const { site_url } = req.body;
    try {
        const wpEndpoint = `${site_url}/wp-json/flotek/v1/create-backup`;
        const response = await fetch(wpEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Hub-Secret': SHARED_SECRET
            }
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
        }
        res.json(result);
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// SECURITY & AUDIT EVENT RECEIVER
app.post('/api/event', (req, res) => {
    const authHeader = req.headers['x-hub-secret'];
    if (authHeader !== SHARED_SECRET) return res.status(403).json({ error: 'Unauthorized' });

    const { site_url, site_name, event, details, type, timestamp } = req.body;
    const record = { id: Date.now(), site_url, site_name, event, details, type: type || 'SECURITY', timestamp: timestamp || new Date().toISOString() };

    if (type === 'AUDIT') {
        auditLogs.unshift(record);
    } else {
        securityEvents.unshift(record);
        sendEmailAlert(`🚨 Security Alert: ${event} on ${site_name}`, `<p><strong>${event}</strong> on ${site_name} (${site_url})</p><pre>${JSON.stringify(details, null, 2)}</pre>`);
    }

    res.json({ success: true });
});

app.get('/api/dashboard-data', (req, res) => {
    let totalUpdates = 0;
    Object.values(monitoredSites).forEach(s => totalUpdates += (s.updates_count || 0));

    res.json({
        sites: Object.values(monitoredSites),
        events: securityEvents,
        audit_logs: auditLogs,
        total_updates: totalUpdates,
        fleet_health: 98,
        alert_email: ALERT_EMAIL
    });
});

app.listen(PORT, () => console.log(`🛡️ Flotek Enterprise Command Hub running on port ${PORT}`));
