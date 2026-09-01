import http.server
import socketserver
import urllib.parse
import json
import sqlite3
import hashlib
import datetime
import os
import base64
import secrets
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Configuration (Render dynamic port support)
PORT = int(os.environ.get("PORT", 8080))
DB_FILE = "auth.db"
ADMIN_PASSWORD = "admin"  # Modify if desired

# Setup database with HWID and Password support
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            password TEXT DEFAULT '',
            hwid TEXT DEFAULT '',
            expires_at TEXT,
            status TEXT,
            comment TEXT,
            created_at TEXT
        )
    """)
    
    # Safe migration for existing databases
    try:
        c.execute("ALTER TABLE keys ADD COLUMN password TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE keys ADD COLUMN hwid TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass

    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            key TEXT,
            status TEXT,
            message TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            expires_at TEXT
        )
    """)
    
    # Add default test account if table is empty
    c.execute("SELECT COUNT(*) FROM keys")
    if c.fetchone()[0] == 0:
        test_key = "BRMODS-USER-2026"
        test_pass = "123456"
        expiry = (datetime.datetime.now() + datetime.timedelta(days=30)).isoformat()
        created = datetime.datetime.now().isoformat()
        c.execute("INSERT INTO keys (key, password, hwid, expires_at, status, comment, created_at) VALUES (?, ?, '', ?, 'active', 'Default Test User', ?)", 
                  (test_key, test_pass, expiry, created))
        conn.commit()
        print(f"[+] Added default test user: {test_key} / Pass: {test_pass}")
        
    conn.close()

# Crypto keys
CLIENT_REQ_KEY = bytes.fromhex("d7659c1e7e7701e2286a351a15e0c0c14258d752a9f4c0f66713c5febc337c1c")
SERVER_MASTER_KEY = "d732f3d741bbeeca76596132ef8e34f30813d2e03605ff3bbb2a5d2d2b4af9a0"
RESPONSE_IV = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10])

# HTML Templates
LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BRMods Admin Login</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-gradient: linear-gradient(135deg, #0f0c20 0%, #15102a 50%, #06040a 100%);
            --glass-bg: rgba(255, 255, 255, 0.03);
            --glass-border: rgba(255, 255, 255, 0.05);
            --primary: #8b5cf6;
            --primary-glow: rgba(139, 92, 246, 0.4);
            --text: #f3f4f6;
            --text-muted: #9ca3af;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Outfit', sans-serif; }
        body {
            background: var(--bg-gradient);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            position: relative;
        }
        body::before, body::after {
            content: '';
            position: absolute;
            width: 300px;
            height: 300px;
            border-radius: 50%;
            background: var(--primary);
            filter: blur(120px);
            z-index: -1;
            opacity: 0.2;
        }
        body::before { top: 10%; left: 15%; }
        body::after { bottom: 10%; right: 15%; }
        .login-card {
            background: var(--glass-bg);
            border: 1px solid var(--glass-border);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-radius: 24px;
            padding: 40px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.5);
            text-align: center;
            animation: fadeIn 0.8s ease-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        h2 {
            font-size: 2rem;
            font-weight: 800;
            margin-bottom: 8px;
            background: linear-gradient(to right, #fff, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        p.subtitle { color: var(--text-muted); font-size: 0.9rem; margin-bottom: 32px; }
        .form-group { margin-bottom: 24px; text-align: left; }
        label {
            display: block;
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-muted);
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        input {
            width: 100%;
            padding: 14px 18px;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--glass-border);
            border-radius: 12px;
            color: #fff;
            font-size: 1rem;
            outline: none;
            transition: all 0.3s ease;
        }
        input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 12px var(--primary-glow);
        }
        button {
            width: 100%;
            padding: 14px;
            background: var(--primary);
            border: none;
            border-radius: 12px;
            color: #fff;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px var(--primary-glow);
            margin-top: 10px;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(139, 92, 246, 0.6);
        }
        .error-message {
            color: #ef4444;
            font-size: 0.9rem;
            margin-top: 16px;
            font-weight: 500;
        }
    </style>
</head>
<body>
    <div class="login-card">
        <h2>BRMods Admin</h2>
        <p class="subtitle">Enter password to manage users & HWID</p>
        <form method="POST" action="/admin/login">
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="••••••••" required>
            </div>
            <button type="submit">Log In</button>
        </form>
        {ERROR_PLACEHOLDER}
    </div>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BRMods Dashboard - HWID & User Management</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-gradient: linear-gradient(135deg, #09070f 0%, #110d1e 50%, #030206 100%);
            --glass-bg: rgba(255, 255, 255, 0.02);
            --glass-border: rgba(255, 255, 255, 0.05);
            --primary: #8b5cf6;
            --primary-glow: rgba(139, 92, 246, 0.3);
            --accent: #d946ef;
            --text: #f3f4f6;
            --text-muted: #9ca3af;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Outfit', sans-serif; }
        body {
            background: var(--bg-gradient);
            color: var(--text);
            min-height: 100vh;
            padding: 40px;
            overflow-x: hidden;
            position: relative;
        }
        body::before, body::after {
            content: '';
            position: absolute;
            width: 400px;
            height: 400px;
            border-radius: 50%;
            background: var(--primary);
            filter: blur(150px);
            z-index: -1;
            opacity: 0.15;
        }
        body::before { top: -10%; left: 5%; }
        body::after { bottom: -10%; right: 5%; }
        .container { max-width: 1300px; margin: 0 auto; }
        header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; }
        h1 {
            font-weight: 800;
            font-size: 2.2rem;
            background: linear-gradient(to right, #fff, #c084fc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .btn {
            padding: 10px 20px;
            border-radius: 10px;
            font-weight: 600;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border: none;
        }
        .btn-primary {
            background: var(--primary);
            color: #fff;
            box-shadow: 0 4px 15px var(--primary-glow);
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(139, 92, 246, 0.5);
        }
        .btn-logout {
            background: rgba(239, 68, 68, 0.1);
            color: var(--danger);
            border: 1px solid rgba(239, 68, 68, 0.2);
        }
        .btn-logout:hover { background: rgba(239, 68, 68, 0.2); }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 24px;
            margin-bottom: 40px;
        }
        .stat-card {
            background: var(--glass-bg);
            border: 1px solid var(--glass-border);
            border-radius: 20px;
            padding: 24px;
            backdrop-filter: blur(10px);
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .stat-label { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); font-weight: 600; }
        .stat-value { font-size: 2.2rem; font-weight: 800; color: #fff; }
        .main-grid { display: grid; grid-template-columns: 1fr; gap: 40px; }
        @media (min-width: 950px) { .main-grid { grid-template-columns: 1fr 2fr; } }
        .section-card {
            background: var(--glass-bg);
            border: 1px solid var(--glass-border);
            border-radius: 24px;
            padding: 32px;
            backdrop-filter: blur(15px);
            display: flex;
            flex-direction: column;
            gap: 24px;
        }
        .section-title { font-size: 1.4rem; font-weight: 700; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 16px; }
        .form-group { display: flex; flex-direction: column; gap: 8px; margin-bottom: 16px; }
        label { font-size: 0.85rem; font-weight: 600; color: var(--text-muted); }
        input, select {
            padding: 12px 16px;
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid var(--glass-border);
            border-radius: 10px;
            color: #fff;
            outline: none;
            transition: all 0.3s ease;
        }
        input:focus, select:focus {
            border-color: var(--primary);
            box-shadow: 0 0 10px var(--primary-glow);
        }
        .table-container { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th, td { padding: 16px; border-bottom: 1px solid rgba(255,255,255,0.04); font-size: 0.9rem; }
        th { font-weight: 600; color: var(--text-muted); text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }
        td { color: #fff; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 8px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .badge-active { background: rgba(16, 185, 129, 0.1); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.2); }
        .badge-revoked { background: rgba(239, 68, 68, 0.1); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.2); }
        .badge-expired { background: rgba(245, 158, 11, 0.1); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.2); }
        .action-btn { background: none; border: none; cursor: pointer; font-weight: 600; font-size: 0.85rem; padding: 4px 8px; border-radius: 6px; transition: all 0.2s ease; margin-right: 4px; }
        .action-btn-revoke { color: var(--warning); background: rgba(245, 158, 11, 0.1); }
        .action-btn-revoke:hover { background: rgba(245, 158, 11, 0.2); }
        .action-btn-reset { color: #38bdf8; background: rgba(56, 189, 248, 0.1); }
        .action-btn-reset:hover { background: rgba(56, 189, 248, 0.2); }
        .action-btn-delete { color: var(--danger); background: rgba(239, 68, 68, 0.1); }
        .action-btn-delete:hover { background: rgba(239, 68, 68, 0.2); }
        .code-key { font-family: monospace; background: rgba(255, 255, 255, 0.05); padding: 4px 8px; border-radius: 6px; font-size: 0.85rem; color: #d946ef; }
        .hwid-text { font-family: monospace; font-size: 0.75rem; color: var(--text-muted); max-width: 130px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-block; vertical-align: middle; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>BRMods Server Portal</h1>
                <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 4px;">Username, Password & HWID Management Dashboard</p>
            </div>
            <a href="/admin/logout" class="btn btn-logout">Logout</a>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-label">Active Accounts</span>
                <span class="stat-value">{ACTIVE_KEYS}</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Total Accounts</span>
                <span class="stat-value">{TOTAL_KEYS}</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Total Logins</span>
                <span class="stat-value">{TOTAL_LOGS}</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">System Mode</span>
                <span class="stat-value" style="color: var(--success); font-size: 1.8rem; font-weight: 700; margin-top: 10px;">SECURE + HWID</span>
            </div>
        </div>

        <div class="main-grid">
            <div class="section-card">
                <h2 class="section-title">Create User / Key</h2>
                <form method="POST" action="/admin/keys/add">
                    <div class="form-group">
                        <label for="username">Username / Key</label>
                        <input type="text" id="username" name="username" placeholder="e.g. user123 or leave empty for auto key">
                    </div>
                    <div class="form-group">
                        <label for="password">Password (Optional)</label>
                        <input type="text" id="password" name="password" placeholder="e.g. secretpass">
                    </div>
                    <div class="form-group">
                        <label for="hwid">Initial HWID (Optional)</label>
                        <input type="text" id="hwid" name="hwid" placeholder="Pre-bind hardware ID if needed">
                    </div>
                    <div class="form-group">
                        <label for="duration">Duration</label>
                        <select id="duration" name="duration">
                            <option value="1h">1 Hour</option>
                            <option value="1">1 Day</option>
                            <option value="7" selected>7 Days</option>
                            <option value="30">30 Days</option>
                            <option value="365">1 Year</option>
                            <option value="9999">Lifetime</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="comment">Description / Comment</label>
                        <input type="text" id="comment" name="comment" placeholder="e.g. Client Name / Device">
                    </div>
                    <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 10px;">Create Account</button>
                </form>
            </div>

            <div class="section-card">
                <h2 class="section-title">Manage Users & HWID</h2>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>User / Key & Pass</th>
                                <th>HWID Status</th>
                                <th>Comment</th>
                                <th>Expires At</th>
                                <th>Status</th>
                                <th style="text-align: right;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {KEYS_TABLE_ROWS}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="section-card" style="margin-top: 40px;">
            <h2 class="section-title">Authentication & HWID Logs</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>IP Address</th>
                            <th>User / Key Used</th>
                            <th>Status</th>
                            <th>Message</th>
                        </tr>
                    </thead>
                    <tbody>
                        {LOGS_TABLE_ROWS}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
"""

class KeyAuthHandler(http.server.BaseHTTPRequestHandler):
    
    def log_message(self, format, *args):
        pass

    def check_auth(self):
        cookie_header = self.headers.get('Cookie', '')
        if not cookie_header:
            return False
        
        tokens = re.findall(r'session=([a-f0-9]+)', cookie_header)
        if not tokens:
            return False
            
        token = tokens[0]
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT expires_at FROM sessions WHERE token = ?", (token,))
        row = c.fetchone()
        conn.close()
        
        if row:
            expiry = datetime.datetime.fromisoformat(row[0])
            if datetime.datetime.now() < expiry:
                return True
        return False

    def do_GET(self):
        if self.path == '/admin/login':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(LOGIN_HTML.replace('{ERROR_PLACEHOLDER}', '').encode('utf-8'))
            return
            
        if self.path == '/admin/logout':
            self.send_response(303)
            self.send_header('Location', '/admin/login')
            self.send_header('Set-Cookie', 'session=deleted; Path=/; Max-Age=0')
            self.end_headers()
            return
            
        if self.path == '/admin' or self.path == '/admin/':
            if not self.check_auth():
                self.send_response(303)
                self.send_header('Location', '/admin/login')
                self.end_headers()
                return
                
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            
            c.execute("SELECT COUNT(*) FROM keys WHERE status = 'active' AND expires_at > ?", (datetime.datetime.now().isoformat(),))
            active_keys = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) FROM keys")
            total_keys = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) FROM logs")
            total_logs = c.fetchone()[0]
            
            c.execute("SELECT key, password, hwid, expires_at, status, comment FROM keys ORDER BY created_at DESC")
            keys = c.fetchall()
            keys_rows = ""
            for key, password, hwid, expires, status, comment in keys:
                expiry_dt = datetime.datetime.fromisoformat(expires)
                is_expired = datetime.datetime.now() > expiry_dt
                
                status_str = status
                if status == 'active' and is_expired:
                    status_str = 'expired'
                
                badge_class = f"badge-{status_str}"
                
                if expiry_dt.year > 9000:
                    exp_disp = "Lifetime"
                else:
                    exp_disp = expiry_dt.strftime("%Y-%m-%d %H:%M")
                
                pass_display = f"<br><small style='color:var(--text-muted);'>Pass: {password}</small>" if password else ""
                hwid_display = f'<span class="hwid-text" title="{hwid}">{hwid}</span>' if hwid else '<span style="color:var(--text-muted); font-size:0.8rem;">Not Bound</span>'
                
                actions = ""
                if status == 'active':
                    actions += f'<form method="POST" action="/admin/keys/revoke" style="display:inline;"><input type="hidden" name="key" value="{key}"><button type="submit" class="action-btn action-btn-revoke">Revoke</button></form>'
                
                actions += f'<form method="POST" action="/admin/keys/resethwid" style="display:inline;"><input type="hidden" name="key" value="{key}"><button type="submit" class="action-btn action-btn-reset">Reset HWID</button></form>'
                actions += f'<form method="POST" action="/admin/keys/delete" style="display:inline;"><input type="hidden" name="key" value="{key}"><button type="submit" class="action-btn action-btn-delete">Delete</button></form>'
                
                keys_rows += f"""
                <tr>
                    <td><span class="code-key">{key}</span>{pass_display}</td>
                    <td>{hwid_display}</td>
                    <td>{comment}</td>
                    <td>{exp_disp}</td>
                    <td><span class="badge {badge_class}">{status_str}</span></td>
                    <td style="text-align: right;">{actions}</td>
                </tr>
                """
                
            c.execute("SELECT timestamp, ip, key, status, message FROM logs ORDER BY id DESC LIMIT 50")
            logs = c.fetchall()
            logs_rows = ""
            for ts, ip, key, log_status, msg in logs:
                ts_disp = datetime.datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M:%S")
                badge_class = "badge-active" if log_status == "success" else "badge-revoked"
                logs_rows += f"""
                <tr>
                    <td>{ts_disp}</td>
                    <td>{ip}</td>
                    <td><span class="code-key">{key}</span></td>
                    <td><span class="badge {badge_class}">{log_status}</span></td>
                    <td>{msg}</td>
                </tr>
                """
                
            conn.close()
            
            html = DASHBOARD_HTML.replace("{ACTIVE_KEYS}", str(active_keys))
            html = html.replace("{TOTAL_KEYS}", str(total_keys))
            html = html.replace("{TOTAL_LOGS}", str(total_logs))
            html = html.replace("{KEYS_TABLE_ROWS}", keys_rows)
            html = html.replace("{LOGS_TABLE_ROWS}", logs_rows)
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))
            return
            
        self.send_response(303)
        self.send_header('Location', '/admin')
        self.end_headers()

    def do_POST(self):
        if self.path == '/admin/login':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)
            pwd = params.get('password', [''])[0]
            
            if pwd == ADMIN_PASSWORD:
                token = secrets.token_hex(16)
                expiry = (datetime.datetime.now() + datetime.timedelta(hours=2)).isoformat()
                
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                c.execute("INSERT INTO sessions VALUES (?, ?)", (token, expiry))
                conn.commit()
                conn.close()
                
                self.send_response(303)
                self.send_header('Location', '/admin')
                self.send_header('Set-Cookie', f'session={token}; Path=/; HttpOnly; Max-Age=7200')
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                err_msg = '<div class="error-message">Invalid Admin Password!</div>'
                self.wfile.write(LOGIN_HTML.replace('{ERROR_PLACEHOLDER}', err_msg).encode('utf-8'))
            return
            
        if self.path == '/admin/keys/add':
            if not self.check_auth():
                self.send_response(303); self.send_header('Location', '/admin/login'); self.end_headers(); return
                
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)
            
            username = params.get('username', [''])[0].strip()
            password = params.get('password', [''])[0].strip()
            hwid = params.get('hwid', [''])[0].strip()
            duration_val = params.get('duration', ['7'])[0]
            comment = params.get('comment', [''])[0].strip()
            
            if username:
                new_key = username
            else:
                new_key = "BRMODS-" + secrets.token_hex(6).upper()
                
            now = datetime.datetime.now()
            if duration_val == "1h":
                expires = now + datetime.timedelta(hours=1)
            elif duration_val == "9999":
                expires = datetime.datetime(9999, 12, 31, 23, 59, 59)
            else:
                expires = now + datetime.timedelta(days=int(duration_val))
                
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            try:
                c.execute("INSERT INTO keys (key, password, hwid, expires_at, status, comment, created_at) VALUES (?, ?, ?, ?, 'active', ?, ?)", 
                          (new_key, password, hwid, expires.isoformat(), comment, now.isoformat()))
                conn.commit()
            except sqlite3.IntegrityError:
                pass
            conn.close()
            
            self.send_response(303); self.send_header('Location', '/admin'); self.end_headers(); return

        if self.path == '/admin/keys/revoke':
            if not self.check_auth():
                self.send_response(303); self.send_header('Location', '/admin/login'); self.end_headers(); return
                
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)
            target_key = params.get('key', [''])[0]
            
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("UPDATE keys SET status = 'revoked' WHERE key = ?", (target_key,))
            conn.commit()
            conn.close()
            
            self.send_response(303); self.send_header('Location', '/admin'); self.end_headers(); return

        if self.path == '/admin/keys/resethwid':
            if not self.check_auth():
                self.send_response(303); self.send_header('Location', '/admin/login'); self.end_headers(); return
                
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)
            target_key = params.get('key', [''])[0]
            
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("UPDATE keys SET hwid = '' WHERE key = ?", (target_key,))
            conn.commit()
            conn.close()
            
            self.send_response(303); self.send_header('Location', '/admin'); self.end_headers(); return

        if self.path == '/admin/keys/delete':
            if not self.check_auth():
                self.send_response(303); self.send_header('Location', '/admin/login'); self.end_headers(); return
                
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)
            target_key = params.get('key', [''])[0]
            
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("DELETE FROM keys WHERE key = ?", (target_key,))
            conn.commit()
            conn.close()
            
            self.send_response(303); self.send_header('Location', '/admin'); self.end_headers(); return

        # API endpoint for client login/verification with HWID and Username/Password support
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        params = urllib.parse.parse_qs(post_data)
        b64_iv = params.get('iv', [''])[0]
        b64_payload = params.get('payload', [''])[0]
        
        if not b64_iv or not b64_payload:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing parameters.")
            return
            
        try:
            iv = base64.b64decode(b64_iv)
            payload = base64.b64decode(b64_payload)
            cipher = AES.new(CLIENT_REQ_KEY, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(payload), AES.block_size)
            
            dec_str = decrypted.decode('utf-8', errors='ignore')
            req_json = json.loads(dec_str)
            
            client_key = req_json.get('key', '').strip() or req_json.get('username', '').strip()
            client_pass = req_json.get('password', '').strip()
            client_hwid = req_json.get('hwid', '').strip()
            nonce = req_json.get('nonce', '').strip()
            
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT password, hwid, expires_at, status FROM keys WHERE key = ?", (client_key,))
            row = c.fetchone()
            
            success = False
            status_msg = ""
            auth_status = "failed"
            days_left = 0
            
            if row:
                db_pass, db_hwid, expires_at_str, status = row
                expiry_dt = datetime.datetime.fromisoformat(expires_at_str)
                
                # Check password if configured on server
                if db_pass and db_pass != client_pass:
                    status_msg = "Incorrect password!"
                    auth_status = "invalid_password"
                elif status == 'revoked':
                    status_msg = "Your account/key has been revoked by admin!"
                    auth_status = "revoked"
                elif datetime.datetime.now() > expiry_dt:
                    status_msg = "Your license has expired!"
                    auth_status = "expired"
                else:
                    # HWID Check & Auto-bind Logic
                    if not db_hwid and client_hwid:
                        # First time bind HWID
                        c.execute("UPDATE keys SET hwid = ? WHERE key = ?", (client_hwid, client_key))
                        conn.commit()
                        db_hwid = client_hwid
                    
                    if db_hwid and client_hwid and db_hwid != client_hwid:
                        status_msg = "HWID mismatch! Locked to another device."
                        auth_status = "hwid_mismatch"
                    else:
                        success = True
                        auth_status = "success"
                        status_msg = "Loaded successfully"
                        days_left = max(1, int((expiry_dt - datetime.datetime.now()).total_seconds() / 86400))
                        if expiry_dt.year > 9000:
                            days_left = 9999
            else:
                status_msg = "Invalid username or key!"
                auth_status = "invalid_user"
                
            # Get client IP (support proxies like Render)
            ip = self.headers.get('X-Forwarded-For')
            if ip:
                ip = ip.split(',')[0].strip()
            else:
                ip = self.client_address[0]
                
            now_iso = datetime.datetime.now().isoformat()
            log_detail = f"{status_msg} [HWID: {client_hwid}]"
            c.execute("INSERT INTO logs (timestamp, ip, key, status, message) VALUES (?, ?, ?, ?, ?)", 
                      (now_iso, ip, client_key, auth_status, log_detail))
            conn.commit()
            conn.close()
            
            key_input = (SERVER_MASTER_KEY + nonce).encode('utf-8')
            resp_key = hashlib.sha256(key_input).digest()
            
            if success:
                response_json = json.dumps({
                    "status": "success",
                    "success": True,
                    "mensagem": status_msg,
                    "token": "brmods_bypass_token_2026",
                    "product": "BRMods",
                    "vendedor": "ServerKey",
                    "dias": days_left,
                    "timeData": int(datetime.datetime.now().timestamp()),
                    "expire": int((datetime.datetime.now() + datetime.timedelta(days=days_left)).timestamp()) if days_left < 9999 else 1918000000,
                    "o_ga": "", "o_gf": "", "o_pn": "", "o_pugc": "", "o_pths": "", "o_pth": ""
                }, separators=(',', ':'))
            else:
                response_json = json.dumps({
                    "status": "failed",
                    "success": False,
                    "mensagem": status_msg
                }, separators=(',', ':'))
                
            response_bytes = response_json.encode('utf-8') + b'\x00'
            
            resp_cipher = AES.new(resp_key, AES.MODE_CBC, RESPONSE_IV)
            resp_ciphertext = resp_cipher.encrypt(pad(response_bytes, AES.block_size))
            
            resp_b64_iv = base64.b64encode(RESPONSE_IV).decode('utf-8')
            resp_b64_payload = base64.b64encode(resp_ciphertext).decode('utf-8')
            
            final_response = json.dumps({"iv": resp_b64_iv, "payload": resp_b64_payload}, separators=(',', ':'))
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(final_response.encode('utf-8'))
            
        except Exception as e:
            self.send_response(500)
            self.end_headers()

def run_server():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), KeyAuthHandler) as httpd:
        print(f"[+] Server started successfully on port {PORT}.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Server stopped.")

if __name__ == "__main__":
    init_db()
    run_server()
