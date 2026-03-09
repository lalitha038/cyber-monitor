import psycopg2
import psycopg2.extras
import os
import csv
import io
import json
import re
from datetime import datetime, timedelta
import random

from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, Response, send_file)
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors as rl_colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import openpyxl
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False

try:
    import praw
    PRAW_AVAILABLE = True
except ImportError:
    PRAW_AVAILABLE = False

try:
    import requests as http_requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

app = Flask(__name__)
app.secret_key = 'super_secret_social_media_key_2026'

# ─── ROLE-BASED ACCESS CONTROL ─────────────────────────────────────────────────

# Role hierarchy: Admin > Analyst > Viewer
ROLE_HIERARCHY = {'Admin': 3, 'Analyst': 2, 'Viewer': 1}

def login_required(f):
    """Ensure the user is logged in."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def require_role(min_role):
    """Restrict access to users whose role meets or exceeds min_role."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            user_role = session.get('role', 'Viewer')
            if ROLE_HIERARCHY.get(user_role, 0) < ROLE_HIERARCHY.get(min_role, 99):
                flash(f'Access denied. {min_role} role or higher required.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator

# PostgreSQL connection via DATABASE_URL environment variable
DATABASE_URL = os.environ.get('DATABASE_URL', '')

# ─── DATABASE ──────────────────────────────────────────────────────────────────

def get_db():
    """Open a new PostgreSQL connection using DATABASE_URL."""
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn

def db_fetchone(conn, query, params=()):
    """Execute a query and return one row as a dict (or None)."""
    with conn.cursor() as cur:
        cur.execute(query, params)
        return cur.fetchone()

def db_fetchall(conn, query, params=()):
    """Execute a query and return all rows as a list of dicts."""
    with conn.cursor() as cur:
        cur.execute(query, params)
        return cur.fetchall()

def db_execute(conn, query, params=()):
    """Execute a write query (INSERT/UPDATE/DELETE) and commit."""
    with conn.cursor() as cur:
        cur.execute(query, params)
    conn.commit()

def init_db():
    conn = get_db()
    with conn.cursor() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'Analyst'
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS watchwords (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            keyword TEXT NOT NULL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS posts (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            platform TEXT NOT NULL,
            username TEXT NOT NULL,
            post_text TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            keyword TEXT NOT NULL,
            category TEXT NOT NULL,
            is_high_risk BOOLEAN DEFAULT FALSE,
            threat_score INTEGER DEFAULT 0,
            sentiment TEXT DEFAULT 'Neutral',
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS threats (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            platform TEXT NOT NULL,
            username TEXT NOT NULL,
            post_text TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            matched_keyword TEXT NOT NULL,
            severity TEXT DEFAULT 'Low',
            threat_score INTEGER DEFAULT 0,
            location TEXT DEFAULT 'Unknown',
            sentiment TEXT DEFAULT 'Neutral',
            is_high_risk BOOLEAN DEFAULT FALSE,
            is_reviewed BOOLEAN DEFAULT FALSE,
            entities TEXT DEFAULT '',
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS user_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            timestamp TEXT NOT NULL
        )''')
        conn.commit()

        # Safe column migrations (PostgreSQL ignores duplicate column errors)
        for migration in [
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'Analyst'",
            "ALTER TABLE posts ADD COLUMN IF NOT EXISTS threat_score INTEGER DEFAULT 0",
            "ALTER TABLE posts ADD COLUMN IF NOT EXISTS sentiment TEXT DEFAULT 'Neutral'",
            "ALTER TABLE threats ADD COLUMN IF NOT EXISTS severity TEXT DEFAULT 'Low'",
            "ALTER TABLE threats ADD COLUMN IF NOT EXISTS threat_score INTEGER DEFAULT 0",
            "ALTER TABLE threats ADD COLUMN IF NOT EXISTS location TEXT DEFAULT 'Unknown'",
            "ALTER TABLE threats ADD COLUMN IF NOT EXISTS sentiment TEXT DEFAULT 'Neutral'",
            "ALTER TABLE threats ADD COLUMN IF NOT EXISTS is_reviewed BOOLEAN DEFAULT FALSE",
            "ALTER TABLE threats ADD COLUMN IF NOT EXISTS entities TEXT DEFAULT ''",
        ]:
            try:
                c.execute(migration)
            except Exception:
                pass
        conn.commit()
    conn.close()

@app.before_request
def before_request():
    init_db()

def log_action(user_id, username, action, details=''):
    """Record user activity to the user_logs table."""
    try:
        db = get_db()
        ip = request.remote_addr or ''
        db_execute(db, 'INSERT INTO user_logs (user_id, username, action, details, ip_address, timestamp) VALUES (%s,%s,%s,%s,%s,%s)',
                   (user_id, username, action, details, ip, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        db.close()
    except Exception:
        pass

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
URL_PATTERN = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
ORG_KEYWORDS = ['microsoft','google','cloudflare','amazon','facebook','twitter','telegram','whatsapp',
                'interpol','fbi','cia','nsa','dhs','cisa','nato','un','who','govt','government',
                'bank','hospital','university','ministry','army','police','intel','cisco','palo alto']

def extract_entities(text):
    """Extract IPs, URLs, and organization names from post text."""
    t = text.lower()
    ips = IP_PATTERN.findall(text)
    urls = URL_PATTERN.findall(text)
    orgs = [o.title() for o in ORG_KEYWORDS if o in t]
    parts = []
    if ips: parts.append('IPs: ' + ', '.join(ips))
    if urls: parts.append('URLs: ' + ', '.join(urls[:2]))
    if orgs: parts.append('Orgs: ' + ', '.join(orgs[:3]))
    return ' | '.join(parts) if parts else ''

# ─── THREAT ENGINE DATA ────────────────────────────────────────────────────────

THREAT_DICTIONARY = {
    'Cyber Attack': [
        'ransomware', 'malware', 'phishing', 'ddos', 'hack', 'data breach',
        'spyware', 'credential leak', 'botnet', 'zero-day', 'network intrusion',
        'corporate espionage', 'information leak', 'exploit', 'backdoor',
        'trojan', 'keylogger', 'worm', 'rootkit', 'sql injection',
        'xss attack', 'man in the middle', 'apt attack', 'ransomware attack',
        'malware distribution', 'account hacking'
    ],
    'Financial Crime': [
        'online scam', 'crypto scam', 'cryptocurrency fraud', 'banking fraud',
        'investment scam', 'fake giveaway', 'marketplace fraud',
        'payment fraud', 'identity theft', 'money laundering',
        'ponzi scheme', 'romance scam', 'wire fraud', 'phishing scam'
    ],
    'Security Threat': [
        'bomb threat', 'terror attack', 'mass attack', 'weapon sale',
        'drug trafficking', 'human trafficking', 'organized crime',
        'violent crime', 'assassination', 'arson', 'murder plot',
        'explosive device', 'terrorism', 'extremist', 'militia'
    ],
    'Social Media Abuse': [
        'fake news', 'misinformation', 'hate speech', 'cyberbullying',
        'online harassment', 'doxxing', 'blackmail', 'impersonation',
        'deepfake', 'disinformation', 'propaganda', 'stalking',
        'sextortion', 'trolling', 'doxing'
    ]
}

SEVERITY_MAP = {
    'Cyber Attack':     {'default': 'High',     'keywords': {'zero-day': 'Critical', 'apt attack': 'Critical', 'ransomware attack': 'Critical', 'ransomware': 'Critical', 'data breach': 'High', 'phishing': 'Medium', 'sql injection': 'High', 'backdoor': 'High'}},
    'Financial Crime':  {'default': 'Medium',   'keywords': {'money laundering': 'High', 'wire fraud': 'High', 'banking fraud': 'High', 'crypto scam': 'Medium', 'phishing scam': 'High'}},
    'Security Threat':  {'default': 'Critical', 'keywords': {'bomb threat': 'Critical', 'terror attack': 'Critical', 'weapon sale': 'High', 'drug trafficking': 'High', 'organized crime': 'High'}},
    'Social Media Abuse': {'default': 'Low',    'keywords': {'doxxing': 'Medium', 'blackmail': 'High', 'sextortion': 'High', 'hate speech': 'Medium', 'deepfake': 'Medium'}}
}

THREAT_SCORE_MAP = {'Low': random.randint(1,3), 'Medium': random.randint(4,6), 'High': random.randint(7,8), 'Critical': random.randint(9,10)}

LOCATIONS = [
    ('India', 20.5937, 78.9629), ('USA', 37.0902, -95.7129),
    ('UK', 55.3781, -3.4360), ('Germany', 51.1657, 10.4515),
    ('Russia', 61.5240, 105.3188), ('China', 35.8617, 104.1954),
    ('Brazil', -14.2350, -51.9253), ('Australia', -25.2744, 133.7751),
    ('Canada', 56.1304, -106.3468), ('France', 46.2276, 2.2137),
    ('Japan', 36.2048, 138.2529), ('Nigeria', 9.0820, 8.6753),
    ('Pakistan', 30.3753, 69.3451), ('Iran', 32.4279, 53.6880),
    ('North Korea', 40.3399, 127.5101), ('Ukraine', 48.3794, 31.1656),
    ('UAE', 23.4241, 53.8478), ('Singapore', 1.3521, 103.8198),
    ('South Korea', 35.9078, 127.7669), ('Netherlands', 52.1326, 5.2913),
]

HIGH_RISK_THREAT_KEYWORDS = [
    'bomb', 'terror attack', 'mass attack', 'critical infrastructure',
    'weapon attack', 'assassination', 'explosive', 'terrorism', 'ransomware attack'
]

THREAT_POST_TEMPLATES = [
    "URGENT: Major {keyword} detected targeting critical systems",
    "Breaking: Authorities investigating serious {keyword} online",
    "Warning: New {keyword} campaign spreading across platforms",
    "Alert: {keyword} activity reported by multiple security agencies",
    "Users warned about widespread {keyword} affecting thousands",
    "Intelligence confirms coordinated {keyword} operation ongoing",
    "Law enforcement tracking {keyword} network on social media",
    "Security researchers expose new {keyword} targeting users",
    "Government agencies issue warning about {keyword} surge",
    "Dark web forums discussing large-scale {keyword} plans",
    "Multiple victims report {keyword} activity in their region",
    "Interpol releases advisory on {keyword} operations worldwide",
]

def classify_severity(threat_type, keyword):
    entry = SEVERITY_MAP.get(threat_type, {'default': 'Low', 'keywords': {}})
    for kw, sev in entry['keywords'].items():
        if kw in keyword.lower():
            return sev
    return entry['default']

def classify_sentiment(post_text):
    pos = ['warning', 'alert', 'advisory', 'authorities', 'interpol', 'law enforcement', 'report']
    neg = ['attack', 'threat', 'crime', 'fraud', 'scam', 'breach', 'hack', 'bomb', 'terror']
    t = post_text.lower()
    neg_count = sum(1 for w in neg if w in t)
    pos_count = sum(1 for w in pos if w in t)
    if neg_count > pos_count: return 'Negative'
    if pos_count > neg_count: return 'Positive'
    return 'Neutral'

def get_threat_score(severity):
    mapping = {'Low': random.randint(1,3), 'Medium': random.randint(4,6), 'High': random.randint(7,8), 'Critical': random.randint(9,10)}
    return mapping.get(severity, 3)

def simulate_threat_scan(user_id):
    db = get_db()
    platforms = ['Twitter', 'Facebook', 'Instagram', 'Discord']
    for threat_type, keywords in THREAT_DICTIONARY.items():
        sample_keywords = random.sample(keywords, min(5, len(keywords)))
        for kw in sample_keywords:
            for _ in range(random.randint(2, 6)):
                platform = random.choice(platforms)
                username = f"intel_user_{random.randint(100, 9999)}"
                post_text = random.choice(THREAT_POST_TEMPLATES).format(keyword=kw)
                severity = classify_severity(threat_type, kw)
                sentiment = classify_sentiment(post_text)
                score = get_threat_score(severity)
                location_entry = random.choice(LOCATIONS)
                lat = location_entry[1] + random.uniform(-2, 2)
                lng = location_entry[2] + random.uniform(-2, 2)
                location_json = json.dumps({'name': location_entry[0], 'lat': round(lat, 4), 'lng': round(lng, 4)})
                is_high_risk = True if severity == 'Critical' or any(w in post_text.lower() or w in kw.lower() for w in HIGH_RISK_THREAT_KEYWORDS) else False
                days_ago = random.randint(0, 6)
                ts = (datetime.now() - timedelta(days=days_ago)).strftime('%Y-%m-%d %H:%M:%S')
                entities = extract_entities(post_text)
                db_execute(db, '''
                    INSERT INTO threats (user_id, platform, username, post_text, timestamp,
                        threat_type, matched_keyword, severity, threat_score, location, sentiment, is_high_risk, entities)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (user_id, platform, username, post_text, ts,
                      threat_type, kw, severity, score, location_json, sentiment, is_high_risk, entities))
    db.close()

# ─── AUTH ──────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db_fetchone(db, 'SELECT * FROM users WHERE username = %s', (username,))
        db.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            log_action(user['id'], user['username'], 'LOGIN', f'Role: {user["role"]}')
            return redirect(url_for('dashboard'))
        else:
            log_action(0, username, 'FAILED_LOGIN', 'Invalid credentials')
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'Analyst')
        db = get_db()
        if db_fetchone(db, 'SELECT id FROM users WHERE username = %s', (username,)):
            db.close()
            flash('Username already exists', 'error')
        else:
            db_execute(db, 'INSERT INTO users (name, username, password, role) VALUES (%s, %s, %s, %s)',
                       (name, username, generate_password_hash(password), role))
            db.close()
            flash('Account created successfully. Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/account-settings', methods=['GET', 'POST'])
@login_required
def account_settings():
    db = get_db()
    user = db_fetchone(db, 'SELECT * FROM users WHERE id = %s', (session['user_id'],))
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'change_password':
            current = request.form.get('current_password')
            new_pass = request.form.get('new_password')
            if check_password_hash(user['password'], current):
                db_execute(db, 'UPDATE users SET password = %s WHERE id = %s',
                           (generate_password_hash(new_pass), session['user_id']))
                flash('Password updated successfully!', 'success')
            else:
                flash('Current password is incorrect.', 'error')
        elif action == 'change_username':
            new_username = request.form.get('new_username')
            existing = db_fetchone(db, 'SELECT id FROM users WHERE username = %s', (new_username,))
            if existing:
                flash('Username already taken.', 'error')
            else:
                db_execute(db, 'UPDATE users SET username = %s WHERE id = %s', (new_username, session['user_id']))
                session['username'] = new_username
                flash('Username updated successfully!', 'success')
    db.close()
    return render_template('account_settings.html', user=user)

# ─── DASHBOARD ─────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    uid = session['user_id']

    total_posts = db_fetchone(db, 'SELECT COUNT(*) as c FROM posts WHERE user_id=%s', (uid,))['c']
    high_risk_alerts = db_fetchone(db, 'SELECT COUNT(*) as c FROM posts WHERE user_id=%s AND is_high_risk=TRUE', (uid,))['c']

    trending_row = db_fetchone(db, '''SELECT keyword, COUNT(*) as c FROM posts WHERE user_id=%s
        GROUP BY keyword ORDER BY c DESC LIMIT 1''', (uid,))
    trending_keyword = trending_row['keyword'] if trending_row else 'None'

    recent_activity = db_fetchall(db, '''SELECT platform, keyword, timestamp FROM posts WHERE user_id=%s
        ORDER BY timestamp DESC LIMIT 5''', (uid,))

    platform_data = db_fetchall(db, 'SELECT platform, COUNT(*) as c FROM posts WHERE user_id=%s GROUP BY platform', (uid,))
    cat_data = db_fetchall(db, 'SELECT category, COUNT(*) as c FROM posts WHERE user_id=%s GROUP BY category', (uid,))

    sev_counts = {}
    for sev in ['Low', 'Medium', 'High', 'Critical']:
        row = db_fetchone(db, 'SELECT COUNT(*) as c FROM threats WHERE user_id=%s AND severity=%s', (uid, sev))
        sev_counts[sev] = row['c']

    total_threats = db_fetchone(db, 'SELECT COUNT(*) as c FROM threats WHERE user_id=%s', (uid,))['c']
    alert_count = db_fetchone(db, 'SELECT COUNT(*) as c FROM threats WHERE user_id=%s AND is_high_risk=TRUE AND is_reviewed=FALSE', (uid,))['c']
    db.close()

    return render_template('dashboard.html',
        total_posts=total_posts, high_risk_alerts=high_risk_alerts,
        trending_keyword=trending_keyword, recent_activity=recent_activity,
        platform_labels=[r['platform'] for r in platform_data],
        platform_counts=[r['c'] for r in platform_data],
        category_labels=[r['category'] for r in cat_data],
        category_counts=[r['c'] for r in cat_data],
        sev_counts=sev_counts, total_threats=total_threats,
        alert_count=alert_count)

# ─── REAL CRAWLERS ─────────────────────────────────────────────────────────────

def real_crawler_reddit(user_id, keywords_list):
    """Fetch real posts from Reddit using PRAW. Requires REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET env vars."""
    if not PRAW_AVAILABLE:
        return False
    client_id = os.environ.get('REDDIT_CLIENT_ID', '')
    client_secret = os.environ.get('REDDIT_CLIENT_SECRET', '')
    if not client_id or not client_secret:
        return False
    try:
        reddit = praw.Reddit(
            client_id=client_id,
            client_secret=client_secret,
            user_agent='CyberIntelPlatform/1.0 (by /u/intel_monitor)'
        )
        db = get_db()
        cyber_threat_words = ['ransomware','malware','hack','ddos','phishing','zero-day',
                              'botnet','exploit','breach','vulnerability','apt','spyware']
        security_alert_words = ['protest','attack','data leak','threat','warning','alert']
        high_risk_words = ['attack','bomb','breach','hack','zero-day','apt','ransomware','terrorism']
        count = 0
        for kw in keywords_list:
            try:
                results = reddit.subreddit('all').search(kw, limit=20, time_filter='week', sort='new')
                for post in results:
                    post_text = (post.title + ' ' + (post.selftext or ''))[:500].strip()
                    if not post_text:
                        continue
                    post_lower = post_text.lower()
                    category = 'General Discussion'
                    if any(w in post_lower for w in cyber_threat_words): category = 'Cyber Threat'
                    elif any(w in post_lower for w in security_alert_words): category = 'Security Alert'
                    is_high_risk = any(w in post_lower for w in high_risk_words)
                    score = get_threat_score('High' if is_high_risk else 'Low')
                    sentiment = classify_sentiment(post_text)
                    author = str(post.author) if post.author else 'deleted'
                    ts = datetime.fromtimestamp(post.created_utc).strftime('%Y-%m-%d %H:%M:%S')
                    platform = f"Reddit r/{post.subreddit.display_name}"
                    db_execute(db, '''INSERT INTO posts (user_id, platform, username, post_text, timestamp, keyword, category, is_high_risk, threat_score, sentiment)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                        (user_id, platform, author, post_text, ts, kw, category, is_high_risk, score, sentiment))
                    count += 1
            except Exception:
                continue
        db.close()
        return count > 0
    except Exception:
        return False


def real_crawler_hackernews(user_id, keywords_list):
    """Fetch real posts from HackerNews via Algolia API — zero setup, no API key needed."""
    if not REQUESTS_AVAILABLE:
        return False
    try:
        db = get_db()
        cyber_threat_words = ['ransomware','malware','hack','ddos','phishing','zero-day',
                              'breach','exploit','vulnerability','security']
        high_risk_words = ['attack','breach','hack','ransomware','zero-day','exploit']
        count = 0
        for kw in keywords_list:
            try:
                url = f'https://hn.algolia.com/api/v1/search?query={kw}&tags=story&hitsPerPage=20'
                resp = http_requests.get(url, timeout=8)
                if resp.status_code != 200:
                    continue
                hits = resp.json().get('hits', [])
                for hit in hits:
                    title = hit.get('title', '')
                    body = hit.get('story_text') or ''
                    post_text = (title + ' ' + body)[:500].strip()
                    if not post_text:
                        continue
                    post_lower = post_text.lower()
                    category = 'Cyber Threat' if any(w in post_lower for w in cyber_threat_words) else 'General Discussion'
                    is_high_risk = any(w in post_lower for w in high_risk_words)
                    score = get_threat_score('High' if is_high_risk else 'Low')
                    sentiment = classify_sentiment(post_text)
                    author = hit.get('author', 'hn_user')
                    created_at = hit.get('created_at', datetime.now().isoformat())
                    try:
                        ts = datetime.fromisoformat(created_at.replace('Z','')).strftime('%Y-%m-%d %H:%M:%S')
                    except Exception:
                        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    db_execute(db, '''INSERT INTO posts (user_id, platform, username, post_text, timestamp, keyword, category, is_high_risk, threat_score, sentiment)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                        (user_id, 'HackerNews', author, post_text, ts, kw, category, is_high_risk, score, sentiment))
                    count += 1
            except Exception:
                continue
        db.close()
        return count > 0
    except Exception:
        return False


def smart_crawler(user_id, keywords_list):
    """Try Reddit first, then HackerNews, then fall back to simulation."""
    if real_crawler_reddit(user_id, keywords_list):
        return 'reddit'
    if real_crawler_hackernews(user_id, keywords_list):
        return 'hackernews'
    simulate_crawler(user_id, keywords_list)
    return 'simulated'


# ─── WATCH WORDS (SIMULATED FALLBACK) ──────────────────────────────────────────

def simulate_crawler(user_id, keywords_list):
    platforms = ['Twitter', 'Facebook', 'Instagram', 'Discord']
    db = get_db()
    templates = [
        "New {keyword} attack targeting hospitals",
        "Major {keyword} reported on banking servers",
        "Discussion about {keyword} spreading online",
        "Alert: {keyword} detected in the network",
        "People organizing a {keyword} tomorrow",
        "Security warning regarding {keyword} vulnerability",
        "Suspicious {keyword} activity found on dark web",
        "System compromised by latest {keyword}",
        "Critical {keyword} infrastructure breach reported",
        "Massive {keyword} campaign affecting multiple orgs",
        "New variant of {keyword} spotted in the wild"
    ]
    cyber_threat_words = ['cyber threat', 'ransomware', 'malware', 'hack', 'ddos', 'phishing',
                          'zero-day', 'botnet', 'apt', 'sql injection', 'xss']
    security_alert_words = ['protest', 'attack', 'data leak', 'breach']
    high_risk_words = ['attack', 'bomb', 'breach', 'hack', 'zero-day', 'apt']

    for kw in keywords_list:
        for _ in range(random.randint(5, 15)):
            platform = random.choice(platforms)
            username = f"user_{random.randint(100, 999)}"
            post_text = random.choice(templates).format(keyword=kw)
            post_lower = post_text.lower()
            category = 'General Discussion'
            if any(w in post_lower for w in cyber_threat_words): category = 'Cyber Threat'
            elif any(w in post_lower for w in security_alert_words): category = 'Security Alert'
            is_high_risk = True if any(w in post_lower for w in high_risk_words) else False
            score = get_threat_score('High' if is_high_risk else 'Low')
            sentiment = classify_sentiment(post_text)
            db_execute(db, '''INSERT INTO posts (user_id, platform, username, post_text, timestamp, keyword, category, is_high_risk, threat_score, sentiment)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                (user_id, platform, username, post_text, datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                 kw, category, is_high_risk, score, sentiment))
    db.close()

@app.route('/watchwords', methods=['GET', 'POST'])
@login_required
def watchwords():
    if request.method == 'POST':
        if session.get('role') == 'Viewer':
            flash('Viewers cannot add watch words. Contact an Admin or Analyst.', 'error')
            return redirect(url_for('watchwords'))
        keywords_str = request.form.get('keywords', '')
        uid = session['user_id']
        keywords_list = [k.strip() for k in keywords_str.split(',') if k.strip()]
        if keywords_list:
            db = get_db()
            for kw in keywords_list:
                db_execute(db, 'INSERT INTO watchwords (user_id, keyword) VALUES (%s, %s)', (uid, kw))
            db.close()
            source = smart_crawler(uid, keywords_list)
            source_labels = {'reddit': 'Reddit', 'hackernews': 'HackerNews', 'simulated': 'Simulated Data'}
            flash(f'Monitoring started! Fetched real posts from {source_labels.get(source, source)} for {len(keywords_list)} keyword(s).', 'success')
            return redirect(url_for('results'))
        flash('Please enter at least one keyword.', 'error')
    return render_template('watchwords.html')

@app.route('/watchword-history')
@login_required
def watchword_history():
    db = get_db()
    words = db_fetchall(db, 'SELECT * FROM watchwords WHERE user_id=%s ORDER BY added_at DESC', (session['user_id'],))
    db.close()
    return render_template('watchword_history.html', words=words)

@app.route('/delete-watchword/<int:wid>')
@require_role('Analyst')
def delete_watchword(wid):
    db = get_db()
    db_execute(db, 'DELETE FROM watchwords WHERE id=%s AND user_id=%s', (wid, session['user_id']))
    db.close()
    flash('Watch word deleted.', 'success')
    return redirect(url_for('watchword_history'))

# ─── RESULTS ───────────────────────────────────────────────────────────────────

@app.route('/results')
@login_required
def results():
    db = get_db()
    uid = session['user_id']
    platform = request.args.get('platform', '')
    keyword = request.args.get('keyword', '')
    category = request.args.get('category', '')

    query = 'SELECT * FROM posts WHERE user_id=%s'
    params = [uid]
    if platform: query += ' AND platform=%s'; params.append(platform)
    if keyword: query += ' AND keyword=%s'; params.append(keyword)
    if category: query += ' AND category=%s'; params.append(category)
    query += ' ORDER BY timestamp DESC'

    posts = db_fetchall(db, query, params)
    platforms = db_fetchall(db, 'SELECT DISTINCT platform FROM posts WHERE user_id=%s', (uid,))
    keywords = db_fetchall(db, 'SELECT DISTINCT keyword FROM posts WHERE user_id=%s', (uid,))
    categories = db_fetchall(db, 'SELECT DISTINCT category FROM posts WHERE user_id=%s', (uid,))
    db.close()

    return render_template('results.html', posts=posts,
        platforms=[p['platform'] for p in platforms],
        keywords=[k['keyword'] for k in keywords],
        categories=[c['category'] for c in categories],
        current_platform=platform, current_keyword=keyword, current_category=category)

@app.route('/delete-post/<int:pid>')
@require_role('Analyst')
def delete_post(pid):
    db = get_db()
    db_execute(db, 'DELETE FROM posts WHERE id=%s AND user_id=%s', (pid, session['user_id']))
    db.close()
    flash('Post deleted.', 'success')
    return redirect(url_for('results'))

@app.route('/clear-data')
@require_role('Admin')
def clear_data():
    db = get_db()
    db_execute(db, 'DELETE FROM posts WHERE user_id=%s', (session['user_id'],))
    db_execute(db, 'DELETE FROM threats WHERE user_id=%s', (session['user_id'],))
    db.close()
    flash('All data cleared successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/export-results')
@require_role('Analyst')
def export_results():
    db = get_db()
    posts = db_fetchall(db, 'SELECT * FROM posts WHERE user_id=%s ORDER BY timestamp DESC', (session['user_id'],))
    db.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Platform', 'Username', 'Post', 'Category', 'Keyword', 'Threat Score', 'Sentiment', 'High Risk', 'Date'])
    for p in posts:
        writer.writerow([p['platform'], p['username'], p['post_text'], p['category'],
                         p['keyword'], p['threat_score'], p['sentiment'],
                         'Yes' if p['is_high_risk'] else 'No', p['timestamp']])
    output.seek(0)
    return Response(output, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=results.csv'})

# ─── THREAT INTELLIGENCE ───────────────────────────────────────────────────────

@app.route('/threat-intelligence')
@login_required
def threat_intelligence():
    db = get_db()
    uid = session['user_id']

    # Auto-scan if empty
    if db_fetchone(db, 'SELECT COUNT(*) as c FROM threats WHERE user_id=%s', (uid,))['c'] == 0:
        simulate_threat_scan(uid)
    
    # Filters
    threat_type_filter = request.args.get('threat_type', '')
    platform_filter = request.args.get('platform', '')
    severity_filter = request.args.get('severity', '')
    search_query = request.args.get('q', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    query = 'SELECT * FROM threats WHERE user_id=%s'
    params = [uid]
    if threat_type_filter: query += ' AND threat_type=%s'; params.append(threat_type_filter)
    if platform_filter: query += ' AND platform=%s'; params.append(platform_filter)
    if severity_filter: query += ' AND severity=%s'; params.append(severity_filter)
    if search_query: query += ' AND (post_text LIKE %s OR matched_keyword LIKE %s)'; params += [f'%{search_query}%', f'%{search_query}%']
    if date_from: query += ' AND timestamp >= %s'; params.append(date_from)
    if date_to: query += ' AND timestamp <= %s'; params.append(date_to + ' 23:59:59')
    query += ' ORDER BY timestamp DESC'

    threats = db_fetchall(db, query, params)

    total_threats = db_fetchone(db, 'SELECT COUNT(*) as c FROM threats WHERE user_id=%s', (uid,))['c']
    high_risk_count = db_fetchone(db, 'SELECT COUNT(*) as c FROM threats WHERE user_id=%s AND is_high_risk=TRUE', (uid,))['c']

    type_counts = {}
    for tt in THREAT_DICTIONARY.keys():
        type_counts[tt] = db_fetchone(db, 'SELECT COUNT(*) as c FROM threats WHERE user_id=%s AND threat_type=%s', (uid, tt))['c']

    sev_counts = {}
    for sev in ['Low', 'Medium', 'High', 'Critical']:
        sev_counts[sev] = db_fetchone(db, 'SELECT COUNT(*) as c FROM threats WHERE user_id=%s AND severity=%s', (uid, sev))['c']

    platform_data = db_fetchall(db, 'SELECT platform, COUNT(*) as c FROM threats WHERE user_id=%s GROUP BY platform', (uid,))

    # Timeline: last 7 days
    timeline_labels = []
    timeline_values = []
    for i in range(6, -1, -1):
        day = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        count = db_fetchone(db, "SELECT COUNT(*) as c FROM threats WHERE user_id=%s AND timestamp LIKE %s", (uid, f'{day}%'))['c']
        timeline_labels.append((datetime.now() - timedelta(days=i)).strftime('%a'))
        timeline_values.append(count)

    all_threats = db_fetchall(db, 'SELECT location, threat_type, post_text FROM threats WHERE user_id=%s', (uid,))
    db.close()
    map_points = []
    for t in all_threats:
        try:
            loc = json.loads(t['location'])
            map_points.append({'lat': loc['lat'], 'lng': loc['lng'], 'name': loc['name'],
                               'type': t['threat_type'], 'post': t['post_text'][:80]})
        except Exception:
            pass

    return render_template('threat_intelligence.html',
        threats=threats, total_threats=total_threats, high_risk_count=high_risk_count,
        type_counts=type_counts, sev_counts=sev_counts,
        platform_labels=[r['platform'] for r in platform_data],
        platform_counts=[r['c'] for r in platform_data],
        timeline_labels=timeline_labels, timeline_values=timeline_values,
        map_points=map_points,
        current_threat_type=threat_type_filter, current_platform=platform_filter,
        current_severity=severity_filter, search_query=search_query,
        date_from=date_from, date_to=date_to,
        threat_types=list(THREAT_DICTIONARY.keys()))

@app.route('/rescan-threats')
@require_role('Analyst')
def rescan_threats():
    db = get_db()
    db_execute(db, 'DELETE FROM threats WHERE user_id=%s', (session['user_id'],))
    db.close()
    simulate_threat_scan(session['user_id'])
    log_action(session['user_id'], session['username'], 'THREAT_SCAN', 'Manual rescan triggered')
    flash('Threat intelligence scan complete!', 'success')
    return redirect(url_for('threat_intelligence'))

@app.route('/mark-reviewed/<int:tid>')
@require_role('Analyst')
def mark_reviewed(tid):
    db = get_db()
    db_execute(db, 'UPDATE threats SET is_reviewed=TRUE WHERE id=%s AND user_id=%s', (tid, session['user_id']))
    db.close()
    return redirect(url_for('alert_inbox'))

# ─── ALERT INBOX ───────────────────────────────────────────────────────────────

@app.route('/alert-inbox')
@login_required
def alert_inbox():
    db = get_db()
    uid = session['user_id']
    show_reviewed = request.args.get('show_reviewed', '0')
    query = 'SELECT * FROM threats WHERE user_id=%s AND is_high_risk=TRUE'
    if show_reviewed != '1':
        query += ' AND is_reviewed=FALSE'
    query += ' ORDER BY timestamp DESC'
    alerts = db_fetchall(db, query, (uid,))
    unread_count = db_fetchone(db, 'SELECT COUNT(*) as c FROM threats WHERE user_id=%s AND is_high_risk=TRUE AND is_reviewed=FALSE', (uid,))['c']
    db.close()
    return render_template('alert_inbox.html', alerts=alerts, unread_count=unread_count, show_reviewed=show_reviewed)

# ─── EXPORT THREAT INTELLIGENCE ────────────────────────────────────────────────

@app.route('/export-threats-csv')
@require_role('Analyst')
def export_threats_csv():
    db = get_db()
    threats = db_fetchall(db, 'SELECT * FROM threats WHERE user_id=%s ORDER BY timestamp DESC', (session['user_id'],))
    db.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Platform', 'Username', 'Post', 'Threat Type', 'Keyword', 'Severity', 'Score', 'Sentiment', 'Location', 'High Risk', 'Date'])
    for t in threats:
        try: loc = json.loads(t['location'])['name']
        except: loc = 'Unknown'
        writer.writerow([t['platform'], t['username'], t['post_text'], t['threat_type'],
                         t['matched_keyword'], t['severity'], t['threat_score'], t['sentiment'],
                         loc, 'Yes' if t['is_high_risk'] else 'No', t['timestamp']])
    output.seek(0)
    return Response(output, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=threat_intelligence.csv'})

@app.route('/export-threats-pdf')
@require_role('Analyst')
def export_threats_pdf():
    if not REPORTLAB_AVAILABLE:
        flash('PDF export requires reportlab. Run: pip install reportlab', 'error')
        return redirect(url_for('threat_intelligence'))
    db = get_db()
    uid = session['user_id']
    threats = db_fetchall(db, 'SELECT * FROM threats WHERE user_id=%s ORDER BY timestamp DESC LIMIT 50', (uid,))
    total = db_fetchone(db, 'SELECT COUNT(*) as c FROM threats WHERE user_id=%s', (uid,))['c']
    high_risk = db_fetchone(db, 'SELECT COUNT(*) as c FROM threats WHERE user_id=%s AND is_high_risk=TRUE', (uid,))['c']
    db.close()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    story.append(Paragraph('Threat Intelligence Report', styles['Title']))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")} | Total Threats: {total} | High Risk: {high_risk}', styles['Normal']))
    story.append(Spacer(1, 20))

    data = [['Platform', 'Threat Type', 'Severity', 'Keyword', 'Date']]
    for t in threats:
        data.append([t['platform'], t['threat_type'], t['severity'], t['matched_keyword'], t['timestamp'][:10]])

    table = Table(data, colWidths=[80, 110, 70, 120, 80])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), rl_colors.HexColor('#1e3a5f')),
        ('TEXTCOLOR', (0,0), (-1,0), rl_colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [rl_colors.white, rl_colors.HexColor('#f0f4f8')]),
        ('GRID', (0,0), (-1,-1), 0.5, rl_colors.grey),
        ('FONTSIZE', (0,0), (-1,-1), 9),
    ]))
    story.append(table)
    doc.build(story)
    buf.seek(0)
    return send_file(buf, mimetype='application/pdf', as_attachment=True, download_name='threat_report.pdf')

@app.route('/export-threats-excel')
@require_role('Analyst')
def export_threats_excel():
    if not OPENPYXL_AVAILABLE:
        flash('Excel export requires openpyxl. Run: pip install openpyxl', 'error')
        return redirect(url_for('threat_intelligence'))
    db = get_db()
    threats = db_fetchall(db, 'SELECT * FROM threats WHERE user_id=%s ORDER BY timestamp DESC', (session['user_id'],))
    db.close()
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = 'Threat Intelligence'
    headers = ['Platform', 'Username', 'Post', 'Threat Type', 'Keyword', 'Severity', 'Score', 'Sentiment', 'Location', 'High Risk', 'Date']
    ws.append(headers)
    for t in threats:
        try: loc = json.loads(t['location'])['name']
        except: loc = 'Unknown'
        ws.append([t['platform'], t['username'], t['post_text'], t['threat_type'],
                   t['matched_keyword'], t['severity'], t['threat_score'], t['sentiment'],
                   loc, 'Yes' if t['is_high_risk'] else 'No', t['timestamp']])
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                     as_attachment=True, download_name='threat_intelligence.xlsx')

# ─── USER ACTIVITY LOGS ────────────────────────────────────────────────────────

@app.route('/user-logs')
@login_required
def user_logs():
    db = get_db()
    uid = session['user_id']
    if session.get('role') == 'Admin':
        logs = db_fetchall(db, 'SELECT * FROM user_logs ORDER BY timestamp DESC LIMIT 500')
    else:
        logs = db_fetchall(db, 'SELECT * FROM user_logs WHERE user_id=%s ORDER BY timestamp DESC LIMIT 200', (uid,))

    total_logins = db_fetchone(db, "SELECT COUNT(*) as c FROM user_logs WHERE user_id=%s AND action='LOGIN'", (uid,))['c']
    failed_logins = db_fetchone(db, "SELECT COUNT(*) as c FROM user_logs WHERE username=%s AND action='FAILED_LOGIN'", (session['username'],))['c']
    total_scans = db_fetchone(db, "SELECT COUNT(*) as c FROM user_logs WHERE user_id=%s AND action='THREAT_SCAN'", (uid,))['c']
    db.close()

    return render_template('user_logs.html', logs=logs, total_logins=total_logins,
                           failed_logins=failed_logins, total_scans=total_scans)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_action(session['user_id'], session.get('username', ''), 'LOGOUT', 'User logged out')
    session.clear()
    return redirect(url_for('login'))

# ─── KEYWORD FREQUENCY DATA ────────────────────────────────────────────────────

@app.route('/api/keyword-frequency')
def keyword_frequency():
    if 'user_id' not in session:
        return jsonify([])
    db = get_db()
    rows = db_fetchall(db, '''SELECT keyword, COUNT(*) as c FROM posts WHERE user_id=%s
        GROUP BY keyword ORDER BY c DESC LIMIT 10''', (session['user_id'],))
    db.close()
    return jsonify([{'keyword': r['keyword'], 'count': r['c']} for r in rows])


# ─── ADMIN PANEL ────────────────────────────────────────────────────────────────

@app.route('/admin')
def admin_panel():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('role') != 'Admin':
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('dashboard'))
    db = get_db()
    users = db_fetchall(db, 'SELECT * FROM users ORDER BY id')
    user_stats = []
    for u in users:
        posts = db_fetchone(db, 'SELECT COUNT(*) as c FROM posts WHERE user_id=%s', (u['id'],))['c']
        threats = db_fetchone(db, 'SELECT COUNT(*) as c FROM threats WHERE user_id=%s', (u['id'],))['c']
        last_login = db_fetchone(db,
            "SELECT timestamp FROM user_logs WHERE user_id=%s AND action='LOGIN' ORDER BY timestamp DESC LIMIT 1",
            (u['id'],))
        user_stats.append({
            'id': u['id'], 'name': u['name'], 'username': u['username'],
            'role': u['role'], 'posts': posts, 'threats': threats,
            'last_login': last_login['timestamp'] if last_login else 'Never'
        })
    total_users = len(users)
    total_posts = db_fetchone(db, 'SELECT COUNT(*) as c FROM posts')['c']
    total_threats = db_fetchone(db, 'SELECT COUNT(*) as c FROM threats')['c']
    total_logs = db_fetchone(db, 'SELECT COUNT(*) as c FROM user_logs')['c']
    recent_logs = db_fetchall(db, 'SELECT * FROM user_logs ORDER BY timestamp DESC LIMIT 20')
    db.close()
    return render_template('admin.html', user_stats=user_stats,
                           total_users=total_users, total_posts=total_posts,
                           total_threats=total_threats, total_logs=total_logs,
                           recent_logs=recent_logs)

@app.route('/admin/change-role/<int:uid>', methods=['POST'])
def change_role(uid):
    if 'user_id' not in session or session.get('role') != 'Admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    new_role = request.form.get('role')
    if new_role not in ('Admin', 'Analyst', 'Viewer'):
        flash('Invalid role.', 'error')
        return redirect(url_for('admin_panel'))
    db = get_db()
    db_execute(db, 'UPDATE users SET role=%s WHERE id=%s', (new_role, uid))
    target = db_fetchone(db, 'SELECT username FROM users WHERE id=%s', (uid,))
    db.close()
    log_action(session['user_id'], session['username'], 'ROLE_CHANGE',
               f"Changed {target['username']} role to {new_role}")
    flash(f'Role updated to {new_role}.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete-user/<int:uid>', methods=['POST'])
def delete_user(uid):
    if 'user_id' not in session or session.get('role') != 'Admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    if uid == session['user_id']:
        flash("You can't delete your own account.", 'error')
        return redirect(url_for('admin_panel'))
    db = get_db()
    target = db_fetchone(db, 'SELECT username FROM users WHERE id=%s', (uid,))
    db_execute(db, 'DELETE FROM posts WHERE user_id=%s', (uid,))
    db_execute(db, 'DELETE FROM threats WHERE user_id=%s', (uid,))
    db_execute(db, 'DELETE FROM watchwords WHERE user_id=%s', (uid,))
    db_execute(db, 'DELETE FROM users WHERE id=%s', (uid,))
    db.close()
    log_action(session['user_id'], session['username'], 'DELETE_USER',
               f"Deleted user: {target['username']}")
    flash(f"User '{target['username']}' deleted.", 'success')
    return redirect(url_for('admin_panel'))

if __name__ == '__main__':
    app.run(debug=True)
