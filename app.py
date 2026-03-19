from flask import Flask, jsonify, request, send_from_directory
from flask_mysqldb import MySQL
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os, uuid, json, time

load_dotenv()

app = Flask(__name__)
CORS(app)

app.config['MYSQL_HOST']        = os.getenv('DB_HOST', 'localhost')
app.config['MYSQL_USER']        = os.getenv('DB_USER', 'root')
app.config['MYSQL_PASSWORD']    = os.getenv('DB_PASSWORD', '')
app.config['MYSQL_DB']          = os.getenv('DB_NAME', 'scamshield')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

# ── Import AI model (graceful fallback if not trained yet) ───────
try:
    from ai_model.detector import analyze as ai_analyze
    AI_AVAILABLE = True
    print("[ScamShield] AI model loaded successfully.")
except Exception as e:
    AI_AVAILABLE = False
    print(f"[ScamShield] AI model not available ({e}). Using keyword-only mode.")


# ================================================================
# SERVE FRONTENDS
# ================================================================

@app.route('/')
def index():
    return send_from_directory('static', 'scamshield_v13.html')

@app.route('/admin')
def admin():
    return send_from_directory('static', 'scamshield_admin_v2__1_.html')

@app.route('/test-db')
def test_db():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SHOW TABLES")
        tables = cur.fetchall()
        cur.close()
        return jsonify({'status': 'Connected!', 'tables': tables, 'ai_model': AI_AVAILABLE})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ================================================================
# USER AUTH
# ================================================================

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    name     = data.get('name', '').strip()
    email    = data.get('email', '').strip()
    password = data.get('password', '')

    if not name or not email or not password:
        return jsonify({'error': 'Name, email and password are required'}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id FROM users WHERE email = %s", (email,))
    if cur.fetchone():
        cur.close()
        return jsonify({'error': 'Email already registered'}), 409

    user_id       = str(uuid.uuid4())
    password_hash = generate_password_hash(password)

    cur.execute("""
        INSERT INTO users (user_id, name, email, password_hash, auth_provider, role, status)
        VALUES (%s, %s, %s, %s, 'email', 'user', 'active')
    """, (user_id, name, email, password_hash))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Account created', 'user_id': user_id}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data     = request.get_json()
    email    = data.get('email', '')
    password = data.get('password', '')

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({'error': 'Invalid email or password'}), 401

    # Support both hashed passwords (new) and plain-text (legacy accounts)
    password_ok = check_password_hash(user['password_hash'], password)
    if not password_ok:
        # Legacy fallback: plain-text match then upgrade hash
        if user['password_hash'] == password:
            new_hash = generate_password_hash(password)
            cur2 = mysql.connection.cursor()
            cur2.execute("UPDATE users SET password_hash = %s WHERE user_id = %s",
                         (new_hash, user['user_id']))
            mysql.connection.commit()
            cur2.close()
        else:
            return jsonify({'error': 'Invalid email or password'}), 401

    if user['status'] == 'suspended':
        return jsonify({'error': 'Account suspended'}), 403

    return jsonify({'message': 'Login successful', 'user': {
        'user_id':  user['user_id'],
        'name':     user['name'],
        'email':    user['email'],
        'role':     user['role'],
        'plan_id':  user['plan_id'],
    }}), 200


@app.route('/api/user/<user_id>', methods=['GET'])
def get_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT user_id, name, email, phone, date_of_birth, country, location,
               timezone, occupation, use_case, bio, role, status, plan_id,
               scan_count, created_at
        FROM users WHERE user_id = %s
    """, (user_id,))
    user = cur.fetchone()
    cur.close()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    # Serialise date fields
    if user.get('date_of_birth'):
        user['date_of_birth'] = str(user['date_of_birth'])
    if user.get('created_at'):
        user['created_at'] = str(user['created_at'])
    return jsonify(user), 200


# ── FIX: Missing update profile endpoint ────────────────────────
@app.route('/api/user/<user_id>/update', methods=['PATCH'])
def update_user(user_id):
    data = request.get_json()
    cur  = mysql.connection.cursor()

    # Only update allowed fields — never let caller change role/status this way
    allowed = ['name', 'email', 'phone', 'date_of_birth', 'country',
               'location', 'timezone', 'occupation', 'use_case', 'bio']

    updates = {k: data[k] for k in allowed if k in data}
    if not updates:
        return jsonify({'error': 'Nothing to update'}), 400

    # Convert empty strings to None for nullable fields
    for k, v in updates.items():
        if v == '':
            updates[k] = None

    set_clause = ', '.join(f"{k} = %s" for k in updates)
    values     = list(updates.values()) + [user_id]

    cur.execute(f"UPDATE users SET {set_clause} WHERE user_id = %s", values)
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Profile updated'}), 200


# ================================================================
# SCANS  —  powered by AI model
# ================================================================

@app.route('/api/scan', methods=['POST'])
def create_scan():
    data      = request.get_json()
    user_id   = data.get('user_id')
    text      = data.get('input_text', '').strip()
    scan_type = data.get('scan_type', 'SMS')

    if not user_id or not text:
        return jsonify({'error': 'user_id and input_text required'}), 400

    start_ms = int(time.time() * 1000)

    # ── Pull keywords from DB for rule engine ───────────────────
    cur = mysql.connection.cursor()
    cur.execute("SELECT keyword, weight FROM banned_keywords WHERE is_active = 1")
    keyword_rows = cur.fetchall()

    # ── Run detection ────────────────────────────────────────────
    if AI_AVAILABLE:
        # Map scan_type to input_type the AI model understands
        type_map = {'SMS': 'sms', 'Email': 'email', 'URL': 'url',
                    'WhatsApp': 'sms', 'Phone': 'phone'}
        input_type = type_map.get(scan_type, 'sms')

        blacklists = {
            'urls':     [],
            'phones':   set(),
            'keywords': [{'keyword': r['keyword'], 'weight': float(r['weight'])}
                         for r in keyword_rows]
        }
        detection = ai_analyze(input_type, text, blacklists)

        score          = round(detection['risk_score'] * 100, 2)
        ml_score       = detection.get('ml_score')
        rule_score     = detection.get('rule_score')
        triggered_rules = detection.get('triggered_rules', [])
    else:
        # Keyword-only fallback (original logic)
        text_lower = text.lower()
        score = 0.0
        triggered_rules = []
        for kw in keyword_rows:
            if kw['keyword'].lower() in text_lower:
                score += float(kw['weight']) * 100
                triggered_rules.append(kw['keyword'])
        score      = min(round(score, 2), 99.99)
        ml_score   = None
        rule_score = round(score / 100, 4)

    result = 'SCAM' if score >= 50 else 'SAFE' if score < 25 else 'UNKNOWN'
    risk   = 'High' if score >= 75 else 'Medium' if score >= 50 else 'Low'
    duration_ms = int(time.time() * 1000) - start_ms

    scan_id = str(uuid.uuid4())
    cur.execute("""
        INSERT INTO scan_logs
            (scan_id, user_id, input_text, scan_type, result, confidence_score,
             risk_level, engine_version, ml_score, rule_score, triggered_rules, duration_ms)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (scan_id, user_id, text, scan_type, result, score, risk,
          'v2.0' if AI_AVAILABLE else 'v1.0',
          ml_score, rule_score,
          json.dumps(triggered_rules), duration_ms))

    cur.execute("""
        UPDATE users
        SET scan_count = scan_count + 1, scans_this_month = scans_this_month + 1
        WHERE user_id = %s
    """, (user_id,))
    mysql.connection.commit()
    cur.close()

    return jsonify({
        'scan_id':          scan_id,
        'result':           result,
        'confidence_score': score,
        'risk_level':       risk,
        'ml_score':         ml_score,
        'rule_score':       rule_score,
        'triggered_rules':  triggered_rules,
        'duration_ms':      duration_ms,
        'engine':           'AI+Rules' if AI_AVAILABLE else 'Rules only',
    }), 201


@app.route('/api/scans/<user_id>', methods=['GET'])
def get_scan_history(user_id):
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT scan_id, input_text, scan_type, result, confidence_score,
               risk_level, created_at
        FROM scan_logs WHERE user_id = %s ORDER BY created_at DESC LIMIT 50
    """, (user_id,))
    scans = cur.fetchall()
    cur.close()
    for s in scans:
        if s.get('created_at'):
            s['created_at'] = str(s['created_at'])
    return jsonify(scans), 200


# ================================================================
# REPORTS
# ================================================================

@app.route('/api/reports', methods=['POST'])
def submit_report():
    data     = request.get_json()
    user_id  = data.get('user_id')
    category = data.get('category')
    if not user_id or not category:
        return jsonify({'error': 'user_id and category required'}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(*) AS total FROM reports")
    count     = cur.fetchone()['total']
    report_id = f"RPT-{str(count + 1).zfill(4)}"

    cur.execute("""
        INSERT INTO reports
            (report_id, user_id, scan_id, category, risk_level,
             description, reported_number, reported_url, amount_lost, currency)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (report_id, user_id, data.get('scan_id'), category,
          data.get('risk_level', 'Medium'), data.get('description'),
          data.get('reported_number'), data.get('reported_url'),
          data.get('amount_lost'), data.get('currency', 'KES')))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Report submitted', 'report_id': report_id}), 201


@app.route('/api/reports/<user_id>', methods=['GET'])
def get_user_reports(user_id):
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT report_id, category, risk_level, status, created_at
        FROM reports WHERE user_id = %s ORDER BY created_at DESC
    """, (user_id,))
    reports = cur.fetchall()
    cur.close()
    for r in reports:
        if r.get('created_at'):
            r['created_at'] = str(r['created_at'])
    return jsonify(reports), 200


# ================================================================
# PLANS / NOTIFICATIONS / CONTACT
# ================================================================

@app.route('/api/plans', methods=['GET'])
def get_plans():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM subscription_plans WHERE is_active = 1 ORDER BY sort_order")
    plans = cur.fetchall()
    cur.close()
    return jsonify(plans), 200


@app.route('/api/notifications/<user_id>', methods=['GET'])
def get_notifications(user_id):
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT notif_id, type, title, body, is_read, created_at
        FROM notifications WHERE user_id = %s ORDER BY created_at DESC LIMIT 20
    """, (user_id,))
    notifs = cur.fetchall()
    cur.close()
    for n in notifs:
        if n.get('created_at'):
            n['created_at'] = str(n['created_at'])
    return jsonify(notifs), 200


@app.route('/api/contact', methods=['POST'])
def submit_contact():
    data = request.get_json()
    cur  = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO inbox_messages
            (user_id, type, category, from_name, from_email, from_phone, subject, body, priority)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (data.get('user_id'), data.get('type', 'contact'), data.get('category', 'General'),
          data.get('name'), data.get('email'), data.get('phone'),
          data.get('subject'), data.get('message'), data.get('priority', 'Normal')))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Message received'}), 201


# ================================================================
# ADMIN AUTH
# ================================================================

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data     = request.get_json()
    admin_id = data.get('admin_id', '')
    password = data.get('password', '')

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT * FROM admin_users
        WHERE (admin_code = %s OR email = %s)
    """, (admin_id.upper(), admin_id))
    admin = cur.fetchone()
    cur.close()

    if not admin:
        return jsonify({'error': 'Invalid credentials'}), 401

    # Support plain-text passwords for default admin seed account
    password_ok = (admin['password_hash'] == password)
    if not password_ok:
        try:
            password_ok = check_password_hash(admin['password_hash'], password)
        except Exception:
            pass

    if not password_ok:
        return jsonify({'error': 'Invalid credentials'}), 401
    if not admin['is_active']:
        return jsonify({'error': 'Account disabled'}), 403

    cur2 = mysql.connection.cursor()
    cur2.execute("""
        INSERT INTO audit_log (log_id, admin_id, admin_name, action, severity, ip_address)
        VALUES (%s, %s, %s, 'Admin login', 'info', %s)
    """, (str(uuid.uuid4()), admin['admin_id'], admin['name'], request.remote_addr))
    mysql.connection.commit()
    cur2.close()

    return jsonify({'message': 'Login successful', 'admin': {
        'admin_id':   admin['admin_id'],
        'admin_code': admin['admin_code'],
        'name':       admin['name'],
        'email':      admin['email'],
        'role':       admin['role'],
    }}), 200


# ================================================================
# ADMIN — LIVE STATS
# ================================================================

@app.route('/api/admin/stats', methods=['GET'])
def admin_stats():
    cur = mysql.connection.cursor()

    def q(sql, params=()):
        cur.execute(sql, params)
        row = cur.fetchone()
        return list(row.values())[0] if row else 0

    total_users       = q("SELECT COUNT(*) FROM users")
    total_scans       = q("SELECT COUNT(*) FROM scan_logs")
    total_scams       = q("SELECT COUNT(*) FROM scan_logs WHERE result = 'SCAM'")
    scans_today       = q("SELECT COUNT(*) FROM scan_logs WHERE DATE(created_at) = CURDATE()")
    total_reports     = q("SELECT COUNT(*) FROM reports")
    reports_pending   = q("SELECT COUNT(*) FROM reports WHERE status = 'Pending'")
    reports_review    = q("SELECT COUNT(*) FROM reports WHERE status = 'Under Review'")
    reports_resolved  = q("SELECT COUNT(*) FROM reports WHERE status = 'Resolved'")
    reports_dismissed = q("SELECT COUNT(*) FROM reports WHERE status = 'Dismissed'")
    active_threats    = q("SELECT COUNT(*) FROM threat_library WHERE status = 'Active'")
    new_threats       = q("SELECT COUNT(*) FROM threat_library WHERE status = 'New'")
    unread_messages   = q("SELECT COUNT(*) FROM inbox_messages WHERE is_unread = 1")
    urgent_messages   = q("SELECT COUNT(*) FROM inbox_messages WHERE priority = 'Urgent' AND is_unread = 1")
    total_messages    = q("SELECT COUNT(*) FROM inbox_messages")
    new_users_week    = q("SELECT COUNT(*) FROM users WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)")

    detection_rate = round((total_scams / total_scans * 100), 1) if total_scans > 0 else 0
    cur.close()

    return jsonify({
        'total_users':       total_users,
        'total_scans':       total_scans,
        'total_scams':       total_scams,
        'scans_today':       scans_today,
        'total_reports':     total_reports,
        'reports_pending':   reports_pending,
        'reports_review':    reports_review,
        'reports_resolved':  reports_resolved,
        'reports_dismissed': reports_dismissed,
        'active_threats':    active_threats,
        'new_threats':       new_threats,
        'unread_messages':   unread_messages,
        'urgent_messages':   urgent_messages,
        'total_messages':    total_messages,
        'new_users_week':    new_users_week,
        'detection_rate':    detection_rate,
    }), 200


# ================================================================
# ADMIN — USERS
# ================================================================

@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT user_id, name, email, role, status, scan_count, created_at
        FROM users ORDER BY created_at DESC LIMIT 200
    """)
    users = cur.fetchall()
    cur.close()
    for u in users:
        if u.get('created_at'):
            u['created_at'] = str(u['created_at'])
    return jsonify(users), 200


@app.route('/api/admin/users/<user_id>/suspend', methods=['PATCH'])
def suspend_user(user_id):
    data = request.get_json() or {}
    cur  = mysql.connection.cursor()
    cur.execute("UPDATE users SET status = 'suspended' WHERE user_id = %s", (user_id,))
    cur.execute("""
        INSERT INTO audit_log (log_id, admin_id, admin_name, action, target, severity)
        VALUES (%s, %s, 'Admin', 'User suspended', %s, 'warn')
    """, (str(uuid.uuid4()), data.get('admin_id', ''), user_id))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'User suspended'}), 200


@app.route('/api/admin/users/<user_id>/activate', methods=['PATCH'])
def activate_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET status = 'active' WHERE user_id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'User activated'}), 200


# ================================================================
# ADMIN — REPORTS
# ================================================================

@app.route('/api/admin/reports', methods=['GET'])
def admin_get_reports():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT r.report_id, u.name AS reporter, r.category, r.risk_level,
               r.status, r.description, r.created_at
        FROM reports r LEFT JOIN users u ON r.user_id = u.user_id
        ORDER BY r.created_at DESC LIMIT 200
    """)
    reports = cur.fetchall()
    cur.close()
    for r in reports:
        if r.get('created_at'):
            r['created_at'] = str(r['created_at'])
    return jsonify(reports), 200


@app.route('/api/admin/reports/<report_id>/resolve', methods=['PATCH'])
def resolve_report(report_id):
    data = request.get_json() or {}
    cur  = mysql.connection.cursor()
    cur.execute("""
        UPDATE reports SET status = 'Resolved', resolution_notes = %s
        WHERE report_id = %s
    """, (data.get('notes', ''), report_id))
    cur.execute("""
        INSERT INTO audit_log (log_id, admin_id, admin_name, action, target, severity)
        VALUES (%s, %s, 'Admin', 'Report resolved', %s, 'success')
    """, (str(uuid.uuid4()), data.get('admin_id', ''), report_id))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Report resolved'}), 200


@app.route('/api/admin/reports/<report_id>/dismiss', methods=['PATCH'])
def dismiss_report(report_id):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE reports SET status = 'Dismissed' WHERE report_id = %s", (report_id,))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Report dismissed'}), 200


# ================================================================
# ADMIN — SCAN LOGS
# ================================================================

@app.route('/api/admin/scans', methods=['GET'])
def admin_get_scans():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT s.scan_id, u.email AS user_email, s.scan_type, s.result,
               s.confidence_score, s.duration_ms, s.created_at
        FROM scan_logs s LEFT JOIN users u ON s.user_id = u.user_id
        ORDER BY s.created_at DESC LIMIT 200
    """)
    scans = cur.fetchall()
    cur.close()
    for s in scans:
        if s.get('created_at'):
            s['created_at'] = str(s['created_at'])
    return jsonify(scans), 200


# ================================================================
# ADMIN — THREATS
# ================================================================

@app.route('/api/admin/threats', methods=['GET'])
def admin_get_threats():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT threat_id, name, category, severity, report_count, status, updated_at
        FROM threat_library ORDER BY report_count DESC LIMIT 200
    """)
    threats = cur.fetchall()
    cur.close()
    for t in threats:
        if t.get('updated_at'):
            t['updated_at'] = str(t['updated_at'])
    return jsonify(threats), 200


# ================================================================
# ADMIN — INBOX
# ================================================================

@app.route('/api/admin/inbox', methods=['GET'])
def admin_get_inbox():
    status = request.args.get('status')
    cur    = mysql.connection.cursor()
    if status and status != 'all':
        cur.execute("""
            SELECT message_id, from_name, from_email, subject, body,
                   type, priority, status, is_unread, created_at
            FROM inbox_messages WHERE status = %s ORDER BY created_at DESC LIMIT 100
        """, (status,))
    else:
        cur.execute("""
            SELECT message_id, from_name, from_email, subject, body,
                   type, priority, status, is_unread, created_at
            FROM inbox_messages ORDER BY created_at DESC LIMIT 100
        """)
    messages = cur.fetchall()
    cur.close()
    for m in messages:
        if m.get('created_at'):
            m['created_at'] = str(m['created_at'])
    return jsonify(messages), 200


@app.route('/api/admin/inbox/<int:message_id>/resolve', methods=['PATCH'])
def resolve_message(message_id):
    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE inbox_messages SET status = 'Resolved', is_unread = 0
        WHERE message_id = %s
    """, (message_id,))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Resolved'}), 200


@app.route('/api/admin/inbox/<int:message_id>/read', methods=['PATCH'])
def mark_read(message_id):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE inbox_messages SET is_unread = 0 WHERE message_id = %s", (message_id,))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Marked read'}), 200


# ================================================================
# ADMIN — AUDIT LOG
# ================================================================

@app.route('/api/admin/audit', methods=['GET'])
def admin_get_audit():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT log_id, admin_name, action, target, severity, ip_address, created_at
        FROM audit_log ORDER BY created_at DESC LIMIT 200
    """)
    logs = cur.fetchall()
    cur.close()
    for l in logs:
        if l.get('created_at'):
            l['created_at'] = str(l['created_at'])
    return jsonify(logs), 200


# ================================================================
# ADMIN — KEYWORDS
# ================================================================

@app.route('/api/admin/keywords', methods=['GET'])
def admin_get_keywords():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT keyword_id, keyword, weight, category, is_active
        FROM banned_keywords ORDER BY weight DESC
    """)
    keywords = cur.fetchall()
    cur.close()
    return jsonify(keywords), 200


@app.route('/api/admin/keywords', methods=['POST'])
def admin_add_keyword():
    data    = request.get_json()
    keyword = data.get('keyword', '').strip()
    if not keyword:
        return jsonify({'error': 'keyword is required'}), 400
    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO banned_keywords (keyword_id, keyword, weight, category, is_active)
        VALUES (%s, %s, %s, %s, 1)
    """, (str(uuid.uuid4()), keyword,
          data.get('weight', 0.5), data.get('category')))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Keyword added'}), 201


if __name__ == '__main__':
    app.run(debug=True, port=5000)