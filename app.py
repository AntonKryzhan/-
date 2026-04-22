from flask import Flask, render_template, request, redirect, url_for, session, abort
import sqlite3
import os
import hmac
import secrets
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from threading import Timer

app = Flask(__name__)
app.secret_key = 'NgsNotebookReserve_2025_kJ7f4!p2@'
ADMIN_PASSWORD = '1221Ngs'

UTC_PLUS_3 = timezone(timedelta(hours=3))
DB_PATH = os.path.join(os.path.dirname(__file__), 'data.db')
MAX_INPUT_LENGTH = 50
ADMIN_LOCK_MINUTES = 15
ADMIN_MAX_FAILED_ATTEMPTS = 5


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        class TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT
    )
    """)

    cursor.execute("PRAGMA table_info(users)")
    cols = {row[1] for row in cursor.fetchall()}

    if 'session_token' not in cols:
        cursor.execute("ALTER TABLE users ADD COLUMN session_token TEXT")
    if 'client_ip' not in cols:
        cursor.execute("ALTER TABLE users ADD COLUMN client_ip TEXT")
    if 'hack_attempts' not in cols:
        cursor.execute("ALTER TABLE users ADD COLUMN hack_attempts INTEGER DEFAULT 0")
    if 'admin_attempts' not in cols:
        cursor.execute("ALTER TABLE users ADD COLUMN admin_attempts INTEGER DEFAULT 0")
    if 'public_id' not in cols:
        cursor.execute("ALTER TABLE users ADD COLUMN public_id TEXT")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS admin_login_protection(
        ip TEXT PRIMARY KEY,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT
    )
    """)

    cursor.execute("SELECT id FROM users WHERE public_id IS NULL OR TRIM(public_id) = ''")
    missing_public_ids = cursor.fetchall()
    for (user_id,) in missing_public_ids:
        cursor.execute(
            "UPDATE users SET public_id = ? WHERE id = ?",
            (uuid4().hex, user_id)
        )

    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_public_id ON users(public_id)")

    conn.commit()
    conn.close()


def format_dt(dt_str):
    if not dt_str:
        return ''
    try:
        dt = datetime.fromisoformat(dt_str)
        return dt.strftime('%d.%m.%Y %H:%M:%S')
    except ValueError:
        return dt_str


def build_public_sessions(rows):
    sessions = []
    for row in rows:
        user_id, public_id, first_name, last_name, class_name, start_time, end_time, client_ip = row
        sessions.append({
            'id': user_id,
            'public_id': public_id,
            'first_name': first_name,
            'last_name': last_name,
            'class': class_name,
            'start_time': format_dt(start_time),
            'end_time': format_dt(end_time) if end_time else '',
            'client_ip': client_ip or '',
        })
    return sessions


def get_csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_hex(32)
        session['_csrf_token'] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {'csrf_token': get_csrf_token}


def validate_csrf():
    session_token = session.get('_csrf_token', '')
    request_token = request.form.get('csrf_token', '')
    if not session_token or not request_token:
        abort(400)
    if not hmac.compare_digest(session_token, request_token):
        abort(400)


def now_local():
    return datetime.now(UTC_PLUS_3)


def get_client_ip():
    return request.remote_addr or ''


def is_locked_until_active(locked_until_str):
    if not locked_until_str:
        return False
    try:
        return datetime.fromisoformat(locked_until_str) > now_local()
    except ValueError:
        return False


def get_admin_lock_state(conn, client_ip):
    cursor = conn.cursor()
    cursor.execute(
        "SELECT failed_attempts, locked_until FROM admin_login_protection WHERE ip = ?",
        (client_ip,)
    )
    row = cursor.fetchone()
    if not row:
        return 0, None
    return row[0] or 0, row[1]


def register_admin_failed_attempt(conn, client_ip):
    cursor = conn.cursor()
    failed_attempts, locked_until = get_admin_lock_state(conn, client_ip)

    if is_locked_until_active(locked_until):
        return failed_attempts, locked_until

    failed_attempts += 1
    new_locked_until = None
    if failed_attempts >= ADMIN_MAX_FAILED_ATTEMPTS:
        new_locked_until = (now_local() + timedelta(minutes=ADMIN_LOCK_MINUTES)).isoformat()

    cursor.execute(
        """
        INSERT INTO admin_login_protection(ip, failed_attempts, locked_until)
        VALUES(?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            failed_attempts = excluded.failed_attempts,
            locked_until = excluded.locked_until
        """,
        (client_ip, failed_attempts, new_locked_until)
    )
    conn.commit()
    return failed_attempts, new_locked_until


def reset_admin_failed_attempts(conn, client_ip):
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO admin_login_protection(ip, failed_attempts, locked_until)
        VALUES(?, 0, NULL)
        ON CONFLICT(ip) DO UPDATE SET
            failed_attempts = 0,
            locked_until = NULL
        """,
        (client_ip,)
    )
    conn.commit()


def validate_length(value):
    return len(value) <= MAX_INPUT_LENGTH


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/reserve', methods=['GET', 'POST'])
def reserve():
    if request.method == 'POST':
        validate_csrf()

        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        class_name = request.form.get('class', '').strip()

        if not first_name or not last_name or not class_name:
            return render_template(
                'reserve.html',
                error='Пожалуйста, заполните все поля: имя, фамилию и класс.'
            )

        if not validate_length(first_name) or not validate_length(last_name) or not validate_length(class_name):
            return render_template(
                'reserve.html',
                error='Каждое поле должно быть не длиннее 50 символов.'
            )

        now = now_local().isoformat()
        session_token = uuid4().hex
        public_id = uuid4().hex
        client_ip = get_client_ip()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users(first_name, last_name, class, start_time, end_time, session_token, client_ip, public_id)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (first_name, last_name, class_name, now, None, session_token, client_ip, public_id)
        )
        conn.commit()
        conn.close()

        return redirect(url_for('index'))

    return render_template('reserve.html', error=None)


@app.route('/return')
def return_laptop():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, public_id, first_name, last_name, class, start_time, end_time, client_ip
        FROM users
        WHERE end_time IS NULL
        ORDER BY start_time DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    sessions = build_public_sessions(rows)
    return render_template('return.html', sessions=sessions)


@app.route('/return/<public_id>', methods=['POST'])
def return_session(public_id):
    validate_csrf()

    end_time = now_local().isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, end_time FROM users WHERE public_id = ?", (public_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        abort(404)

    if not row[1]:
        cursor.execute("UPDATE users SET end_time = ? WHERE public_id = ?", (end_time, public_id))
        conn.commit()

    conn.close()
    return redirect(url_for('return_laptop'))


@app.route('/finish/<session_token>')
def finish(session_token):
    return redirect(url_for('return_laptop'))


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get('is_admin'):
        client_ip = get_client_ip()
        conn = get_db_connection()

        failed_attempts, locked_until = get_admin_lock_state(conn, client_ip)
        if is_locked_until_active(locked_until):
            conn.close()
            try:
                unlock_time = datetime.fromisoformat(locked_until).strftime('%d.%m.%Y %H:%M:%S')
            except ValueError:
                unlock_time = locked_until
            return render_template(
                'admin_login.html',
                error=f'Вход временно заблокирован после 5 неудачных попыток. Попробуйте снова после {unlock_time}.'
            )

        if request.method == 'POST':
            validate_csrf()

            password = request.form.get('password', '')
            if password == ADMIN_PASSWORD:
                reset_admin_failed_attempts(conn, client_ip)
                conn.close()
                session['is_admin'] = True
                return redirect(url_for('admin'))

            failed_attempts, locked_until = register_admin_failed_attempt(conn, client_ip)

            cursor = conn.cursor()
            cursor.execute(
                "SELECT id FROM users WHERE client_ip = ? AND end_time IS NULL ORDER BY start_time DESC LIMIT 1",
                (client_ip,)
            )
            row = cursor.fetchone()
            if row:
                user_id = row[0]
                cursor.execute(
                    "UPDATE users SET admin_attempts = COALESCE(admin_attempts, 0) + 1 WHERE id = ?",
                    (user_id,)
                )
                conn.commit()

            conn.close()

            if locked_until:
                try:
                    unlock_time = datetime.fromisoformat(locked_until).strftime('%d.%m.%Y %H:%M:%S')
                except ValueError:
                    unlock_time = locked_until
                return render_template(
                    'admin_login.html',
                    error=f'После 5 неудачных попыток вход заблокирован до {unlock_time}.'
                )

            return render_template('admin_login.html', error='Неверный пароль')

        conn.close()
        return render_template('admin_login.html', error=None)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, public_id, first_name, last_name, class, start_time, end_time,
               client_ip, hack_attempts, admin_attempts
        FROM users
        ORDER BY start_time DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    sessions = []
    for row in rows:
        user_id, public_id, first_name, last_name, class_name, start_time, end_time, client_ip, hack_attempts, admin_attempts = row
        sessions.append({
            'id': user_id,
            'public_id': public_id,
            'first_name': first_name,
            'last_name': last_name,
            'class': class_name,
            'start_time': format_dt(start_time),
            'end_time': format_dt(end_time) if end_time else '',
            'client_ip': client_ip or '',
            'hack_attempts': hack_attempts or 0,
            'admin_attempts': admin_attempts or 0
        })

    return render_template('admin.html', sessions=sessions)


@app.route('/admin/end_session/<public_id>', methods=['POST'])
def admin_end_session(public_id):
    if not session.get('is_admin'):
        abort(403)

    validate_csrf()

    end_time = now_local().isoformat()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET end_time = ? WHERE public_id = ? AND end_time IS NULL", (end_time, public_id))
    conn.commit()
    conn.close()
    return redirect(url_for('admin'))


@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    if not session.get('is_admin'):
        abort(403)
    validate_csrf()
    session.pop('is_admin', None)
    return redirect(url_for('index'))


@app.route('/admin/restart', methods=['GET', 'POST'])
def admin_restart():
    if request.method == 'GET':
        return redirect(url_for('admin'))

    if not session.get('is_admin'):
        abort(403)

    validate_csrf()

    environ = request.environ

    def shutdown_later():
        func = environ.get('werkzeug.server.shutdown')
        if func is None:
            os._exit(0)
        func()

    Timer(1.0, shutdown_later).start()
    session.pop('is_admin', None)
    return redirect(url_for('index'))


@app.route('/end_session/<session_token>', methods=['POST'])
def end_session(session_token):
    validate_csrf()

    end_time = now_local().isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, end_time FROM users WHERE session_token = ?", (session_token,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return redirect(url_for('return_laptop'))

    user_id, current_end_time = row
    if not current_end_time:
        cursor.execute("UPDATE users SET end_time = ? WHERE id = ?", (end_time, user_id))
        conn.commit()

    conn.close()
    return redirect(url_for('return_laptop'))


init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False, threaded=True)
