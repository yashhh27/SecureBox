from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import time
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'securebox_secret_key'

# --- In-memory brute-force tracking ---
login_attempts = {}
csrf_alerts = []
login_logs = {}

# --- Initialize DB if it doesn't exist ---
def init_db():
    if not os.path.exists('database.db'):
        with sqlite3.connect('database.db') as conn:
            conn.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user'
                )
            ''')

# --- DB Helper Functions ---
def get_user_by_username(username):
    with sqlite3.connect('database.db') as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cur.fetchone()

def insert_user(username, password_hash, role='user'):
    with sqlite3.connect('database.db') as conn:
        conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                     (username, password_hash, role))
        conn.commit()

# --- Routes ---
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = 'admin' if request.form.get('admin') else 'user'

        if get_user_by_username(username):
            flash("Username already exists", "danger")
            return redirect(url_for('register'))

        password_hash = generate_password_hash(password)
        insert_user(username, password_hash, role)
        flash("Registration successful. Please login.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = get_user_by_username(username)
        if user and check_password_hash(user[2], password):
            session['username'] = username
            session['role'] = user[3]
            session['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials", "danger")

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    return render_template('dashboard.html', 
                           username=session['username'], 
                           role=session['role'],
                           timestamp=session.get('timestamp'),
                           csrf_alerts=csrf_alerts)

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for('login'))

@app.route('/secure_login', methods=['GET', 'POST'])
def secure_login():
    global login_attempts
    error = None
    ip = request.remote_addr

    # Initialize login attempt tracking if IP not present
    if ip not in login_attempts:
        login_attempts[ip] = {'count': 0, 'lockout': False, 'timestamps': []}

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Update attempt count and add timestamp
        login_attempts[ip]['count'] += 1
        login_attempts[ip]['timestamps'].append(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        # Lockout logic
        if login_attempts[ip]['count'] >= 5:
            login_attempts[ip]['lockout'] = True

        if username == 'admin' and password == 'password123':
            return render_template('dashboard.html',
                                   username=username,
                                   role='admin',
                                   csrf_alerts=csrf_alerts,
                                   login_logs=login_attempts)
        else:
            error = 'Invalid credentials'

    return render_template('secure_login.html', error=error)

@app.route('/insecure_input', methods=['GET', 'POST'])
def insecure_input():
    comment = None
    if request.method == 'POST':
        comment = request.form['comment']
    return render_template('insecure_input.html', comment=comment)

@app.route('/secure_input', methods=['GET', 'POST'])
def secure_input():
    comment = None
    error = None
    if request.method == 'POST':
        comment = request.form['comment']
        if '<' in comment or '>' in comment:
            error = "HTML tags are not allowed!"
            comment = None
    return render_template('secure_input.html', comment=comment, error=error)

@app.route('/insecure_sql_login', methods=['GET', 'POST'])
def insecure_sql_login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        if "'" in username or "'" in password or 'OR' in username.upper() or 'OR' in password.upper():
            error = f"🔴 SQL Injection detected!<br><code>{query}</code>"
        elif username == "admin" and password == "admin123":
            return render_template('dashboard.html', username="admin", role="admin", csrf_alerts=csrf_alerts)
        else:
            error = f"Invalid credentials.<br><code>{query}</code>"

    return render_template('insecure_sql_login.html', error=error)

@app.route('/brute_force_login', methods=['GET', 'POST'])
def brute_force_login():
    ip = request.remote_addr
    error = None

    if ip not in login_attempts:
        login_attempts[ip] = {'count': 0, 'lockout': 0}

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        if login_attempts[ip]['count'] >= 5:
            error = "Too many failed attempts. Try again later."
        elif username == 'admin' and password == 'password123':
            login_attempts[ip] = {'count': 0, 'lockout': 0}
            session['username'] = username
            session['role'] = 'admin'
            return redirect(url_for('dashboard'))
        else:
            login_attempts[ip]['count'] += 1
            error = f"Login failed. Attempts left: {5 - login_attempts[ip]['count']}"

    return render_template('brute_force_login.html', error=error)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
