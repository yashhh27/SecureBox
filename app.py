from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'securebox_secret_key'

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
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials", "danger")

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'], role=session['role'])

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
