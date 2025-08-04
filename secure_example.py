from flask import Flask, render_template, request, flash
import sqlite3
from werkzeug.security import check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Replace in prod

DATABASE = 'secure_users.db'

# 🔒 Secure login logic
@app.route('/secure_login', methods=['GET', 'POST'])
def secure_login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Use parameterized query to prevent SQL Injection
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()

        if row and check_password_hash(row[0], password):
            return render_template("dashboard.html", username=username)
        else:
            error = 'Invalid username or password'

    return render_template("secure_login.html", error=error)

if __name__ == '__main__':
    app.run(debug=True)
