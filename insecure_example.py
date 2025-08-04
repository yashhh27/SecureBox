from flask import Flask, render_template, request
import sqlite3

app = Flask(__name__)
app.secret_key = 'this_is_very_insecure'

@app.route('/', methods=['GET', 'POST'])
def insecure_login():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # ❌ This is deliberately insecure!
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        try:
            with sqlite3.connect("database.db") as conn:
                cur = conn.cursor()
                cur.execute(query)
                user = cur.fetchone()
                if user:
                    return f"<h2>✅ Login bypassed!</h2><p>Welcome, {user[1]} (SQLi succeeded)</p>"
                else:
                    error = "❌ Invalid credentials (try SQL injection)"
        except Exception as e:
            error = str(e)

    return render_template("insecure_login.html", error=error)

if __name__ == '__main__':
    app.run(port=5001, debug=True)
