import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect('secure_users.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
''')

# Create a user
username = 'secureuser'
password = 'secure123'
hashed_password = generate_password_hash(password)

cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", (username, hashed_password))

conn.commit()
conn.close()

print("User created: secureuser / secure123")
