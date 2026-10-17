import sqlite3

conn = sqlite3.connect("instance/securedesk.db")
print(conn.execute("select username, role, password_hash from users").fetchall())