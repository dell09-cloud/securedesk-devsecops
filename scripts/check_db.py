import sqlite3

conn = sqlite3.connect("instance/securedesk.db")
print(conn.execute("select name from sqlite_master").fetchall())