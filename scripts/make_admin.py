import os
import sys

from sqlalchemy import create_engine, text

if len(sys.argv) != 2:
    print("Usage: python scripts/make_admin.py USERNAME")
    sys.exit(1)

url = os.environ.get("DATABASE_URL", "sqlite:///instance/securedesk.db")
engine = create_engine(url)

with engine.begin() as conn:
    result = conn.execute(
        text("UPDATE users SET role = 'admin' WHERE username = :name"),
        {"name": sys.argv[1]},
    )

print("Done: user is now an admin." if result.rowcount else "No user with that name.")