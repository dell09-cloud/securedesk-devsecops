import os
from datetime import datetime, timezone

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Database address comes from a setting; SQLite is the default on my laptop
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///securedesk.db"
)

db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default="user")
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )


@app.route("/")
def home():
    return "<h1>SecureDesk is running</h1>"


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)