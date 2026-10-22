import os
import re
from datetime import datetime, timezone

from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import Flask, abort, flash, redirect, render_template, request, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

# Environment: "development" on my laptop, "production" on the server
IS_PRODUCTION = os.environ.get("APP_ENV", "development") == "production"

# Settings come from the environment; defaults are for my laptop only
secret_key = os.environ.get("SECRET_KEY")
if IS_PRODUCTION and not secret_key:
    raise RuntimeError("SECRET_KEY must be set in production")
app.config["SECRET_KEY"] = secret_key or "dev-only-change-me"

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///securedesk.db"
)

# Session cookie protection (Secure flag needs HTTPS, so production only)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = IS_PRODUCTION

# Behind a load balancer / Nginx: read the real visitor address and protocol
proxy_count = int(os.environ.get("PROXY_COUNT", "0"))
if proxy_count:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=proxy_count, x_proto=proxy_count)

db = SQLAlchemy(app)
ph = PasswordHasher()
csrf = CSRFProtect(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per hour"],
    storage_uri="memory://",
)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to see that page."


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default="user")
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )

class Ticket(db.Model):
    __tablename__ = "tickets"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="open")
    priority = db.Column(db.String(10), nullable=False, default="medium")
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def admin_required(view):
    """Allow only admins. Use it below @login_required."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user.role != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped

@app.errorhandler(429)
def too_many_requests(error):
    return "Too many attempts. Please wait a few minutes and try again.", 429

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self'"
    )
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        error = None
        if not re.fullmatch(r"[A-Za-z0-9_]{3,50}", username):
            error = "Username must be 3-50 characters: letters, numbers, underscore."
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            error = "Enter a valid email address."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."

        if error is None:
            user = User(
                username=username,
                email=email,
                password_hash=ph.hash(password),
            )
            db.session.add(user)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                error = "That username or email is already registered."
            else:
                flash("Account created. You can now log in.")
                return redirect(url_for("login"))

        flash(error)

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
@limiter.limit(
    "5 per 15 minutes",
    methods=["POST"],
    key_func=lambda: request.form.get("username", "")[:50].lower(),
    deduct_when=lambda response: response.status_code != 302,
)
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user is not None:
            try:
                ph.verify(user.password_hash, password)
            except VerifyMismatchError:
                user = None

        if user is None:
            app.logger.warning(
                "Failed login for username %r from %s",
                username[:50],
                request.remote_addr,
            )
            # Same message for wrong username and wrong password
            flash("Invalid username or password.")
        else:
            login_user(user)
            return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for("home"))


@app.route("/dashboard")
@login_required
def dashboard():
    mine = Ticket.query.filter_by(user_id=current_user.id)
    counts = {
        "total": mine.count(),
        "open": mine.filter_by(status="open").count(),
        "closed": mine.filter_by(status="closed").count(),
    }
    recent = mine.order_by(Ticket.created_at.desc()).limit(5).all()
    return render_template("dashboard.html", counts=counts, recent=recent)

PRIORITIES = ("low", "medium", "high")

@app.route("/tickets")
@login_required
def tickets():
    my_tickets = (
        Ticket.query.filter_by(user_id=current_user.id)
        .order_by(Ticket.created_at.desc())
        .all()
    )
    return render_template("tickets.html", tickets=my_tickets)


@app.route("/tickets/new", methods=["GET", "POST"])
@login_required
def ticket_new():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        priority = request.form.get("priority", "medium")

        error = None
        if not 3 <= len(title) <= 100:
            error = "Title must be 3-100 characters."
        elif not 1 <= len(description) <= 2000:
            error = "Description must be 1-2000 characters."
        elif priority not in PRIORITIES:
            error = "Choose a valid priority."

        if error is None:
            ticket = Ticket(
                title=title,
                description=description,
                priority=priority,
                user_id=current_user.id,
            )
            db.session.add(ticket)
            db.session.commit()
            flash("Ticket created.")
            return redirect(url_for("ticket_detail", ticket_id=ticket.id))

        flash(error)

    return render_template("ticket_new.html")


@app.route("/tickets/<int:ticket_id>")
@login_required
def ticket_detail(ticket_id):
    ticket = db.session.get(Ticket, ticket_id)
    # Not found and "not yours" give the same answer, so ticket IDs can't be probed
    if ticket is None or ticket.user_id != current_user.id:
        abort(404)
    return render_template("ticket_detail.html", ticket=ticket)

def get_own_ticket(ticket_id):
    """Return the ticket only if it belongs to the logged-in user."""
    ticket = db.session.get(Ticket, ticket_id)
    if ticket is None or ticket.user_id != current_user.id:
        abort(404)
    return ticket


@app.route("/tickets/<int:ticket_id>/edit", methods=["GET", "POST"])
@login_required
def ticket_edit(ticket_id):
    ticket = get_own_ticket(ticket_id)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        priority = request.form.get("priority", "medium")

        error = None
        if not 3 <= len(title) <= 100:
            error = "Title must be 3-100 characters."
        elif not 1 <= len(description) <= 2000:
            error = "Description must be 1-2000 characters."
        elif priority not in PRIORITIES:
            error = "Choose a valid priority."

        if error is None:
            ticket.title = title
            ticket.description = description
            ticket.priority = priority
            db.session.commit()
            flash("Ticket updated.")
            return redirect(url_for("ticket_detail", ticket_id=ticket.id))

        flash(error)

    return render_template("ticket_edit.html", ticket=ticket)


@app.route("/tickets/<int:ticket_id>/close", methods=["POST"])
@login_required
def ticket_close(ticket_id):
    ticket = get_own_ticket(ticket_id)
    ticket.status = "closed"
    db.session.commit()
    flash("Ticket closed.")
    return redirect(url_for("ticket_detail", ticket_id=ticket.id))

@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    stats = {
        "users": User.query.count(),
        "tickets": Ticket.query.count(),
        "open": Ticket.query.filter_by(status="open").count(),
        "closed": Ticket.query.filter_by(status="closed").count(),
    }
    return render_template("admin_dashboard.html", stats=stats)


@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.id).all()
    return render_template("admin_users.html", users=users)


@app.route("/admin/tickets")
@login_required
@admin_required
def admin_tickets():
    rows = (
        db.session.query(Ticket, User)
        .join(User, Ticket.user_id == User.id)
        .order_by(Ticket.created_at.desc())
        .all()
    )
    return render_template("admin_tickets.html", rows=rows)

@app.route("/tickets/<int:ticket_id>/delete", methods=["POST"])
@login_required
def ticket_delete(ticket_id):
    ticket = get_own_ticket(ticket_id)
    db.session.delete(ticket)
    db.session.commit()
    flash("Ticket deleted.")
    return redirect(url_for("tickets"))
@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_user_delete(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)

    if user.id == current_user.id:
        flash("You cannot delete your own account.")
    elif user.role == "admin":
        flash("Admin accounts cannot be deleted here.")
    else:
        Ticket.query.filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()
        flash("User and their tickets deleted.")

    return redirect(url_for("admin_users"))


@app.route("/admin/tickets/<int:ticket_id>/close", methods=["POST"])
@login_required
@admin_required
def admin_ticket_close(ticket_id):
    ticket = db.session.get(Ticket, ticket_id)
    if ticket is None:
        abort(404)
    ticket.status = "closed"
    db.session.commit()
    flash("Ticket closed.")
    return redirect(url_for("admin_tickets"))


@app.route("/admin/tickets/<int:ticket_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_ticket_delete(ticket_id):
    ticket = db.session.get(Ticket, ticket_id)
    if ticket is None:
        abort(404)
    db.session.delete(ticket)
    db.session.commit()
    flash("Ticket deleted.")
    return redirect(url_for("admin_tickets"))

with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=not IS_PRODUCTION)