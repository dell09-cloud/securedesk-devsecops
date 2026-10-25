import os
import re
import uuid
from datetime import datetime, timezone
from functools import wraps

import boto3
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import (
    Flask,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
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
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
# Environment: "development" on my laptop, "production" on the server
IS_PRODUCTION = os.environ.get("APP_ENV", "development") == "production"

# Settings come from the environment; defaults are for my laptop only
secret_key = os.environ.get("SECRET_KEY")
if IS_PRODUCTION and not secret_key:
    raise RuntimeError("SECRET_KEY must be set in production")
app.config["SECRET_KEY"] = secret_key or "dev-only-change-me"

database_url = os.environ.get("DATABASE_URL")
if IS_PRODUCTION and not database_url:
    raise RuntimeError("DATABASE_URL must be set in production")
app.config["SQLALCHEMY_DATABASE_URI"] = database_url or "sqlite:///securedesk.db"

# Keep database connections healthy (RDS can close idle connections)
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 280,
}

# Session cookie protection (Secure flag needs HTTPS, so production only)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = IS_PRODUCTION

# Behind a load balancer / Nginx: read the real visitor address and protocol
proxy_count = int(os.environ.get("PROXY_COUNT", "0"))
if proxy_count:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=proxy_count, x_proto=proxy_count)

# File uploads
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB limit
MEDIA_BUCKET = os.environ.get("S3_MEDIA_BUCKET")
AWS_REGION = os.environ.get("AWS_REGION", "ap-south-1")
if IS_PRODUCTION and not MEDIA_BUCKET:
    raise RuntimeError("S3_MEDIA_BUCKET must be set in production")
UPLOAD_DIR = os.path.join(app.instance_path, "uploads")  # local testing only

# Allowed types: extension -> (content type, first bytes the file must start with)
ALLOWED_TYPES = {
    "png": ("image/png", b"\x89PNG\r\n\x1a\n"),
    "jpg": ("image/jpeg", b"\xff\xd8\xff"),
    "jpeg": ("image/jpeg", b"\xff\xd8\xff"),
    "pdf": ("application/pdf", b"%PDF-"),
    "txt": ("text/plain", None),
}
INLINE_TYPES = {"image/png", "image/jpeg"}

PRIORITIES = ("low", "medium", "high")

# ---------------------------------------------------------------------------
# Extensions
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Database models
# ---------------------------------------------------------------------------
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
    attachments = db.relationship(
        "Attachment", backref="ticket", cascade="all, delete-orphan"
    )


class Attachment(db.Model):
    __tablename__ = "attachments"

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("tickets.id"), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    stored_key = db.Column(db.String(255), unique=True, nullable=False)
    content_type = db.Column(db.String(100), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    uploaded_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )


# ---------------------------------------------------------------------------
# File storage helpers (S3 in production, a local folder while developing)
# ---------------------------------------------------------------------------
_s3_client = None


def s3():
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client("s3", region_name=AWS_REGION)
    return _s3_client


def validate_upload(file):
    """Check an uploaded file; return (name, extension, content type, bytes)."""
    filename = secure_filename(file.filename or "")
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_TYPES:
        raise ValueError("Allowed file types: png, jpg, pdf, txt.")
    data = file.read()
    if not data:
        raise ValueError("The file is empty.")
    content_type, signature = ALLOWED_TYPES[ext]
    if signature and not data.startswith(signature):
        raise ValueError("The file content does not match its type.")
    if ext == "txt" and b"\x00" in data:
        raise ValueError("The file content does not match its type.")
    return filename, ext, content_type, data


def store_file(key, data, content_type):
    if MEDIA_BUCKET:
        s3().put_object(
            Bucket=MEDIA_BUCKET, Key=key, Body=data, ContentType=content_type
        )
    else:
        path = os.path.join(UPLOAD_DIR, key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)


def load_file(key):
    if MEDIA_BUCKET:
        return s3().get_object(Bucket=MEDIA_BUCKET, Key=key)["Body"].read()
    with open(os.path.join(UPLOAD_DIR, key), "rb") as f:
        return f.read()


def remove_files(keys):
    for key in keys:
        try:
            if MEDIA_BUCKET:
                s3().delete_object(Bucket=MEDIA_BUCKET, Key=key)
            else:
                os.remove(os.path.join(UPLOAD_DIR, key))
        except Exception:
            app.logger.warning("Could not remove stored file %r", key)


# ---------------------------------------------------------------------------
# Login helpers
# ---------------------------------------------------------------------------
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


def get_own_ticket(ticket_id):
    """Return the ticket only if it belongs to the logged-in user."""
    ticket = db.session.get(Ticket, ticket_id)
    if ticket is None or ticket.user_id != current_user.id:
        abort(404)
    return ticket


# ---------------------------------------------------------------------------
# Error pages
# ---------------------------------------------------------------------------
def error_page(code, title, message, icon_name):
    page = render_template(
        "error.html", code=code, title=title, message=message, icon_name=icon_name
    )
    return page, code


@app.errorhandler(400)
def bad_request(error):
    return error_page(
        400,
        "Request not accepted",
        "Your session may have expired. Go back, reload the page, and try again.",
        "alert",
    )


@app.errorhandler(403)
def forbidden(error):
    return error_page(
        403, "Access denied", "You don't have permission to open this page.", "lock"
    )


@app.errorhandler(404)
def not_found(error):
    return error_page(
        404, "Page not found", "We couldn't find what you were looking for.", "compass"
    )


@app.errorhandler(413)
def too_large(error):
    return error_page(413, "File too large", "Attachments can be up to 5 MB.", "alert")


@app.errorhandler(429)
def too_many_requests(error):
    return error_page(
        429, "Too many attempts", "Please wait a few minutes and try again.", "alert"
    )


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Public and account pages
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Tickets
# ---------------------------------------------------------------------------
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
        upload = request.files.get("attachment")

        error = None
        file_info = None
        if not 3 <= len(title) <= 100:
            error = "Title must be 3-100 characters."
        elif not 1 <= len(description) <= 2000:
            error = "Description must be 1-2000 characters."
        elif priority not in PRIORITIES:
            error = "Choose a valid priority."
        elif upload and upload.filename:
            try:
                file_info = validate_upload(upload)
            except ValueError as exc:
                error = str(exc)

        if error is None:
            ticket = Ticket(
                title=title,
                description=description,
                priority=priority,
                user_id=current_user.id,
            )
            db.session.add(ticket)
            db.session.flush()  # gives the ticket its ID

            if file_info:
                filename, ext, content_type, data = file_info
                key = f"tickets/{ticket.id}/{uuid.uuid4().hex}.{ext}"
                try:
                    store_file(key, data, content_type)
                except Exception:
                    db.session.rollback()
                    app.logger.exception("Could not store attachment")
                    flash("The file could not be saved. Please try again.")
                    return render_template("ticket_new.html")
                db.session.add(
                    Attachment(
                        ticket_id=ticket.id,
                        original_name=filename,
                        stored_key=key,
                        content_type=content_type,
                        size=len(data),
                    )
                )

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


@app.route("/tickets/<int:ticket_id>/attachment")
@login_required
def ticket_attachment(ticket_id):
    ticket = db.session.get(Ticket, ticket_id)
    if ticket is None or not ticket.attachments:
        abort(404)
    if ticket.user_id != current_user.id and current_user.role != "admin":
        abort(404)

    attachment = ticket.attachments[0]
    try:
        data = load_file(attachment.stored_key)
    except Exception:
        app.logger.exception("Could not read stored file")
        abort(404)

    disposition = "inline" if attachment.content_type in INLINE_TYPES else "attachment"
    response = Response(data, mimetype=attachment.content_type)
    response.headers["Content-Disposition"] = (
        f'{disposition}; filename="{attachment.original_name}"'
    )
    response.headers["Cache-Control"] = "private, no-store"
    return response


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


@app.route("/tickets/<int:ticket_id>/delete", methods=["POST"])
@login_required
def ticket_delete(ticket_id):
    ticket = get_own_ticket(ticket_id)
    keys = [a.stored_key for a in ticket.attachments]
    db.session.delete(ticket)
    db.session.commit()
    remove_files(keys)
    flash("Ticket deleted.")
    return redirect(url_for("tickets"))


# ---------------------------------------------------------------------------
# Admin pages
# ---------------------------------------------------------------------------
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
        keys = []
        for t in Ticket.query.filter_by(user_id=user.id).all():
            keys += [a.stored_key for a in t.attachments]
            db.session.delete(t)
        db.session.delete(user)
        db.session.commit()
        remove_files(keys)
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
    keys = [a.stored_key for a in ticket.attachments]
    db.session.delete(ticket)
    db.session.commit()
    remove_files(keys)
    flash("Ticket deleted.")
    return redirect(url_for("admin_tickets"))


# ---------------------------------------------------------------------------
# Start-up
# ---------------------------------------------------------------------------
with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("APP_HOST", "127.0.0.1"),
        debug=not IS_PRODUCTION and os.environ.get("APP_HOST") is None,
    )