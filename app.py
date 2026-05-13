"""
snickr – CS6083 Project 2
Flask web application backed by PostgreSQL.

Security measures:
  • SQL injection  → 100% parameterised queries / stored procedures (psycopg2 %s)
  • XSS            → Jinja2 auto-escaping on all templates (default in Flask)
  • CSRF           → Synchroniser token on every state-changing form
  • Passwords      → bcrypt (werkzeug.security)
  • Sessions       → server-side secret key, HttpOnly cookie
  • Concurrency    → stored procedures run inside transactions (psycopg2 autocommit=False)
"""

import os
import uuid
import functools
import secrets
import mimetypes
from contextlib import contextmanager
from pathlib import Path

import psycopg2
import psycopg2.extras
from flask import (Flask, g, session, request, redirect, url_for,
                   render_template, flash, abort, send_from_directory)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ── File upload config ──────────────────────────────────────────────────────
UPLOAD_FOLDER = Path(__file__).parent / "static" / "uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
MAX_FILE_BYTES = 10 * 1024 * 1024   # 10 MB hard limit
ALLOWED_EXTENSIONS = {
    # images
    "jpg", "jpeg", "png", "gif", "webp", "svg",
    # documents
    "pdf", "txt", "md",
    # data / code
    "csv", "json", "py", "js", "html", "css", "sql",
    # archives
    "zip",
}
IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp", "svg"}
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_BYTES

# ─────────────────────────────────────────
# Database helpers
# ─────────────────────────────────────────

def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(
            host=os.environ.get("DB_HOST", "localhost"),
            port=os.environ.get("DB_PORT", 5432),
            dbname=os.environ.get("DB_NAME", "snickr"),
            user=os.environ.get("DB_USER", "postgres"),
            password=os.environ.get("DB_PASSWORD", ""),
            cursor_factory=psycopg2.extras.RealDictCursor,
        )
        g.db.autocommit = False
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        if exc:
            db.rollback()
        db.close()


@contextmanager
def transaction():
    """Wrap a block in an explicit transaction with rollback on error."""
    db = get_db()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise


def query(sql, params=(), one=False):
    """Execute a SELECT and return rows as dicts."""
    db = get_db()
    with db.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def execute(sql, params=()):
    """Execute a DML statement inside the current transaction."""
    db = get_db()
    with db.cursor() as cur:
        cur.execute(sql, params)
        try:
            return cur.fetchone()
        except psycopg2.ProgrammingError:
            return None


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def is_image(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in IMAGE_EXTENSIONS

def save_upload(file_storage):
    """Validate, sanitize, and persist an uploaded file.
    Returns (stored_name, original_name, mime_type, size) or raises ValueError.
    """
    original_name = secure_filename(file_storage.filename)
    if not original_name:
        raise ValueError("No filename provided.")
    if not allowed_file(original_name):
        ext = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else "?"
        raise ValueError(f"File type '.{ext}' is not allowed.")

    # Read into memory to check size (werkzeug MAX_CONTENT_LENGTH handles the hard cap)
    data = file_storage.read()
    if len(data) == 0:
        raise ValueError("Uploaded file is empty.")

    ext = original_name.rsplit(".", 1)[1].lower()
    stored_name = f"{uuid.uuid4().hex}.{ext}"
    dest = UPLOAD_FOLDER / stored_name
    dest.write_bytes(data)

    mime_type = mimetypes.guess_type(original_name)[0] or "application/octet-stream"
    return stored_name, original_name, mime_type, len(data)


# ─────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────

def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def current_user():
    if "user_id" not in session:
        return None
    return query(
        "SELECT user_id, username, email, nickname, created_at FROM users WHERE user_id = %s",
        (session["user_id"],), one=True
    )


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


def check_csrf():
    token = request.form.get("_csrf_token")
    if not token or token != session.get("_csrf"):
        abort(403)


app.jinja_env.globals["csrf_token"] = csrf_token
app.jinja_env.globals["current_user"] = current_user


@app.before_request
def load_sidebar_data():
    """Inject sidebar workspaces, DM channels, and pending invitation count into g."""
    uid = session.get("user_id")
    if uid:
        g.sidebar_workspaces = query("""
            SELECT w.workspace_id, w.name
            FROM workspaces w
            JOIN workspace_members wm ON wm.workspace_id = w.workspace_id AND wm.user_id = %s
            ORDER BY w.name
        """, (uid,))

        # DM channels: for each direct channel the user is in, find the other person
        g.sidebar_dms = query("""
            SELECT c.channel_id, c.workspace_id,
                   u.username AS partner_username,
                   u.user_id  AS partner_id
            FROM channels c
            JOIN channel_members cm  ON cm.channel_id  = c.channel_id AND cm.user_id = %s
            JOIN channel_members cm2 ON cm2.channel_id = c.channel_id AND cm2.user_id != %s
            JOIN users u             ON u.user_id       = cm2.user_id
            WHERE c.channel_type = 'direct'
            ORDER BY c.channel_id DESC
        """, (uid, uid))

        row = query("""
            SELECT COUNT(*) AS n FROM channel_invitations
            WHERE invited_user_id = %s AND status = 'pending'
        """, (uid,), one=True)
        g.pending_channel_inv_count = row["n"] if row else 0

        row2 = query("""
            SELECT COUNT(*) AS n FROM workspace_invitations
            WHERE invited_user_id = %s AND status = 'pending'
        """, (uid,), one=True)
        g.pending_ws_inv_count = row2["n"] if row2 else 0

        g.pending_count = g.pending_channel_inv_count + g.pending_ws_inv_count


def mark_channel_read(channel_id, user_id):
    """Upsert the last-read timestamp for this user+channel."""
    with transaction():
        execute("""
            INSERT INTO channel_last_read(channel_id, user_id, last_read_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (channel_id, user_id)
            DO UPDATE SET last_read_at = NOW()
        """, (channel_id, user_id))


# ─────────────────────────────────────────
# Routes – Auth
# ─────────────────────────────────────────

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        check_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = query(
            "SELECT user_id, password_hash FROM users WHERE username = %s",
            (username,), one=True
        )
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["user_id"]
            session["username"] = username
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        check_csrf()
        username     = request.form.get("username", "").strip()
        email        = request.form.get("email", "").strip().lower()
        nickname     = request.form.get("nickname", "").strip() or None
        password     = request.form.get("password", "")
        confirm      = request.form.get("confirm", "")

        errors = []
        if len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        if len(password) < 6:
            errors.append("Password must be at least 6 characters.")
        if password != confirm:
            errors.append("Passwords do not match.")

        if not errors:
            try:
                pw_hash = generate_password_hash(password)
                with transaction():
                    row = execute(
                        "SELECT sp_register_user(%s, %s, %s, %s)",
                        (username, email, nickname, pw_hash)
                    )
                    user_id = row["sp_register_user"]
                session.clear()
                session["user_id"] = user_id
                session["username"] = username
                flash("Account created! Welcome to snickr.", "success")
                return redirect(url_for("dashboard"))
            except psycopg2.errors.UniqueViolation:
                flash("Username or email is already taken.", "danger")
            except Exception as e:
                flash(f"Registration failed: {e}", "danger")
        else:
            for e in errors:
                flash(e, "danger")

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You've been logged out.", "info")
    return redirect(url_for("login"))


# ─────────────────────────────────────────
# Routes – Dashboard
# ─────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    uid = session["user_id"]
    workspaces = query("""
        SELECT w.workspace_id, w.name, w.description, w.created_at,
               wm.is_admin,
               (SELECT COUNT(*) FROM workspace_members WHERE workspace_id = w.workspace_id) AS member_count,
               (SELECT COUNT(*) FROM channels WHERE workspace_id = w.workspace_id) AS channel_count
        FROM workspaces w
        JOIN workspace_members wm ON wm.workspace_id = w.workspace_id AND wm.user_id = %s
        ORDER BY w.name
    """, (uid,))

    ch_pending = query("""
        SELECT COUNT(*) AS n FROM channel_invitations
        WHERE invited_user_id = %s AND status = 'pending'
    """, (uid,), one=True)["n"]
    ws_pending = query("""
        SELECT COUNT(*) AS n FROM workspace_invitations
        WHERE invited_user_id = %s AND status = 'pending'
    """, (uid,), one=True)["n"]
    pending_count = ch_pending + ws_pending

    return render_template("dashboard.html",
                           workspaces=workspaces,
                           pending_count=pending_count)


# ─────────────────────────────────────────
# Routes – Workspaces
# ─────────────────────────────────────────

@app.route("/workspace/new", methods=["GET", "POST"])
@login_required
def new_workspace():
    if request.method == "POST":
        check_csrf()
        name = request.form.get("name", "").strip()
        desc = request.form.get("description", "").strip()
        if not name:
            flash("Workspace name is required.", "danger")
        else:
            try:
                with transaction():
                    row = execute(
                        "SELECT sp_create_workspace(%s, %s, %s)",
                        (name, desc, session["user_id"])
                    )
                    ws_id = row["sp_create_workspace"]
                flash(f"Workspace '{name}' created!", "success")
                return redirect(url_for("workspace", ws_id=ws_id))
            except Exception as e:
                flash(f"Could not create workspace: {e}", "danger")
    return render_template("new_workspace.html")


@app.route("/workspace/<int:ws_id>")
@login_required
def workspace(ws_id):
    uid = session["user_id"]

    membership = query("""
        SELECT is_admin FROM workspace_members
        WHERE workspace_id = %s AND user_id = %s
    """, (ws_id, uid), one=True)
    if not membership:
        abort(403)

    ws = query("SELECT * FROM workspaces WHERE workspace_id = %s", (ws_id,), one=True)
    if not ws:
        abort(404)

    channels = query("""
        SELECT c.channel_id, c.name, c.description, c.channel_type, c.created_at,
               (cm.user_id IS NOT NULL) AS is_member,
               (SELECT COUNT(*) FROM messages WHERE channel_id = c.channel_id) AS msg_count
        FROM channels c
        LEFT JOIN channel_members cm ON cm.channel_id = c.channel_id AND cm.user_id = %s
        WHERE c.workspace_id = %s
        ORDER BY c.name
    """, (uid, ws_id))

    # Unread counts: messages newer than last_read_at, excluding own messages
    unread_rows = query("""
        SELECT c.channel_id,
               COUNT(m.message_id) AS unread_count
        FROM channels c
        JOIN channel_members cm  ON cm.channel_id = c.channel_id AND cm.user_id = %s
        LEFT JOIN channel_last_read clr
               ON clr.channel_id = c.channel_id AND clr.user_id = %s
        LEFT JOIN messages m
               ON m.channel_id = c.channel_id
              AND m.user_id   != %s
              AND m.created_at > COALESCE(clr.last_read_at, '1970-01-01'::timestamptz)
        WHERE c.workspace_id = %s
        GROUP BY c.channel_id
    """, (uid, uid, uid, ws_id))
    unread = {r["channel_id"]: r["unread_count"] for r in unread_rows}

    members = query("""
        SELECT u.user_id, u.username, u.nickname, wm.is_admin, wm.joined_at
        FROM workspace_members wm
        JOIN users u ON u.user_id = wm.user_id
        WHERE wm.workspace_id = %s
        ORDER BY u.username
    """, (ws_id,))

    # Set of user_ids the current user already has a DM with in this workspace
    dm_rows = query("""
        SELECT cm2.user_id AS partner_id
        FROM channels c
        JOIN channel_members cm  ON cm.channel_id  = c.channel_id AND cm.user_id = %s
        JOIN channel_members cm2 ON cm2.channel_id = c.channel_id AND cm2.user_id != %s
        WHERE c.workspace_id = %s AND c.channel_type = 'direct'
    """, (uid, uid, ws_id))
    existing_dms = {r["partner_id"] for r in dm_rows}

    is_owner = (ws["created_by"] == uid)

    return render_template("workspace.html",
                           ws=ws, channels=channels, members=members,
                           is_admin=membership["is_admin"], is_owner=is_owner,
                           unread=unread, existing_dms=existing_dms)


@app.route("/workspace/<int:ws_id>/join_channel/<int:ch_id>", methods=["POST"])
@login_required
def join_channel(ws_id, ch_id):
    check_csrf()
    uid = session["user_id"]
    # Verify channel belongs to workspace and is public
    ch = query("""
        SELECT channel_type FROM channels
        WHERE channel_id = %s AND workspace_id = %s
    """, (ch_id, ws_id), one=True)
    if not ch:
        abort(404)
    if ch["channel_type"] != "public":
        flash("You need an invitation to join private channels.", "warning")
        return redirect(url_for("workspace", ws_id=ws_id))
    # Verify user is a workspace member
    if not query("SELECT 1 FROM workspace_members WHERE workspace_id=%s AND user_id=%s",
                 (ws_id, uid), one=True):
        abort(403)
    try:
        with transaction():
            execute("""
                INSERT INTO channel_members(channel_id, user_id)
                VALUES (%s, %s) ON CONFLICT DO NOTHING
            """, (ch_id, uid))
        flash("Joined channel!", "success")
    except Exception as e:
        flash(str(e), "danger")
    return redirect(url_for("workspace", ws_id=ws_id))


@app.route("/workspace/<int:ws_id>/new_channel", methods=["GET", "POST"])
@login_required
def new_channel(ws_id):
    uid = session["user_id"]
    membership = query("""
        SELECT is_admin FROM workspace_members
        WHERE workspace_id = %s AND user_id = %s
    """, (ws_id, uid), one=True)
    if not membership:
        abort(403)

    ws = query("SELECT name FROM workspaces WHERE workspace_id = %s", (ws_id,), one=True)

    if request.method == "POST":
        check_csrf()
        name    = request.form.get("name", "").strip().lower().replace(" ", "-")
        desc    = request.form.get("description", "").strip()
        ch_type = request.form.get("channel_type", "public")
        if ch_type not in ("public", "private"):
            ch_type = "public"
        if not name:
            flash("Channel name is required.", "danger")
        else:
            try:
                with transaction():
                    row = execute("""
                        INSERT INTO channels(workspace_id, name, description, channel_type, created_by)
                        VALUES (%s, %s, %s, %s, %s)
                        RETURNING channel_id
                    """, (ws_id, name, desc, ch_type, uid))
                    ch_id = row["channel_id"]
                    # Creator auto-joins
                    execute("INSERT INTO channel_members(channel_id, user_id) VALUES (%s, %s)",
                            (ch_id, uid))
                flash(f"Channel #{name} created!", "success")
                return redirect(url_for("channel", ws_id=ws_id, ch_id=ch_id))
            except psycopg2.errors.UniqueViolation:
                flash("A channel with that name already exists.", "danger")
            except Exception as e:
                flash(str(e), "danger")

    return render_template("new_channel.html", ws=ws, ws_id=ws_id)


# ─────────────────────────────────────────
# Routes – Direct Messages
# ─────────────────────────────────────────

@app.route("/workspace/<int:ws_id>/dm/<int:target_uid>", methods=["POST"])
@login_required
def start_dm(ws_id, target_uid):
    check_csrf()
    uid = session["user_id"]

    if uid == target_uid:
        flash("You can't DM yourself.", "warning")
        return redirect(url_for("workspace", ws_id=ws_id))

    # Both must be workspace members
    if not query("SELECT 1 FROM workspace_members WHERE workspace_id=%s AND user_id=%s",
                 (ws_id, uid), one=True):
        abort(403)
    if not query("SELECT 1 FROM workspace_members WHERE workspace_id=%s AND user_id=%s",
                 (ws_id, target_uid), one=True):
        abort(403)

    # Check if a 2-member direct channel already exists between these two users
    existing = query("""
        SELECT c.channel_id
        FROM channels c
        JOIN channel_members cm1 ON cm1.channel_id = c.channel_id AND cm1.user_id = %s
        JOIN channel_members cm2 ON cm2.channel_id = c.channel_id AND cm2.user_id = %s
        WHERE c.workspace_id = %s
          AND c.channel_type = 'direct'
          AND (SELECT COUNT(*) FROM channel_members WHERE channel_id = c.channel_id) = 2
        LIMIT 1
    """, (uid, target_uid, ws_id), one=True)

    if existing:
        return redirect(url_for("channel", ws_id=ws_id, ch_id=existing["channel_id"]))

    # Build a deterministic channel name so alice→bob and bob→alice share one channel
    target = query("SELECT username FROM users WHERE user_id=%s", (target_uid,), one=True)
    if not target:
        abort(404)
    me = session["username"]
    dm_name = f"dm-{min(me, target['username'])}-{max(me, target['username'])}"

    try:
        with transaction():
            row = execute("""
                INSERT INTO channels(workspace_id, name, channel_type, created_by)
                VALUES (%s, %s, 'direct', %s)
                RETURNING channel_id
            """, (ws_id, dm_name, uid))
            ch_id = row["channel_id"]
            execute("INSERT INTO channel_members(channel_id, user_id) VALUES (%s,%s)", (ch_id, uid))
            execute("INSERT INTO channel_members(channel_id, user_id) VALUES (%s,%s)", (ch_id, target_uid))
        return redirect(url_for("channel", ws_id=ws_id, ch_id=ch_id))
    except psycopg2.errors.UniqueViolation:
        # Race condition — DM was created simultaneously; find and redirect to it
        existing = query("""
            SELECT c.channel_id
            FROM channels c
            JOIN channel_members cm1 ON cm1.channel_id = c.channel_id AND cm1.user_id = %s
            JOIN channel_members cm2 ON cm2.channel_id = c.channel_id AND cm2.user_id = %s
            WHERE c.workspace_id = %s AND c.channel_type = 'direct'
            LIMIT 1
        """, (uid, target_uid, ws_id), one=True)
        if existing:
            return redirect(url_for("channel", ws_id=ws_id, ch_id=existing["channel_id"]))
        flash("Could not create DM channel.", "danger")
        return redirect(url_for("workspace", ws_id=ws_id))

@app.route("/workspace/<int:ws_id>/channel/<int:ch_id>", methods=["GET", "POST"])
@login_required
def channel(ws_id, ch_id):
    uid = session["user_id"]

    # Verify workspace membership
    if not query("SELECT 1 FROM workspace_members WHERE workspace_id=%s AND user_id=%s",
                 (ws_id, uid), one=True):
        abort(403)

    ch = query("""
        SELECT c.*, w.name AS workspace_name
        FROM channels c JOIN workspaces w ON w.workspace_id = c.workspace_id
        WHERE c.channel_id = %s AND c.workspace_id = %s
    """, (ch_id, ws_id), one=True)
    if not ch:
        abort(404)

    is_member = bool(query("SELECT 1 FROM channel_members WHERE channel_id=%s AND user_id=%s",
                           (ch_id, uid), one=True))

    if ch["channel_type"] == "private" and not is_member:
        abort(403)

    if request.method == "POST" and is_member:
        check_csrf()
        content = request.form.get("content", "").strip()
        file    = request.files.get("attachment")

        # A message needs at least text OR a file
        has_file = file and file.filename
        if not content and not has_file:
            flash("Message cannot be empty.", "warning")
        else:
            # If only a file with no text, use filename as placeholder content
            if not content and has_file:
                content = f"📎 {secure_filename(file.filename)}"
            try:
                with transaction():
                    row = execute("SELECT sp_post_message(%s, %s, %s)",
                                  (ch_id, uid, content))
                    msg_id = row["sp_post_message"]

                    if has_file:
                        stored, original, mime, size = save_upload(file)
                        execute("""
                            INSERT INTO message_attachments
                                (message_id, original_name, stored_name, mime_type, file_size_bytes)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (msg_id, original, stored, mime, size))

                return redirect(url_for("channel", ws_id=ws_id, ch_id=ch_id))
            except ValueError as e:
                flash(str(e), "danger")
            except Exception as e:
                flash(str(e), "danger")

    messages = query("""
        SELECT m.message_id, m.content, m.created_at, m.edited_at,
               u.user_id, u.username
        FROM messages m
        JOIN users u ON u.user_id = m.user_id
        WHERE m.channel_id = %s
        ORDER BY m.created_at ASC
        LIMIT 200
    """, (ch_id,))

    # Load attachments keyed by message_id
    if messages:
        msg_ids = [m["message_id"] for m in messages]
        att_rows = query("""
            SELECT message_id, attachment_id, original_name, stored_name,
                   mime_type, file_size_bytes
            FROM message_attachments
            WHERE message_id = ANY(%s)
        """, (msg_ids,))
        attachments = {r["message_id"]: r for r in att_rows}
    else:
        attachments = {}

    # Reactions grouped by message: {msg_id: [{emoji, count, reacted_by_me}]}
    if messages:
        msg_ids = [m["message_id"] for m in messages]
        reaction_rows = query("""
            SELECT message_id, emoji,
                   COUNT(*)            AS count,
                   bool_or(user_id = %s) AS reacted_by_me
            FROM message_reactions
            WHERE message_id = ANY(%s)
            GROUP BY message_id, emoji
            ORDER BY count DESC
        """, (uid, msg_ids))
        reactions = {}
        for r in reaction_rows:
            reactions.setdefault(r["message_id"], []).append(r)
    else:
        reactions = {}

    # Pinned messages for this channel
    pinned = query("""
        SELECT m.message_id, m.content, m.created_at,
               u.username, pm.pinned_at, pu.username AS pinned_by_name
        FROM pinned_messages pm
        JOIN messages m ON m.message_id = pm.message_id
        JOIN users u    ON u.user_id    = m.user_id
        JOIN users pu   ON pu.user_id   = pm.pinned_by
        WHERE pm.channel_id = %s
        ORDER BY pm.pinned_at DESC
    """, (ch_id,))

    pinned_ids = {p["message_id"] for p in pinned}

    # Mark channel as read for this user
    if is_member:
        mark_channel_read(ch_id, uid)

    # Members list for invite modal
    ws_members = query("""
        SELECT u.user_id, u.username
        FROM workspace_members wm JOIN users u ON u.user_id = wm.user_id
        WHERE wm.workspace_id = %s
          AND u.user_id NOT IN (
              SELECT user_id FROM channel_members WHERE channel_id = %s
          )
          AND u.user_id NOT IN (
              SELECT invited_user_id FROM channel_invitations
              WHERE channel_id = %s AND status = 'pending'
          )
        ORDER BY u.username
    """, (ws_id, ch_id, ch_id))

    # For DM channels: find the other person's username for the topbar
    dm_partner = None
    if ch["channel_type"] == "direct":
        partner_row = query("""
            SELECT u.username, u.user_id
            FROM channel_members cm
            JOIN users u ON u.user_id = cm.user_id
            WHERE cm.channel_id = %s AND cm.user_id != %s
            LIMIT 1
        """, (ch_id, uid), one=True)
        dm_partner = partner_row

    return render_template("channel.html",
                           ch=ch, messages=messages, is_member=is_member,
                           ws_id=ws_id, ws_members=ws_members,
                           reactions=reactions, pinned=pinned,
                           pinned_ids=pinned_ids,
                           attachments=attachments,
                           dm_partner=dm_partner)


@app.route("/workspace/<int:ws_id>/channel/<int:ch_id>/message/<int:msg_id>/delete",
           methods=["POST"])
@login_required
def delete_message(ws_id, ch_id, msg_id):
    check_csrf()
    uid = session["user_id"]
    msg = query("SELECT user_id FROM messages WHERE message_id=%s AND channel_id=%s",
                (msg_id, ch_id), one=True)
    if not msg:
        abort(404)
    if msg["user_id"] != uid:
        # Allow workspace admin too
        is_admin = query("""
            SELECT 1 FROM workspace_members WHERE workspace_id=%s AND user_id=%s AND is_admin
        """, (ws_id, uid), one=True)
        if not is_admin:
            abort(403)
    with transaction():
        execute("DELETE FROM messages WHERE message_id=%s", (msg_id,))
    return redirect(url_for("channel", ws_id=ws_id, ch_id=ch_id))


@app.route("/workspace/<int:ws_id>/channel/<int:ch_id>/message/<int:msg_id>/edit",
           methods=["POST"])
@login_required
def edit_message(ws_id, ch_id, msg_id):
    check_csrf()
    uid = session["user_id"]
    msg = query("SELECT user_id FROM messages WHERE message_id=%s AND channel_id=%s",
                (msg_id, ch_id), one=True)
    if not msg or msg["user_id"] != uid:
        abort(403)
    content = request.form.get("content", "").strip()
    if content:
        with transaction():
            execute("""
                UPDATE messages SET content=%s, edited_at=NOW()
                WHERE message_id=%s
            """, (content, msg_id))
    return redirect(url_for("channel", ws_id=ws_id, ch_id=ch_id))


# ─────────────────────────────────────────
# Routes – Invitations
# ─────────────────────────────────────────

@app.route("/workspace/<int:ws_id>/channel/<int:ch_id>/invite", methods=["POST"])
@login_required
def invite_user(ws_id, ch_id):
    check_csrf()
    uid = session["user_id"]
    invited_uid = request.form.get("invited_user_id", type=int)
    if not invited_uid:
        flash("Please select a user to invite.", "warning")
        return redirect(url_for("channel", ws_id=ws_id, ch_id=ch_id))
    try:
        with transaction():
            execute("""
                INSERT INTO channel_invitations(channel_id, invited_by, invited_user_id)
                VALUES (%s, %s, %s)
            """, (ch_id, uid, invited_uid))
        flash("Invitation sent!", "success")
    except psycopg2.errors.UniqueViolation:
        flash("That user already has a pending invitation.", "warning")
    except Exception as e:
        flash(str(e), "danger")
    return redirect(url_for("channel", ws_id=ws_id, ch_id=ch_id))


@app.route("/invitations")
@login_required
def invitations():
    uid = session["user_id"]
    invites = query("""
        SELECT ci.invitation_id, ci.status, ci.created_at,
               c.name AS channel_name, c.channel_id, c.channel_type,
               w.workspace_id, w.name AS workspace_name,
               u.username AS invited_by_name
        FROM channel_invitations ci
        JOIN channels c     ON c.channel_id     = ci.channel_id
        JOIN workspaces w   ON w.workspace_id   = c.workspace_id
        JOIN users u        ON u.user_id        = ci.invited_by
        WHERE ci.invited_user_id = %s
        ORDER BY ci.created_at DESC
    """, (uid,))
    return render_template("invitations.html", invites=invites)


@app.route("/invitations/<int:inv_id>/respond", methods=["POST"])
@login_required
def respond_invitation(inv_id):
    check_csrf()
    uid    = session["user_id"]
    accept = request.form.get("action") == "accept"
    try:
        with transaction():
            execute("SELECT sp_respond_invitation(%s, %s, %s)", (inv_id, uid, accept))
        flash("Accepted!" if accept else "Declined.", "success" if accept else "info")
    except Exception as e:
        flash(str(e), "danger")
    return redirect(url_for("invitations"))


# ─────────────────────────────────────────
# Routes – Search
# ─────────────────────────────────────────

@app.route("/search")
@login_required
def search():
    q      = request.args.get("q", "").strip()
    ws_id  = request.args.get("ws_id", None, type=int)
    results = []
    workspaces = query("""
        SELECT w.workspace_id, w.name FROM workspaces w
        JOIN workspace_members wm ON wm.workspace_id = w.workspace_id AND wm.user_id = %s
        ORDER BY w.name
    """, (session["user_id"],))

    if q:
        results = query(
            "SELECT * FROM sp_search_messages(%s, %s, %s)",
            (session["user_id"], q, ws_id)
        )
    return render_template("search.html", q=q, results=results,
                           workspaces=workspaces, selected_ws=ws_id)


# ─────────────────────────────────────────
# Routes – Profile
# ─────────────────────────────────────────

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    uid = session["user_id"]
    if request.method == "POST":
        check_csrf()
        nickname = request.form.get("nickname", "").strip() or None
        email    = request.form.get("email", "").strip().lower()
        if not email:
            flash("Email is required.", "danger")
        else:
            try:
                with transaction():
                    execute("""
                        UPDATE users SET nickname = %s, email = %s
                        WHERE user_id = %s
                    """, (nickname, email, uid))
                flash("Profile updated!", "success")
            except psycopg2.errors.UniqueViolation:
                flash("That email is already taken.", "danger")
            except Exception as e:
                flash(f"Update failed: {e}", "danger")
    user = current_user()
    return render_template("profile.html", user=user)


# ─────────────────────────────────────────
# Routes – Workspace: invite member
# ─────────────────────────────────────────

@app.route("/workspace/<int:ws_id>/invite_member", methods=["POST"])
@login_required
def invite_workspace_member(ws_id):
    """Admin sends a workspace invitation to a user by username."""
    check_csrf()
    uid = session["user_id"]
    # Only admins
    if not query("SELECT 1 FROM workspace_members WHERE workspace_id=%s AND user_id=%s AND is_admin",
                 (ws_id, uid), one=True):
        abort(403)
    username = request.form.get("username", "").strip()
    user = query("SELECT user_id FROM users WHERE username=%s", (username,), one=True)
    if not user:
        flash(f"User '{username}' not found.", "danger")
        return redirect(url_for("workspace", ws_id=ws_id))
    if user["user_id"] == uid:
        flash("You can't invite yourself.", "warning")
        return redirect(url_for("workspace", ws_id=ws_id))
    # Check if already a member
    if query("SELECT 1 FROM workspace_members WHERE workspace_id=%s AND user_id=%s",
             (ws_id, user["user_id"]), one=True):
        flash(f"{username} is already a member of this workspace.", "warning")
        return redirect(url_for("workspace", ws_id=ws_id))
    try:
        with transaction():
            execute("""
                INSERT INTO workspace_invitations(workspace_id, invited_by, invited_user_id)
                VALUES (%s, %s, %s)
            """, (ws_id, uid, user["user_id"]))
        flash(f"Invitation sent to {username}!", "success")
    except psycopg2.errors.UniqueViolation:
        flash(f"{username} already has a pending invitation.", "warning")
    except Exception as e:
        flash(str(e), "danger")
    return redirect(url_for("workspace", ws_id=ws_id))


# ─────────────────────────────────────────
# Routes – Workspace invitations (list + respond)
# ─────────────────────────────────────────

@app.route("/workspace_invitations")
@login_required
def workspace_invitations():
    uid = session["user_id"]
    invites = query("""
        SELECT wi.invitation_id, wi.status, wi.created_at,
               w.workspace_id, w.name AS workspace_name, w.description,
               u.username AS invited_by_name
        FROM workspace_invitations wi
        JOIN workspaces w ON w.workspace_id = wi.workspace_id
        JOIN users u      ON u.user_id      = wi.invited_by
        WHERE wi.invited_user_id = %s
        ORDER BY wi.created_at DESC
    """, (uid,))
    return render_template("workspace_invitations.html", invites=invites)


@app.route("/workspace_invitations/<int:inv_id>/respond", methods=["POST"])
@login_required
def respond_workspace_invitation(inv_id):
    check_csrf()
    uid    = session["user_id"]
    accept = request.form.get("action") == "accept"
    try:
        with transaction():
            execute("SELECT sp_respond_workspace_invitation(%s, %s, %s)",
                    (inv_id, uid, accept))
        flash("Workspace joined!" if accept else "Invitation declined.", "success" if accept else "info")
    except Exception as e:
        flash(str(e), "danger")
    return redirect(url_for("workspace_invitations"))


# ─────────────────────────────────────────
# Routes – Workspace: remove member
# ─────────────────────────────────────────

@app.route("/workspace/<int:ws_id>/remove_member/<int:target_uid>", methods=["POST"])
@login_required
def remove_workspace_member(ws_id, target_uid):
    """Admin removes a non-admin member from the workspace."""
    check_csrf()
    uid = session["user_id"]
    # Only admins
    if not query("SELECT 1 FROM workspace_members WHERE workspace_id=%s AND user_id=%s AND is_admin",
                 (ws_id, uid), one=True):
        abort(403)
    # Cannot remove yourself
    if target_uid == uid:
        flash("You cannot remove yourself.", "warning")
        return redirect(url_for("workspace", ws_id=ws_id))
    # Cannot remove another admin
    target_membership = query("""
        SELECT is_admin FROM workspace_members
        WHERE workspace_id=%s AND user_id=%s
    """, (ws_id, target_uid), one=True)
    if not target_membership:
        flash("User is not a member of this workspace.", "warning")
        return redirect(url_for("workspace", ws_id=ws_id))
    if target_membership["is_admin"]:
        flash("Cannot remove an admin. Demote them first.", "warning")
        return redirect(url_for("workspace", ws_id=ws_id))
    try:
        with transaction():
            # Remove from all channels in this workspace
            execute("""
                DELETE FROM channel_members
                WHERE user_id = %s AND channel_id IN (
                    SELECT channel_id FROM channels WHERE workspace_id = %s
                )
            """, (target_uid, ws_id))
            # Remove from workspace
            execute("""
                DELETE FROM workspace_members
                WHERE workspace_id = %s AND user_id = %s
            """, (ws_id, target_uid))
        target = query("SELECT username FROM users WHERE user_id=%s", (target_uid,), one=True)
        flash(f"Removed {target['username']} from the workspace.", "success")
    except Exception as e:
        flash(str(e), "danger")
    return redirect(url_for("workspace", ws_id=ws_id))


# ─────────────────────────────────────────
# Routes – Workspace: promote to admin
# ─────────────────────────────────────────

@app.route("/workspace/<int:ws_id>/promote/<int:target_uid>", methods=["POST"])
@login_required
def promote_to_admin(ws_id, target_uid):
    """Only workspace owner (created_by) can promote members to admin."""
    check_csrf()
    uid = session["user_id"]
    # Only the workspace owner can promote
    ws = query("SELECT created_by FROM workspaces WHERE workspace_id=%s", (ws_id,), one=True)
    if not ws or ws["created_by"] != uid:
        flash("Only the workspace owner can promote members to admin.", "warning")
        return redirect(url_for("workspace", ws_id=ws_id))
    # Target must be a non-admin member
    target_membership = query("""
        SELECT is_admin FROM workspace_members
        WHERE workspace_id=%s AND user_id=%s
    """, (ws_id, target_uid), one=True)
    if not target_membership:
        flash("User is not a member of this workspace.", "warning")
        return redirect(url_for("workspace", ws_id=ws_id))
    if target_membership["is_admin"]:
        flash("User is already an admin.", "info")
        return redirect(url_for("workspace", ws_id=ws_id))
    try:
        with transaction():
            execute("""
                UPDATE workspace_members SET is_admin = TRUE
                WHERE workspace_id = %s AND user_id = %s
            """, (ws_id, target_uid))
        target = query("SELECT username FROM users WHERE user_id=%s", (target_uid,), one=True)
        flash(f"Promoted {target['username']} to admin!", "success")
    except Exception as e:
        flash(str(e), "danger")
    return redirect(url_for("workspace", ws_id=ws_id))


# ─────────────────────────────────────────
# Routes – Attachments
# ─────────────────────────────────────────

@app.route("/uploads/<path:stored_name>")
@login_required
def serve_attachment(stored_name):
    """Serve uploaded files — only accessible to logged-in users."""
    # Prevent path traversal: stored_name must be a plain filename
    if "/" in stored_name or "\\" in stored_name or ".." in stored_name:
        abort(400)
    att = query("""
        SELECT ma.*, m.channel_id
        FROM message_attachments ma
        JOIN messages m ON m.message_id = ma.message_id
        WHERE ma.stored_name = %s
    """, (stored_name,), one=True)
    if not att:
        abort(404)
    # Verify the requesting user is a member of that channel
    if not query("SELECT 1 FROM channel_members WHERE channel_id=%s AND user_id=%s",
                 (att["channel_id"], session["user_id"]), one=True):
        abort(403)
    return send_from_directory(UPLOAD_FOLDER, stored_name,
                               download_name=att["original_name"])


@app.route("/workspace/<int:ws_id>/channel/<int:ch_id>/attachment/<int:att_id>/delete",
           methods=["POST"])
@login_required
def delete_attachment(ws_id, ch_id, att_id):
    check_csrf()
    uid = session["user_id"]
    att = query("""
        SELECT ma.stored_name, m.user_id AS msg_owner
        FROM message_attachments ma
        JOIN messages m ON m.message_id = ma.message_id
        WHERE ma.attachment_id = %s AND m.channel_id = %s
    """, (att_id, ch_id), one=True)
    if not att:
        abort(404)
    if att["msg_owner"] != uid:
        # Workspace admins can also delete
        if not query("""SELECT 1 FROM workspace_members
                        WHERE workspace_id=%s AND user_id=%s AND is_admin""",
                     (ws_id, uid), one=True):
            abort(403)
    # Delete from DB and disk
    with transaction():
        execute("DELETE FROM message_attachments WHERE attachment_id=%s", (att_id,))
    disk_path = UPLOAD_FOLDER / att["stored_name"]
    if disk_path.exists():
        disk_path.unlink()
    flash("Attachment removed.", "info")
    return redirect(url_for("channel", ws_id=ws_id, ch_id=ch_id))


# ─────────────────────────────────────────
# Routes – Reactions
# ─────────────────────────────────────────

ALLOWED_EMOJIS = {"👍","👎","❤️","😂","🎉","🚀","👀","🔥","✅","😮"}

@app.route("/workspace/<int:ws_id>/channel/<int:ch_id>/message/<int:msg_id>/react",
           methods=["POST"])
@login_required
def toggle_reaction(ws_id, ch_id, msg_id):
    check_csrf()
    uid   = session["user_id"]
    emoji = request.form.get("emoji", "").strip()
    if emoji not in ALLOWED_EMOJIS:
        abort(400)
    if not query("SELECT 1 FROM channel_members WHERE channel_id=%s AND user_id=%s",
                 (ch_id, uid), one=True):
        abort(403)
    existing = query("""
        SELECT 1 FROM message_reactions
        WHERE message_id=%s AND user_id=%s AND emoji=%s
    """, (msg_id, uid, emoji), one=True)
    with transaction():
        if existing:
            execute("""
                DELETE FROM message_reactions
                WHERE message_id=%s AND user_id=%s AND emoji=%s
            """, (msg_id, uid, emoji))
        else:
            execute("""
                INSERT INTO message_reactions(message_id, user_id, emoji)
                VALUES (%s, %s, %s)
            """, (msg_id, uid, emoji))
    return redirect(url_for("channel", ws_id=ws_id, ch_id=ch_id) + f"#msg-{msg_id}")


# ─────────────────────────────────────────
# Routes – Pinned messages
# ─────────────────────────────────────────

@app.route("/workspace/<int:ws_id>/channel/<int:ch_id>/message/<int:msg_id>/pin",
           methods=["POST"])
@login_required
def toggle_pin(ws_id, ch_id, msg_id):
    check_csrf()
    uid = session["user_id"]
    if not query("SELECT 1 FROM channel_members WHERE channel_id=%s AND user_id=%s",
                 (ch_id, uid), one=True):
        abort(403)
    existing = query("""
        SELECT 1 FROM pinned_messages WHERE channel_id=%s AND message_id=%s
    """, (ch_id, msg_id), one=True)
    with transaction():
        if existing:
            execute("DELETE FROM pinned_messages WHERE channel_id=%s AND message_id=%s",
                    (ch_id, msg_id))
            flash("Message unpinned.", "info")
        else:
            execute("""
                INSERT INTO pinned_messages(channel_id, message_id, pinned_by)
                VALUES (%s, %s, %s)
            """, (ch_id, msg_id, uid))
            flash("📌 Message pinned!", "success")
    return redirect(url_for("channel", ws_id=ws_id, ch_id=ch_id))


# ─────────────────────────────────────────
# Error handlers
# ─────────────────────────────────────────

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403,
                           msg="You don't have permission to access this page."), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404,
                           msg="The page you're looking for doesn't exist."), 404


if __name__ == "__main__":
    app.run(debug=True, port=5000)