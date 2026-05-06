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
import functools
import secrets
from contextlib import contextmanager

import psycopg2
import psycopg2.extras
from flask import (Flask, g, session, request, redirect, url_for,
                   render_template, flash, abort)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ─────────────────────────────────────────
# Database helpers
# ─────────────────────────────────────────

def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(
            host=os.environ.get("DB_HOST", "localhost"),
            port=os.environ.get("DB_PORT", 5432),
            dbname=os.environ.get("DB_NAME", "postgres"),
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
        "SELECT user_id, username, email, created_at FROM users WHERE user_id = %s",
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
    """Inject sidebar workspaces and pending invitation count into g."""
    uid = session.get("user_id")
    if uid:
        g.sidebar_workspaces = query("""
            SELECT w.workspace_id, w.name
            FROM workspaces w
            JOIN workspace_members wm ON wm.workspace_id = w.workspace_id AND wm.user_id = %s
            ORDER BY w.name
        """, (uid,))
        row = query("""
            SELECT COUNT(*) AS n FROM channel_invitations
            WHERE invited_user_id = %s AND status = 'pending'
        """, (uid,), one=True)
        g.pending_count = row["n"] if row else 0


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
                        "SELECT sp_register_user(%s, %s, %s)",
                        (username, email, pw_hash)
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

    pending_count = query("""
        SELECT COUNT(*) AS n FROM channel_invitations
        WHERE invited_user_id = %s AND status = 'pending'
    """, (uid,), one=True)["n"]

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

    members = query("""
        SELECT u.user_id, u.username, wm.is_admin, wm.joined_at
        FROM workspace_members wm
        JOIN users u ON u.user_id = wm.user_id
        WHERE wm.workspace_id = %s
        ORDER BY u.username
    """, (ws_id,))

    return render_template("workspace.html",
                           ws=ws, channels=channels, members=members,
                           is_admin=membership["is_admin"])


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
# Routes – Channel / Messages
# ─────────────────────────────────────────

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
        if content:
            try:
                with transaction():
                    execute("SELECT sp_post_message(%s, %s, %s)",
                            (ch_id, uid, content))
                return redirect(url_for("channel", ws_id=ws_id, ch_id=ch_id))
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

    return render_template("channel.html",
                           ch=ch, messages=messages, is_member=is_member,
                           ws_id=ws_id, ws_members=ws_members)


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

@app.route("/profile")
@login_required
def profile():
    user = current_user()
    return render_template("profile.html", user=user)


# ─────────────────────────────────────────
# Routes – Workspace: add member
# ─────────────────────────────────────────

@app.route("/workspace/<int:ws_id>/add_member", methods=["POST"])
@login_required
def add_workspace_member(ws_id):
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
    try:
        with transaction():
            execute("""
                INSERT INTO workspace_members(workspace_id, user_id)
                VALUES (%s, %s) ON CONFLICT DO NOTHING
            """, (ws_id, user["user_id"]))
            # Auto-add to general channel
            general = query("""
                SELECT channel_id FROM channels
                WHERE workspace_id=%s AND name='general'
            """, (ws_id,), one=True)
            if general:
                execute("""
                    INSERT INTO channel_members(channel_id, user_id)
                    VALUES (%s, %s) ON CONFLICT DO NOTHING
                """, (general["channel_id"], user["user_id"]))
        flash(f"Added {username} to the workspace.", "success")
    except Exception as e:
        flash(str(e), "danger")
    return redirect(url_for("workspace", ws_id=ws_id))


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
