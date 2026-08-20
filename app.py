from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from database import init_db, get_db
from services.llm_service import analyze_incident
from datetime import datetime
import sqlite3


# ============================================================
# APPLICATION
# ============================================================

app = Flask(__name__)
app.config.from_object("config")


# ============================================================
# DATABASE HELPERS
# ============================================================

def now():
    return datetime.now().isoformat(timespec="seconds")


def column_exists(db, table_name, column_name):
    """Check whether a column exists in a SQLite table."""
    try:
        columns = db.execute(
            f"PRAGMA table_info({table_name})"
        ).fetchall()

        for column in columns:
            if column["name"] == column_name:
                return True

    except Exception:
        return False

    return False


def add_column_if_missing(db, table_name, column_name, definition):
    """Safely add a missing database column."""
    if not column_exists(db, table_name, column_name):
        db.execute(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"
        )


def ensure_database_schema():
    """
    Makes the application more tolerant of older databases.

    Existing data is preserved.
    Missing tables/columns are created where necessary.
    """

    db = get_db()

    # --------------------------------------------------------
    # USERS TABLE
    # --------------------------------------------------------

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT
        )
    """)

    add_column_if_missing(
        db,
        "users",
        "password_hash",
        "TEXT"
    )

    add_column_if_missing(
        db,
        "users",
        "role",
        "TEXT DEFAULT 'user'"
    )

    add_column_if_missing(
        db,
        "users",
        "created_at",
        "TEXT"
    )

    # --------------------------------------------------------
    # INCIDENTS TABLE
    # --------------------------------------------------------

    db.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reported_by INTEGER,
            incident_type TEXT,
            location TEXT,
            description TEXT,
            priority TEXT DEFAULT 'Medium',
            status TEXT DEFAULT 'Pending',
            llm_summary TEXT,
            llm_recommendation TEXT,
            manager_remarks TEXT,
            created_at TEXT,
            updated_at TEXT
        )
    """)

    incident_columns = [
        ("reported_by", "INTEGER"),
        ("incident_type", "TEXT"),
        ("location", "TEXT"),
        ("description", "TEXT"),
        ("priority", "TEXT DEFAULT 'Medium'"),
        ("status", "TEXT DEFAULT 'Pending'"),
        ("llm_summary", "TEXT"),
        ("llm_recommendation", "TEXT"),
        ("manager_remarks", "TEXT"),
        ("created_at", "TEXT"),
        ("updated_at", "TEXT"),
    ]

    for column_name, definition in incident_columns:
        add_column_if_missing(
            db,
            "incidents",
            column_name,
            definition
        )

    # --------------------------------------------------------
    # INCIDENT UPDATES / MANAGER REPLIES
    # --------------------------------------------------------

    db.execute("""
        CREATE TABLE IF NOT EXISTS incident_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            updated_by INTEGER,
            old_status TEXT,
            new_status TEXT,
            remarks TEXT,
            created_at TEXT
        )
    """)

    update_columns = [
        ("incident_id", "INTEGER"),
        ("updated_by", "INTEGER"),
        ("old_status", "TEXT"),
        ("new_status", "TEXT"),
        ("remarks", "TEXT"),
        ("created_at", "TEXT"),
    ]

    for column_name, definition in update_columns:
        add_column_if_missing(
            db,
            "incident_updates",
            column_name,
            definition
        )

    # --------------------------------------------------------
    # INCIDENT FLAGS
    # --------------------------------------------------------

    db.execute("""
        CREATE TABLE IF NOT EXISTS incident_flags (
            incident_id INTEGER PRIMARY KEY,
            cleared INTEGER NOT NULL DEFAULT 0,
            cleared_at TEXT,
            cleared_by INTEGER
        )
    """)

    db.commit()
    db.close()


# ============================================================
# INITIALIZE DATABASE
# ============================================================

try:
    init_db()
except Exception as e:
    print("Database initialization warning:", e)

try:
    ensure_database_schema()
except Exception as e:
    print("Database schema warning:", e)


# ============================================================
# AUTHENTICATION DECORATORS
# ============================================================

def login_required(view):

    @wraps(view)
    def wrapped_view(*args, **kwargs):

        if "user_id" not in session:

            flash(
                "Please login first.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        return view(*args, **kwargs)

    return wrapped_view


def manager_required(view):

    @wraps(view)
    def wrapped_view(*args, **kwargs):

        if "user_id" not in session:

            flash(
                "Please login first.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        role = str(
            session.get("role", "")
        ).lower()

        if role not in ("manager", "admin"):

            flash(
                "Manager/Admin access required.",
                "danger"
            )

            return redirect(
                url_for("user_dashboard")
            )

        return view(*args, **kwargs)

    return wrapped_view


# ============================================================
# TEMPLATE CONTEXT
# ============================================================

@app.context_processor
def inject_user():

    return {
        "current_username": session.get("username"),
        "current_role": session.get("role")
    }


# ============================================================
# HOME
# ============================================================

@app.route("/")
def index():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    role = str(
        session.get("role", "")
    ).lower()

    if role in ("manager", "admin"):

        return redirect(
            url_for("manager_dashboard")
        )

    return redirect(
        url_for("user_dashboard")
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if "user_id" in session:

        return redirect(
            url_for("index")
        )

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not password:

            flash(
                "Please enter both username and password.",
                "warning"
            )

            return render_template(
                "login.html"
            )

        db = get_db()

        try:

            user = db.execute(
                """
                SELECT
                    id,
                    username,
                    password_hash,
                    role
                FROM users
                WHERE LOWER(username) = LOWER(?)
                LIMIT 1
                """,
                (username,)
            ).fetchone()

        except Exception as e:

            db.close()

            print("LOGIN DATABASE ERROR:", e)

            flash(
                "Unable to access the login database.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        db.close()

        # ----------------------------------------------------
        # CHECK USER
        # ----------------------------------------------------

        if not user:

            flash(
                "Invalid username or password.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        stored_hash = user["password_hash"]

        # ----------------------------------------------------
        # NORMAL HASHED PASSWORD
        # ----------------------------------------------------

        password_valid = False

        if stored_hash:

            try:

                password_valid = check_password_hash(
                    stored_hash,
                    password
                )

            except Exception as e:

                print(
                    "PASSWORD CHECK ERROR:",
                    e
                )

                password_valid = False

        if not password_valid:

            flash(
                "Invalid username or password.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        # ----------------------------------------------------
        # LOGIN SUCCESS
        # ----------------------------------------------------

        session.clear()

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = (
            user["role"]
            or "user"
        ).lower()

        flash(
            "Login successful.",
            "success"
        )

        return redirect(
            url_for("index")
        )

    return render_template(
        "login.html"
    )


# ============================================================
# REGISTER
# ============================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if "user_id" in session:

        return redirect(
            url_for("index")
        )

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        # ----------------------------------------------------
        # VALIDATION
        # ----------------------------------------------------

        if len(username) < 3:

            flash(
                "Username must contain at least 3 characters.",
                "warning"
            )

            return render_template(
                "register.html"
            )

        if len(password) < 6:

            flash(
                "Password must contain at least 6 characters.",
                "warning"
            )

            return render_template(
                "register.html"
            )

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "warning"
            )

            return render_template(
                "register.html"
            )

        db = get_db()

        try:

            existing = db.execute(
                """
                SELECT id
                FROM users
                WHERE LOWER(username) = LOWER(?)
                LIMIT 1
                """,
                (username,)
            ).fetchone()

            if existing:

                db.close()

                flash(
                    "That username already exists. Please choose another username.",
                    "danger"
                )

                return render_template(
                    "register.html"
                )

            password_hash = generate_password_hash(
                password
            )

            db.execute(
                """
                INSERT INTO users
                (
                    username,
                    password_hash,
                    role,
                    created_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    username,
                    password_hash,
                    "user",
                    now()
                )
            )

            db.commit()

        except sqlite3.IntegrityError:

            db.rollback()
            db.close()

            flash(
                "That username is already registered.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        except Exception as e:

            db.rollback()
            db.close()

            print(
                "REGISTRATION ERROR:",
                e
            )

            flash(
                "Registration failed. Please try again.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        db.close()

        flash(
            "Account created successfully. You can now login.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# ============================================================
# USER DASHBOARD
# ============================================================

@app.route("/user/dashboard")
@login_required
def user_dashboard():

    if str(
        session.get("role", "")
    ).lower() in ("manager", "admin"):

        return redirect(
            url_for("manager_dashboard")
        )

    db = get_db()

    stats = db.execute(
        """
        SELECT

            COUNT(*) AS total,

            COALESCE(
                SUM(
                    CASE
                        WHEN status = 'Pending'
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS pending,

            COALESCE(
                SUM(
                    CASE
                        WHEN status = 'In Progress'
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS in_progress,

            COALESCE(
                SUM(
                    CASE
                        WHEN status = 'Resolved'
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS resolved

        FROM incidents

        WHERE reported_by = ?
        """,
        (
            session["user_id"],
        )
    ).fetchone()

    db.close()

    return render_template(
        "user/dashboard.html",
        stats=stats
    )


# ============================================================
# SUBMIT INCIDENT
# ============================================================

@app.route(
    "/user/report",
    methods=["GET", "POST"]
)
@login_required
def report_incident():

    if str(
        session.get("role", "")
    ).lower() in ("manager", "admin"):

        return redirect(
            url_for("manager_dashboard")
        )

    if request.method == "POST":

        incident_type = request.form.get(
            "incident_type",
            ""
        ).strip()

        location = request.form.get(
            "location",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        if not incident_type or not location or not description:

            flash(
                "Please fill in all incident fields.",
                "warning"
            )

            return render_template(
                "user/report_incident.html"
            )

        # ----------------------------------------------------
        # AI ANALYSIS
        # ----------------------------------------------------

        try:

            analysis = analyze_incident(
                incident_type,
                location,
                description
            )

        except Exception as e:

            print(
                "LLM ANALYSIS ERROR:",
                e
            )

            analysis = {
                "priority": "Medium",
                "summary": description[:250],
                "recommendation": "Manager review required."
            }

        priority = analysis.get(
            "priority",
            "Medium"
        )

        summary = analysis.get(
            "summary",
            ""
        )

        recommendation = analysis.get(
            "recommendation",
            ""
        )

        db = get_db()

        current_time = now()

        cursor = db.execute(
            """
            INSERT INTO incidents
            (
                reported_by,
                incident_type,
                location,
                description,
                priority,
                status,
                llm_summary,
                llm_recommendation,
                manager_remarks,
                created_at,
                updated_at
            )
            VALUES
            (
                ?,
                ?,
                ?,
                ?,
                ?,
                'Pending',
                ?,
                ?,
                '',
                ?,
                ?
            )
            """,
            (
                session["user_id"],
                incident_type,
                location,
                description,
                priority,
                summary,
                recommendation,
                current_time,
                current_time
            )
        )

        incident_id = cursor.lastrowid

        # New incident always starts in active queue.
        db.execute(
            """
            INSERT OR REPLACE INTO incident_flags
            (
                incident_id,
                cleared,
                cleared_at,
                cleared_by
            )
            VALUES (?, 0, NULL, NULL)
            """,
            (
                incident_id,
            )
        )

        db.commit()
        db.close()

        flash(
            "Your report has been submitted successfully.",
            "success"
        )

        return redirect(
            url_for("my_reports")
        )

    return render_template(
        "user/report_incident.html"
    )


# ============================================================
# USER REPORTS
# ============================================================

@app.route("/user/reports")
@login_required
def my_reports():

    if str(
        session.get("role", "")
    ).lower() in ("manager", "admin"):

        return redirect(
            url_for("manager_incidents")
        )

    db = get_db()

    reports = db.execute(
        """
        SELECT

            incidents.*,

            COALESCE(
                incident_flags.cleared,
                0
            ) AS cleared,

            (
                SELECT COUNT(*)
                FROM incident_updates
                WHERE incident_updates.incident_id = incidents.id
            ) AS reply_count

        FROM incidents

        LEFT JOIN incident_flags
            ON incident_flags.incident_id = incidents.id

        WHERE incidents.reported_by = ?

        ORDER BY incidents.id DESC
        """,
        (
            session["user_id"],
        )
    ).fetchall()

    db.close()

    return render_template(
        "user/my_reports.html",
        reports=reports
    )


# ============================================================
# USER REPORT DETAILS
# ============================================================

@app.route(
    "/user/report/<int:incident_id>"
)
@login_required
def user_report_detail(incident_id):

    if str(
        session.get("role", "")
    ).lower() in ("manager", "admin"):

        return redirect(
            url_for(
                "incident_detail",
                incident_id=incident_id
            )
        )

    db = get_db()

    incident = db.execute(
        """
        SELECT

            incidents.*,

            COALESCE(
                users.username,
                'Unknown User'
            ) AS reporter,

            COALESCE(
                incident_flags.cleared,
                0
            ) AS cleared

        FROM incidents

        LEFT JOIN users
            ON users.id = incidents.reported_by

        LEFT JOIN incident_flags
            ON incident_flags.incident_id = incidents.id

        WHERE incidents.id = ?

        AND incidents.reported_by = ?
        """,
        (
            incident_id,
            session["user_id"]
        )
    ).fetchone()

    if not incident:

        db.close()

        flash(
            "Report not found.",
            "danger"
        )

        return redirect(
            url_for("my_reports")
        )

    # --------------------------------------------------------
    # ALL MANAGER REPLIES
    # Oldest first = proper conversation/order
    # --------------------------------------------------------

    updates = db.execute(
        """
        SELECT

            incident_updates.*,

            COALESCE(
                users.username,
                'Manager'
            ) AS updater

        FROM incident_updates

        LEFT JOIN users
            ON users.id = incident_updates.updated_by

        WHERE incident_updates.incident_id = ?

        ORDER BY incident_updates.id ASC
        """,
        (
            incident_id,
        )
    ).fetchall()

    db.close()

    return render_template(
        "user/report_detail.html",
        incident=incident,
        updates=updates
    )


# ============================================================
# EDIT USER REPORT
# ============================================================

@app.route(
    "/user/report/<int:incident_id>/edit",
    methods=["GET", "POST"]
)
@login_required
def edit_report(incident_id):

    if str(
        session.get("role", "")
    ).lower() in ("manager", "admin"):

        return redirect(
            url_for(
                "incident_detail",
                incident_id=incident_id
            )
        )

    db = get_db()

    incident = db.execute(
        """
        SELECT *
        FROM incidents
        WHERE id = ?
        AND reported_by = ?
        """,
        (
            incident_id,
            session["user_id"]
        )
    ).fetchone()

    if not incident:

        db.close()

        flash(
            "Report not found.",
            "danger"
        )

        return redirect(
            url_for("my_reports")
        )

    if request.method == "POST":

        incident_type = request.form.get(
            "incident_type",
            ""
        ).strip()

        location = request.form.get(
            "location",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        if not incident_type or not location or not description:

            db.close()

            flash(
                "Please fill in all incident fields.",
                "warning"
            )

            return render_template(
                "user/edit_report.html",
                incident=incident
            )

        try:

            analysis = analyze_incident(
                incident_type,
                location,
                description
            )

        except Exception:

            analysis = {
                "priority": incident["priority"] or "Medium",
                "summary": description[:250],
                "recommendation": "Manager review required."
            }

        db.execute(
            """
            UPDATE incidents

            SET
                incident_type = ?,
                location = ?,
                description = ?,
                priority = ?,
                llm_summary = ?,
                llm_recommendation = ?,
                updated_at = ?

            WHERE id = ?
            AND reported_by = ?
            """,
            (
                incident_type,
                location,
                description,
                analysis.get(
                    "priority",
                    "Medium"
                ),
                analysis.get(
                    "summary",
                    ""
                ),
                analysis.get(
                    "recommendation",
                    ""
                ),
                now(),
                incident_id,
                session["user_id"]
            )
        )

        db.commit()
        db.close()

        flash(
            "Report updated successfully.",
            "success"
        )

        return redirect(
            url_for(
                "user_report_detail",
                incident_id=incident_id
            )
        )

    db.close()

    return render_template(
        "user/edit_report.html",
        incident=incident
    )


# ============================================================
# DELETE USER REPORT
# ============================================================

@app.route(
    "/user/report/<int:incident_id>/delete",
    methods=["POST"]
)
@login_required
def delete_report(incident_id):

    if str(
        session.get("role", "")
    ).lower() in ("manager", "admin"):

        return redirect(
            url_for("manager_incidents")
        )

    db = get_db()

    incident = db.execute(
        """
        SELECT id
        FROM incidents
        WHERE id = ?
        AND reported_by = ?
        """,
        (
            incident_id,
            session["user_id"]
        )
    ).fetchone()

    if not incident:

        db.close()

        flash(
            "Report not found.",
            "danger"
        )

        return redirect(
            url_for("my_reports")
        )

    # Delete replies first.
    db.execute(
        """
        DELETE FROM incident_updates
        WHERE incident_id = ?
        """,
        (
            incident_id,
        )
    )

    # Delete queue flag.
    db.execute(
        """
        DELETE FROM incident_flags
        WHERE incident_id = ?
        """,
        (
            incident_id,
        )
    )

    # Delete incident.
    db.execute(
        """
        DELETE FROM incidents
        WHERE id = ?
        AND reported_by = ?
        """,
        (
            incident_id,
            session["user_id"]
        )
    )

    db.commit()
    db.close()

    flash(
        "Report deleted successfully.",
        "success"
    )

    return redirect(
        url_for("my_reports")
    )


# ============================================================
# FRAMEWORK PAGE
# ============================================================

@app.route("/framework")
@login_required
def framework():

    return render_template(
        "framework.html"
    )


# ============================================================
# MANAGER DASHBOARD
# ============================================================

@app.route("/manager/dashboard")
@manager_required
def manager_dashboard():

    db = get_db()

    # --------------------------------------------------------
    # MAIN STATISTICS
    # --------------------------------------------------------

    stats = db.execute(
        """
        SELECT

            COUNT(*) AS total,

            COALESCE(
                SUM(
                    CASE
                        WHEN status = 'Pending'
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS pending,

            COALESCE(
                SUM(
                    CASE
                        WHEN status = 'In Progress'
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS in_progress,

            COALESCE(
                SUM(
                    CASE
                        WHEN priority = 'High'
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS high,

            COALESCE(
                SUM(
                    CASE
                        WHEN priority = 'Critical'
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS critical,

            COALESCE(
                SUM(
                    CASE
                        WHEN status = 'Resolved'
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS resolved

        FROM incidents
        """
    ).fetchone()

    # --------------------------------------------------------
    # ALL RECENT REPORTS
    # --------------------------------------------------------

    recent = db.execute(
        """
        SELECT

            incidents.*,

            COALESCE(
                users.username,
                'Unknown User'
            ) AS reporter,

            COALESCE(
                incident_flags.cleared,
                0
            ) AS cleared,

            (
                SELECT COUNT(*)
                FROM incident_updates
                WHERE incident_updates.incident_id = incidents.id
            ) AS reply_count

        FROM incidents

        LEFT JOIN users
            ON users.id = incidents.reported_by

        LEFT JOIN incident_flags
            ON incident_flags.incident_id = incidents.id

        ORDER BY incidents.id DESC

        LIMIT 20
        """
    ).fetchall()

    # --------------------------------------------------------
    # ACTIVE QUEUE COUNT
    # --------------------------------------------------------

    active_count = db.execute(
        """
        SELECT COUNT(*)

        FROM incidents

        LEFT JOIN incident_flags
            ON incident_flags.incident_id = incidents.id

        WHERE COALESCE(
            incident_flags.cleared,
            0
        ) = 0
        """
    ).fetchone()["COUNT(*)"]

    db.close()

    return render_template(
        "manager/dashboard.html",
        stats=stats,
        recent=recent,
        active_count=active_count
    )


# ============================================================
# ALL INCIDENTS / ACTIVE QUEUE
# ============================================================

@app.route("/manager/incidents")
@manager_required
def manager_incidents():

    status = request.args.get(
        "status",
        ""
    ).strip()

    priority = request.args.get(
        "priority",
        ""
    ).strip()

    incident_type = request.args.get(
        "incident_type",
        ""
    ).strip()

    search = request.args.get(
        "search",
        ""
    ).strip()

    # --------------------------------------------------------
    # BASE QUERY
    #
    # IMPORTANT:
    # Replying does NOT remove the report.
    # Only clearing removes it from this active queue.
    # --------------------------------------------------------

    query = """
        SELECT

            incidents.*,

            COALESCE(
                users.username,
                'Unknown User'
            ) AS reporter,

            COALESCE(
                incident_flags.cleared,
                0
            ) AS cleared,

            (
                SELECT COUNT(*)
                FROM incident_updates
                WHERE incident_updates.incident_id = incidents.id
            ) AS reply_count

        FROM incidents

        LEFT JOIN users
            ON users.id = incidents.reported_by

        LEFT JOIN incident_flags
            ON incident_flags.incident_id = incidents.id

        WHERE COALESCE(
            incident_flags.cleared,
            0
        ) = 0
    """

    params = []

    if status:

        query += """
            AND incidents.status = ?
        """

        params.append(
            status
        )

    if priority:

        query += """
            AND incidents.priority = ?
        """

        params.append(
            priority
        )

    if incident_type:

        query += """
            AND incidents.incident_type = ?
        """

        params.append(
            incident_type
        )

    if search:

        query += """
            AND (
                incidents.location LIKE ?
                OR incidents.description LIKE ?
                OR incidents.incident_type LIKE ?
                OR COALESCE(
                    users.username,
                    ''
                ) LIKE ?
            )
        """

        term = f"%{search}%"

        params.extend(
            [
                term,
                term,
                term,
                term
            ]
        )

    # Newest report first.
    query += """
        ORDER BY incidents.id DESC
    """

    db = get_db()

    incidents = db.execute(
        query,
        params
    ).fetchall()

    types = db.execute(
        """
        SELECT DISTINCT
            incident_type
        FROM incidents
        WHERE incident_type IS NOT NULL
        AND incident_type != ''
        ORDER BY incident_type
        """
    ).fetchall()

    db.close()

    return render_template(
        "manager/incidents.html",
        incidents=incidents,
        types=types,
        selected_status=status,
        selected_priority=priority,
        selected_type=incident_type,
        search=search
    )


# ============================================================
# MANAGER INCIDENT DETAIL + REPLY
# ============================================================

@app.route(
    "/manager/incident/<int:incident_id>",
    methods=["GET", "POST"]
)
@manager_required
def incident_detail(incident_id):

    db = get_db()

    # ========================================================
    # MANAGER SENDS REPLY
    # ========================================================

    if request.method == "POST":

        new_status = request.form.get(
            "status",
            "Pending"
        ).strip()

        new_priority = request.form.get(
            "priority",
            "Medium"
        ).strip()

        remarks = request.form.get(
            "manager_remarks",
            ""
        ).strip()

        if not remarks:

            db.close()

            flash(
                "Please enter a reply before updating the incident.",
                "warning"
            )

            return redirect(
                url_for(
                    "incident_detail",
                    incident_id=incident_id
                )
            )

        incident = db.execute(
            """
            SELECT *
            FROM incidents
            WHERE id = ?
            """,
            (
                incident_id,
            )
        ).fetchone()

        if not incident:

            db.close()

            flash(
                "Incident not found.",
                "danger"
            )

            return redirect(
                url_for("manager_incidents")
            )

        old_status = incident["status"]

        current_time = now()

        # ----------------------------------------------------
        # UPDATE CURRENT INCIDENT STATE
        # ----------------------------------------------------

        db.execute(
            """
            UPDATE incidents

            SET
                status = ?,
                priority = ?,
                manager_remarks = ?,
                updated_at = ?

            WHERE id = ?
            """,
            (
                new_status,
                new_priority,
                remarks,
                current_time,
                incident_id
            )
        )

        # ----------------------------------------------------
        # SAVE REPLY AS HISTORY
        # ----------------------------------------------------

        db.execute(
            """
            INSERT INTO incident_updates
            (
                incident_id,
                updated_by,
                old_status,
                new_status,
                remarks,
                created_at
            )
            VALUES
            (
                ?,
                ?,
                ?,
                ?,
                ?,
                ?
            )
            """,
            (
                incident_id,
                session["user_id"],
                old_status,
                new_status,
                remarks,
                current_time
            )
        )

        # ----------------------------------------------------
        # IMPORTANT:
        # A REPLY MUST NOT CLEAR THE INCIDENT.
        # ----------------------------------------------------

        db.execute(
            """
            INSERT OR IGNORE INTO incident_flags
            (
                incident_id,
                cleared
            )
            VALUES (?, 0)
            """,
            (
                incident_id,
            )
        )

        db.commit()
        db.close()

        flash(
            "Your reply has been sent. The incident remains in the active queue.",
            "success"
        )

        return redirect(
            url_for(
                "incident_detail",
                incident_id=incident_id
            )
        )

    # ========================================================
    # LOAD INCIDENT
    # ========================================================

    incident = db.execute(
        """
        SELECT

            incidents.*,

            COALESCE(
                users.username,
                'Unknown User'
            ) AS reporter,

            COALESCE(
                incident_flags.cleared,
                0
            ) AS cleared

        FROM incidents

        LEFT JOIN users
            ON users.id = incidents.reported_by

        LEFT JOIN incident_flags
            ON incident_flags.incident_id = incidents.id

        WHERE incidents.id = ?
        """,
        (
            incident_id,
        )
    ).fetchone()

    # ========================================================
    # LOAD REPLY HISTORY
    #
    # Oldest first so the conversation is displayed
    # in proper order.
    # ========================================================

    updates = db.execute(
        """
        SELECT

            incident_updates.*,

            COALESCE(
                users.username,
                'Manager'
            ) AS updater

        FROM incident_updates

        LEFT JOIN users
            ON users.id = incident_updates.updated_by

        WHERE incident_updates.incident_id = ?

        ORDER BY incident_updates.id ASC
        """,
        (
            incident_id,
        )
    ).fetchall()

    db.close()

    if not incident:

        flash(
            "Incident not found.",
            "danger"
        )

        return redirect(
            url_for("manager_incidents")
        )

    return render_template(
        "manager/incident_detail.html",
        incident=incident,
        updates=updates
    )


# ============================================================
# CLEAR / RESTORE INCIDENT
# ============================================================

@app.route(
    "/manager/incident/<int:incident_id>/toggle-clear",
    methods=["POST"]
)
@manager_required
def toggle_incident_clear(incident_id):

    db = get_db()

    incident = db.execute(
        """
        SELECT id
        FROM incidents
        WHERE id = ?
        """,
        (
            incident_id,
        )
    ).fetchone()

    if not incident:

        db.close()

        flash(
            "Incident not found.",
            "danger"
        )

        return redirect(
            url_for("manager_incidents")
        )

    flag = db.execute(
        """
        SELECT cleared
        FROM incident_flags
        WHERE incident_id = ?
        """,
        (
            incident_id,
        )
    ).fetchone()

    current_value = (
        flag["cleared"]
        if flag
        else 0
    )

    new_value = (
        0
        if current_value
        else 1
    )

    current_time = now()

    db.execute(
        """
        INSERT OR REPLACE INTO incident_flags
        (
            incident_id,
            cleared,
            cleared_at,
            cleared_by
        )
        VALUES
        (
            ?,
            ?,
            ?,
            ?
        )
        """,
        (
            incident_id,
            new_value,
            current_time if new_value else None,
            session["user_id"] if new_value else None
        )
    )

    db.commit()
    db.close()

    if new_value == 1:

        flash(
            "Incident cleared from the active queue.",
            "success"
        )

    else:

        flash(
            "Incident restored to the active queue.",
            "success"
        )

    return redirect(
        url_for(
            "incident_detail",
            incident_id=incident_id
        )
    )


# ============================================================
# ANALYTICS
# ============================================================

@app.route("/manager/analytics")
@manager_required
def analytics():

    db = get_db()

    status_rows = db.execute(
        """
        SELECT
            COALESCE(status, 'Unknown') AS status,
            COUNT(*) AS count
        FROM incidents
        GROUP BY status
        ORDER BY count DESC
        """
    ).fetchall()

    priority_rows = db.execute(
        """
        SELECT
            COALESCE(priority, 'Unknown') AS priority,
            COUNT(*) AS count
        FROM incidents
        GROUP BY priority
        ORDER BY count DESC
        """
    ).fetchall()

    type_rows = db.execute(
        """
        SELECT
            COALESCE(incident_type, 'Unknown') AS incident_type,
            COUNT(*) AS count
        FROM incidents
        GROUP BY incident_type
        ORDER BY count DESC
        """
    ).fetchall()

    location_rows = db.execute(
        """
        SELECT
            COALESCE(location, 'Unknown') AS location,
            COUNT(*) AS count
        FROM incidents
        GROUP BY location
        ORDER BY count DESC
        LIMIT 10
        """
    ).fetchall()

    # --------------------------------------------------------
    # USER REPORT COUNTS
    # --------------------------------------------------------

    user_rows = db.execute(
        """
        SELECT
            COALESCE(users.username, 'Unknown User') AS username,
            COUNT(incidents.id) AS count
        FROM incidents
        LEFT JOIN users
            ON users.id = incidents.reported_by
        GROUP BY incidents.reported_by
        ORDER BY count DESC
        """
    ).fetchall()

    db.close()

    status_data = [
        {
            "status": row["status"],
            "count": row["count"]
        }
        for row in status_rows
    ]

    priority_data = [
        {
            "priority": row["priority"],
            "count": row["count"]
        }
        for row in priority_rows
    ]

    type_data = [
        {
            "incident_type": row["incident_type"],
            "count": row["count"]
        }
        for row in type_rows
    ]

    location_data = [
        {
            "location": row["location"],
            "count": row["count"]
        }
        for row in location_rows
    ]

    user_data = [
        {
            "username": row["username"],
            "count": row["count"]
        }
        for row in user_rows
    ]

    return render_template(
        "manager/analytics.html",
        status_data=status_data,
        priority_data=priority_data,
        type_data=type_data,
        location_data=location_data,
        user_data=user_data
    )


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def page_not_found(error):

    return render_template(
        "base.html"
    ), 404


@app.errorhandler(500)
def internal_server_error(error):

    print(
        "INTERNAL SERVER ERROR:",
        error
    )

    return (
        "Internal Server Error. Check the terminal for the exact error.",
        500
    )


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )