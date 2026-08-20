from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from database import init_db, get_db
from services.llm_service import analyze_incident
from datetime import datetime


app = Flask(__name__)
app.config.from_object("config")


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

init_db()


def ensure_incident_flags_table():
    """
    Stores admin-only queue visibility.

    We use a separate table instead of changing the existing
    incidents table, so the current database keeps working.
    """

    db = get_db()

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


ensure_incident_flags_table()


# =========================================================
# AUTHENTICATION DECORATORS
# =========================================================

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

        if session.get("role") not in (
            "manager",
            "admin"
        ):

            flash(
                "Admin access required.",
                "danger"
            )

            return redirect(
                url_for("user_dashboard")
            )

        return view(*args, **kwargs)

    return wrapped_view


# =========================================================
# TEMPLATE CONTEXT
# =========================================================

@app.context_processor
def inject_user():

    return {
        "current_username": session.get("username"),
        "current_role": session.get("role")
    }


# =========================================================
# HOME
# =========================================================

@app.route("/")
def index():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    if session.get("role") in (
        "manager",
        "admin"
    ):

        return redirect(
            url_for("manager_dashboard")
        )

    return redirect(
        url_for("user_dashboard")
    )


# =========================================================
# LOGIN
# =========================================================

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
                "Enter username and password.",
                "warning"
            )

            return render_template(
                "login.html"
            )

        db = get_db()

        user = db.execute(
            """
            SELECT
                id,
                username,
                password_hash,
                role
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        db.close()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            flash(
                "Login successful.",
                "success"
            )

            return redirect(
                url_for("index")
            )

        flash(
            "Invalid username or password.",
            "danger"
        )

    return render_template(
        "login.html"
    )


# =========================================================
# REGISTER
# =========================================================

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

        existing = db.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        if existing:

            db.close()

            flash(
                "Username already exists.",
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
            VALUES (?, ?, 'user', ?)
            """,
            (
                username,
                password_hash,
                datetime.now().isoformat(
                    timespec="seconds"
                )
            )
        )

        db.commit()
        db.close()

        flash(
            "Account created successfully. Please login.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# =========================================================
# LOGOUT
# =========================================================

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


# =========================================================
# USER DASHBOARD
# =========================================================

@app.route("/user/dashboard")
@login_required
def user_dashboard():

    if session.get("role") in (
        "manager",
        "admin"
    ):

        return redirect(
            url_for("manager_dashboard")
        )

    db = get_db()

    stats = db.execute(
        """
        SELECT

            COUNT(*) AS total,

            SUM(
                CASE
                    WHEN status = 'Pending'
                    THEN 1
                    ELSE 0
                END
            ) AS pending,

            SUM(
                CASE
                    WHEN status = 'In Progress'
                    THEN 1
                    ELSE 0
                END
            ) AS in_progress,

            SUM(
                CASE
                    WHEN status = 'Resolved'
                    THEN 1
                    ELSE 0
                END
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


# =========================================================
# SUBMIT INCIDENT
# =========================================================

@app.route(
    "/user/report",
    methods=["GET", "POST"]
)
@login_required
def report_incident():

    if session.get("role") in (
        "manager",
        "admin"
    ):

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

        if (
            not incident_type
            or not location
            or not description
        ):

            flash(
                "Please fill all incident fields.",
                "warning"
            )

            return render_template(
                "user/report_incident.html"
            )

        # AI / LLM analysis
        analysis = analyze_incident(
            incident_type,
            location,
            description
        )

        db = get_db()

        now = datetime.now().isoformat(
            timespec="seconds"
        )

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
                ?,
                ?
            )
            """,
            (
                session["user_id"],
                incident_type,
                location,
                description,
                analysis["priority"],
                analysis["summary"],
                analysis["recommendation"],
                now,
                now
            )
        )

        incident_id = cursor.lastrowid

        # Ensure new incidents are active
        db.execute(
            """
            INSERT OR REPLACE INTO incident_flags
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
            "Your report has been submitted successfully.",
            "success"
        )

        return redirect(
            url_for("my_reports")
        )

    return render_template(
        "user/report_incident.html"
    )


# =========================================================
# USER REPORTS
# =========================================================

@app.route("/user/reports")
@login_required
def my_reports():

    if session.get("role") in (
        "manager",
        "admin"
    ):

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
            ) AS cleared

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


# =========================================================
# EDIT USER REPORT
# =========================================================

@app.route(
    "/user/report/<int:incident_id>/edit",
    methods=["GET", "POST"]
)
@login_required
def edit_report(incident_id):

    if session.get("role") in (
        "manager",
        "admin"
    ):

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

        if (
            not incident_type
            or not location
            or not description
        ):

            db.close()

            flash(
                "Please fill all incident fields.",
                "warning"
            )

            return render_template(
                "user/edit_report.html",
                incident=incident
            )

        analysis = analyze_incident(
            incident_type,
            location,
            description
        )

        now = datetime.now().isoformat(
            timespec="seconds"
        )

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
                analysis["priority"],
                analysis["summary"],
                analysis["recommendation"],
                now,
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


# =========================================================
# DELETE USER REPORT
# =========================================================

@app.route(
    "/user/report/<int:incident_id>/delete",
    methods=["POST"]
)
@login_required
def delete_report(incident_id):

    if session.get("role") in (
        "manager",
        "admin"
    ):

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

    db.execute(
        """
        DELETE FROM incident_updates
        WHERE incident_id = ?
        """,
        (
            incident_id,
        )
    )

    db.execute(
        """
        DELETE FROM incident_flags
        WHERE incident_id = ?
        """,
        (
            incident_id,
        )
    )

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


# =========================================================
# USER REPORT DETAILS
# =========================================================

@app.route(
    "/user/report/<int:incident_id>"
)
@login_required
def user_report_detail(incident_id):

    if session.get("role") in (
        "manager",
        "admin"
    ):

        return redirect(
            url_for(
                "incident_detail",
                incident_id=incident_id
            )
        )

    db = get_db()

    # LEFT JOIN so the student's report is always accessible
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

    updates = []

    if incident:

        updates = db.execute(
            """
            SELECT

                incident_updates.*,

                COALESCE(
                    users.username,
                    'Admin'
                ) AS updater

            FROM incident_updates

            LEFT JOIN users
                ON users.id = incident_updates.updated_by

            WHERE incident_updates.incident_id = ?

            ORDER BY incident_updates.id DESC
            """,
            (
                incident_id,
            )
        ).fetchall()

    db.close()

    if not incident:

        flash(
            "Report not found.",
            "danger"
        )

        return redirect(
            url_for("my_reports")
        )

    return render_template(
        "user/report_detail.html",
        incident=incident,
        updates=updates
    )


# =========================================================
# FRAMEWORK PAGE
# =========================================================

@app.route("/framework")
@login_required
def framework():

    return render_template(
        "framework.html"
    )


# =========================================================
# MANAGER / ADMIN DASHBOARD
# =========================================================

@app.route("/manager/dashboard")
@manager_required
def manager_dashboard():

    db = get_db()

    # =====================================================
    # TOTAL COUNTS
    # =====================================================

    stats = db.execute(
        """
        SELECT

            COUNT(*) AS total,

            SUM(
                CASE
                    WHEN status = 'Pending'
                    THEN 1
                    ELSE 0
                END
            ) AS pending,

            SUM(
                CASE
                    WHEN priority = 'High'
                    THEN 1
                    ELSE 0
                END
            ) AS high,

            SUM(
                CASE
                    WHEN priority = 'Critical'
                    THEN 1
                    ELSE 0
                END
            ) AS critical,

            SUM(
                CASE
                    WHEN status = 'Resolved'
                    THEN 1
                    ELSE 0
                END
            ) AS resolved

        FROM incidents
        """
    ).fetchone()


    # =====================================================
    # RECENT REPORTS FROM EVERY USER
    # =====================================================

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
            ) AS cleared

        FROM incidents

        LEFT JOIN users
            ON users.id = incidents.reported_by

        LEFT JOIN incident_flags
            ON incident_flags.incident_id = incidents.id

        ORDER BY incidents.id DESC

        LIMIT 10
        """
    ).fetchall()


    db.close()

    return render_template(
        "manager/dashboard.html",
        stats=stats,
        recent=recent
    )


# =========================================================
# ALL INCIDENTS / ACTIVE QUEUE
# =========================================================

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
            ) AS cleared

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


    # =====================================================
    # STATUS FILTER
    # =====================================================

    if status:

        query += """
            AND incidents.status = ?
        """

        params.append(
            status
        )


    # =====================================================
    # PRIORITY FILTER
    # =====================================================

    if priority:

        query += """
            AND incidents.priority = ?
        """

        params.append(
            priority
        )


    # =====================================================
    # TYPE FILTER
    # =====================================================

    if incident_type:

        query += """
            AND incidents.incident_type = ?
        """

        params.append(
            incident_type
        )


    # =====================================================
    # SEARCH
    # =====================================================

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


# =========================================================
# ADMIN / MANAGER INCIDENT DETAILS + REPLY
# =========================================================

@app.route(
    "/manager/incident/<int:incident_id>",
    methods=["GET", "POST"]
)
@manager_required
def incident_detail(incident_id):

    db = get_db()


    # =====================================================
    # ADMIN SUBMITS REPLY / DECISION
    # =====================================================

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


        # -------------------------------------------------
        # ADMIN MUST ENTER A REPLY
        # -------------------------------------------------

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

        now = datetime.now().isoformat(
            timespec="seconds"
        )


        # -------------------------------------------------
        # SAVE ADMIN REPLY
        # -------------------------------------------------

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
                now,
                incident_id
            )
        )


        # -------------------------------------------------
        # SAVE REPLY HISTORY
        # -------------------------------------------------

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
                now
            )
        )


        db.commit()
        db.close()


        flash(
            "Admin reply sent successfully. The incident remains in the active queue until you clear it.",
            "success"
        )


        return redirect(
            url_for(
                "incident_detail",
                incident_id=incident_id
            )
        )


    # =====================================================
    # LOAD COMPLETE INCIDENT
    # =====================================================

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


    # =====================================================
    # LOAD COMPLETE ADMIN REPLY HISTORY
    # =====================================================

    updates = db.execute(
        """
        SELECT

            incident_updates.*,

            COALESCE(
                users.username,
                'Admin'
            ) AS updater

        FROM incident_updates

        LEFT JOIN users
            ON users.id = incident_updates.updated_by

        WHERE incident_updates.incident_id = ?

        ORDER BY incident_updates.id DESC
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


# =========================================================
# ADMIN CLEAR / RESTORE INCIDENT
# =========================================================

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
        SELECT
            cleared
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


    now = datetime.now().isoformat(
        timespec="seconds"
    )


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
            now if new_value else None,
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


# =========================================================
# ANALYTICS
# =========================================================

@app.route("/manager/analytics")
@manager_required
def analytics():

    db = get_db()


    # =====================================================
    # STATUS DATA
    # =====================================================

    status_rows = db.execute(
        """
        SELECT

            COALESCE(
                status,
                'Unknown'
            ) AS status,

            COUNT(*) AS count

        FROM incidents

        GROUP BY status

        ORDER BY count DESC
        """
    ).fetchall()


    # =====================================================
    # PRIORITY DATA
    # =====================================================

    priority_rows = db.execute(
        """
        SELECT

            COALESCE(
                priority,
                'Unknown'
            ) AS priority,

            COUNT(*) AS count

        FROM incidents

        GROUP BY priority

        ORDER BY count DESC
        """
    ).fetchall()


    # =====================================================
    # INCIDENT TYPE DATA
    # =====================================================

    type_rows = db.execute(
        """
        SELECT

            COALESCE(
                incident_type,
                'Unknown'
            ) AS incident_type,

            COUNT(*) AS count

        FROM incidents

        GROUP BY incident_type

        ORDER BY count DESC
        """
    ).fetchall()


    # =====================================================
    # LOCATION DATA
    # =====================================================

    location_rows = db.execute(
        """
        SELECT

            COALESCE(
                location,
                'Unknown'
            ) AS location,

            COUNT(*) AS count

        FROM incidents

        GROUP BY location

        ORDER BY count DESC

        LIMIT 10
        """
    ).fetchall()


    db.close()


    # =====================================================
    # CONVERT SQLITE ROWS TO NORMAL DICTIONARIES
    # =====================================================

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


    return render_template(

        "manager/analytics.html",

        status_data=status_data,

        priority_data=priority_data,

        type_data=type_data,

        location_data=location_data
    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )