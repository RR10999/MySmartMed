"""
app.py
------
MySmartMed — Flask prototype implementing the architecture described
in the paper (Fig. 1): Authentication Layer, Application/Logic Layer,
Security Layer, and Data Layer, all running against a local SQLite
database with AES-256-GCM field-level encryption.

Run with:
    python app.py
Then open http://127.0.0.1:5000
"""

import hmac
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect, url_for, session, flash,
    abort, jsonify, send_file
)

import db
from crypto_utils import (
    derive_key, generate_login_salt, encrypt_field, decrypt_field,
    hash_password, verify_password,
)
from medicine_data import search_medicines
from report_generator import generate_weekly_report, generate_visit_summary_report
from notification_manager import (
    start_notification_manager,
    stop_notification_manager,
    register_schedule_provider,
    register_dose_logger,
    register_dose_exists_checker,
    get_notifications,
    acknowledge,
)

app = Flask(__name__)
app.secret_key = os.environ.get("MYSMARTMED_SECRET_KEY", os.urandom(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("MYSMARTMED_HTTPS") == "1",
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)

DATE_FMT = "%Y-%m-%d"


# ---------------------------------------------------------------------------
# Session / key helpers
#
# Per Section III-B: "the encryption key is derived during login and
# is held in the server-side session memory for the duration of the
# session." We keep the raw key bytes in an in-process dict keyed by
# Flask's session id rather than in the (client-side, signed-but-not-
# encrypted) session cookie itself, so the AES key never leaves the
# server. This mirrors the paper's stated threat-model limitation
# (Section V-C): the key is still exposed if the server process/
# session store is compromised while the session is active.
# ---------------------------------------------------------------------------

_SESSION_KEYS = {}  # session_token -> raw AES key bytes (server memory only)
_ACTIVE_USERS = {}   # user_id -> raw AES key bytes for active local sessions


def csrf_token():
    """Return a per-session CSRF token for all state-changing requests."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def require_csrf():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        expected = session.get("csrf_token", "")
        if not supplied or not expected or not hmac.compare_digest(supplied, expected):
            abort(400, "Invalid or missing CSRF token.")


def _valid_username(value):
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,48}", value))


def _valid_password(value):
    return len(value) >= 12 and any(c.islower() for c in value) and any(c.isupper() for c in value) and any(c.isdigit() for c in value)


def _owned_medicine(conn, medicine_id):
    return conn.execute("""SELECT m.* FROM Medicine_Details m JOIN Patient_Details p
        ON p.patient_id=m.patient_id WHERE m.medicine_id=? AND p.user_id=?""",
        (medicine_id, session["user_id"])).fetchone()


def _encrypted_int(value, key, default=0):
    try:
        return int(decrypt_field(value, key) or default)
    except (TypeError, ValueError):
        return default


def _current_key():
    token = session.get("session_token")
    if not token or token not in _SESSION_KEYS:
        return None
    return _SESSION_KEYS[token]


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not _current_key() or "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# Auth routes (Authentication Layer, Fig. 1)
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if _current_key():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        contact_number = request.form.get("contact_number", "").strip()

        if not _valid_username(username):
            flash("Username must be 3–48 characters using letters, numbers, dots, hyphens, or underscores.", "danger")
            return render_template("register.html")
        if not _valid_password(password):
            flash("Use a password of at least 12 characters with upper-case, lower-case, and a number.", "danger")
            return render_template("register.html")

        conn = db.get_connection()
        existing = conn.execute(
            "SELECT 1 FROM User_Details WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            conn.close()
            flash("That username is already taken.", "danger")
            return render_template("register.html")

        salt = generate_login_salt()
        pw_hash = hash_password(password, salt)
        # The AES key is derived from the SAME salt+password so we can
        # re-derive it on every login without storing it anywhere.
        aes_key = derive_key(password, salt)
        enc_contact = encrypt_field(contact_number, aes_key) if contact_number else None

        try:
            conn.execute(
                "INSERT INTO User_Details (username, password_hash, password_salt, contact_number) VALUES (?, ?, ?, ?)",
                (username, pw_hash, salt, enc_contact),
            )
            conn.commit()
        finally:
            conn.close()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = db.get_connection()
        user = conn.execute(
            "SELECT * FROM User_Details WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if not user or not verify_password(password, user["password_salt"], user["password_hash"]):
            flash("Invalid username or password.", "danger")
            return render_template("login.html")

        aes_key = derive_key(password, user["password_salt"])
        token = os.urandom(16).hex()
        _SESSION_KEYS[token] = aes_key
        _ACTIVE_USERS[user["user_id"]] = aes_key

        session.clear()  # session fixation defense; a fresh CSRF token follows.
        session["session_token"] = token
        session["user_id"] = user["user_id"]
        session["username"] = user["username"]
        csrf_token()

        flash(f"Welcome back, {user['username']}.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    token = session.get("session_token")
    if token in _SESSION_KEYS:
        # Explicit zeroing best-effort (Python strings/bytes are immutable,
        # but we drop the reference so it can be garbage collected and
        # remove it from server memory immediately).
        del _SESSION_KEYS[token]

    user_id = session.get("user_id")
    if user_id is not None:
        # The prototype keeps one active key per caregiver account.
        # This means automatic reminders operate while that local account
        # is logged in, consistent with the paper's session-scoped key model.
        _ACTIVE_USERS.pop(user_id, None)

    session.clear()
    flash("You have been logged out. Session key discarded.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    key = _current_key()
    conn = db.get_connection()
    patients_raw = conn.execute(
        "SELECT * FROM Patient_Details WHERE user_id = ? ORDER BY patient_id DESC",
        (session["user_id"],),
    ).fetchall()

    patients = []
    refill_alerts = 0
    for p in patients_raw:
        name = decrypt_field(p["name"], key) or "(unnamed)"

        # Check for any refill alerts across this patient's medicines
        meds = conn.execute(
            "SELECT medicine_id, name FROM Medicine_Details WHERE patient_id = ? AND active = 1",
            (p["patient_id"],),
        ).fetchall()
        patient_alerts = 0
        for m in meds:
            refills = conn.execute(
                "SELECT * FROM Refill_Details WHERE medicine_id = ? ORDER BY refill_id DESC LIMIT 1",
                (m["medicine_id"],),
            ).fetchone()
            if refills:
                remaining = int(decrypt_field(refills["remaining_qty"], key) or 0)
                if remaining - 1 < _encrypted_int(refills["threshold"], key):
                    patient_alerts += 1
        refill_alerts += patient_alerts

        patients.append({
            "patient_id": p["patient_id"],
            "name": name,
            "gender": p["gender"],
            "medicine_count": len(meds),
            "refill_alerts": patient_alerts,
        })

    conn.close()
    return render_template("dashboard.html", patients=patients,
                            total_alerts=refill_alerts, username=session["username"])


# ---------------------------------------------------------------------------
# Patients
# ---------------------------------------------------------------------------

@app.route("/patients/add", methods=["GET", "POST"])
@login_required
def add_patient():
    if request.method == "POST":
        key = _current_key()
        name = request.form["name"].strip()
        dob = request.form.get("dob", "").strip()
        gender = request.form.get("gender", "").strip()
        contact_number = request.form.get("contact_number", "").strip()
        family_email = request.form.get("family_email", "").strip()

        if not name or len(name) > 120 or (family_email and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", family_email)):
            flash("Enter a patient name and, if supplied, a valid email address.", "danger")
            return render_template("add_patient.html")

        conn = db.get_connection()
        conn.execute(
            "INSERT INTO Patient_Details (user_id, name, dob, gender, contact_number, family_email) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                session["user_id"],
                encrypt_field(name, key),
                encrypt_field(dob, key),
                gender,
                encrypt_field(contact_number, key),
                encrypt_field(family_email, key),
            ),
        )
        conn.commit()
        conn.close()
        flash(f"Patient '{name}' added.", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_patient.html")


@app.route("/patients/<int:patient_id>")
@login_required
def patient_detail(patient_id):
    key = _current_key()
    conn = db.get_connection()

    p = conn.execute(
        "SELECT * FROM Patient_Details WHERE patient_id = ? AND user_id = ?",
        (patient_id, session["user_id"]),
    ).fetchone()
    if not p:
        conn.close()
        flash("Patient not found.", "danger")
        return redirect(url_for("dashboard"))

    patient = {
        "patient_id": p["patient_id"],
        "name": decrypt_field(p["name"], key),
        "dob": decrypt_field(p["dob"], key),
        "gender": p["gender"],
        "contact_number": decrypt_field(p["contact_number"], key),
        "family_email": decrypt_field(p["family_email"], key),
    }

    meds_raw = conn.execute(
        "SELECT * FROM Medicine_Details WHERE patient_id = ? ORDER BY medicine_id DESC",
        (patient_id,),
    ).fetchall()
    medicines = []
    for m in meds_raw:
        refill = conn.execute(
            "SELECT * FROM Refill_Details WHERE medicine_id = ? ORDER BY refill_id DESC LIMIT 1",
            (m["medicine_id"],),
        ).fetchone()
        refill_info = None
        if refill:
            remaining = int(decrypt_field(refill["remaining_qty"], key) or 0)
            refill_info = {
                "remaining_qty": remaining,
                "threshold": _encrypted_int(refill["threshold"], key),
                "alert": (remaining - 1) < _encrypted_int(refill["threshold"], key),
                "last_refill_date": decrypt_field(refill["last_refill_date"], key),
            }
        medicines.append({
            "medicine_id": m["medicine_id"],
            "name": m["name"],
            "dosage": m["dosage"],
            "frequency": m["frequency"],
            "time_of_day": m["time_of_day"],
            "start_date": decrypt_field(m["start_date"], key),
            "end_date": decrypt_field(m["end_date"], key),
            "active": bool(m["active"]),
            "refill": refill_info,
        })

    visits_raw = conn.execute(
        """SELECT v.*, d.name AS doctor_name_enc, d.hospital, d.specialisation
           FROM Visit_Details v LEFT JOIN Doctor_Details d ON v.doctor_id = d.doctor_id
           WHERE v.patient_id = ? ORDER BY v.visit_id DESC""",
        (patient_id,),
    ).fetchall()
    visits = []
    for v in visits_raw:
        visits.append({
            "visit_id": v["visit_id"],
            "doctor_name": decrypt_field(v["doctor_name_enc"], key) if v["doctor_name_enc"] else "N/A",
            "hospital": v["hospital"],
            "visit_date": decrypt_field(v["visit_date"], key),
            "next_visit_date": decrypt_field(v["next_visit_date"], key),
            "notes": decrypt_field(v["notes"], key),
        })

    doctors_raw = conn.execute(
        "SELECT * FROM Doctor_Details WHERE user_id = ? ORDER BY doctor_id DESC",
        (session["user_id"],),
    ).fetchall()
    doctors = [{"doctor_id": d["doctor_id"], "name": decrypt_field(d["name"], key),
                "hospital": d["hospital"]} for d in doctors_raw]

    conn.close()
    return render_template("patient_detail.html", patient=patient, medicines=medicines,
                            visits=visits, doctors=doctors)


# ---------------------------------------------------------------------------
# Doctors
# ---------------------------------------------------------------------------

@app.route("/doctors/add", methods=["GET", "POST"])
@login_required
def add_doctor():
    if request.method == "POST":
        key = _current_key()
        name = request.form["name"].strip()
        hospital = request.form.get("hospital", "").strip()
        specialisation = request.form.get("specialisation", "").strip()
        contact_number = request.form.get("contact_number", "").strip()

        if not name or len(name) > 120:
            flash("Doctor name is required and must be at most 120 characters.", "danger")
            return render_template("add_doctor.html")

        conn = db.get_connection()
        conn.execute(
            "INSERT INTO Doctor_Details (user_id, name, hospital, specialisation, contact_number) "
            "VALUES (?, ?, ?, ?, ?)",
            (session["user_id"], encrypt_field(name, key), hospital, specialisation,
             encrypt_field(contact_number, key)),
        )
        conn.commit()
        conn.close()
        flash(f"Doctor '{name}' added.", "success")
        return redirect(request.form.get("return_to") or url_for("dashboard"))

    patient_id = request.args.get("patient_id", type=int)
    return render_template("add_doctor.html", patient_id=patient_id)


# ---------------------------------------------------------------------------
# Medicines
# ---------------------------------------------------------------------------

@app.route("/patients/<int:patient_id>/medicines/add", methods=["GET", "POST"])
@login_required
def add_medicine(patient_id):
    key = _current_key()
    conn = db.get_connection()
    p = conn.execute(
        "SELECT * FROM Patient_Details WHERE patient_id = ? AND user_id = ?",
        (patient_id, session["user_id"]),
    ).fetchone()
    if not p:
        conn.close()
        flash("Patient not found.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form["name"].strip()
        dosage = request.form.get("dosage", "").strip()
        frequency = request.form.get("frequency", "").strip()
        time_of_day = request.form.get("time_of_day", "").strip()
        start_date = request.form.get("start_date", "").strip()
        end_date = request.form.get("end_date", "").strip()
        total_qty = request.form.get("total_qty", type=int) or 0
        threshold = request.form.get("threshold", type=int) or 0

        times = _parse_schedule_times(time_of_day)
        if not name or len(name) > 120 or not times or total_qty < 0 or threshold < 0 or threshold > total_qty:
            conn.close()
            flash("Provide a medicine name, valid dose time(s), and a threshold between 0 and the total quantity.", "danger")
            return render_template("add_medicine.html", patient_id=patient_id)

        cur = conn.execute(
            "INSERT INTO Medicine_Details (patient_id, name, dosage, frequency, time_of_day, "
            "start_date, end_date, active) VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
            (patient_id, name, dosage, frequency, time_of_day,
             encrypt_field(start_date, key), encrypt_field(end_date, key)),
        )
        medicine_id = cur.lastrowid

        conn.execute(
            "INSERT INTO Refill_Details (medicine_id, total_qty, remaining_qty, threshold, "
            "last_refill_date) VALUES (?, ?, ?, ?, ?)",
            (medicine_id, encrypt_field(str(total_qty), key), encrypt_field(str(total_qty), key), encrypt_field(str(threshold), key),
             encrypt_field(datetime.now().strftime(DATE_FMT), key)),
        )
        conn.commit()
        conn.close()
        flash(f"Medicine '{name}' added for {decrypt_field(p['name'], key)}.", "success")
        return redirect(url_for("patient_detail", patient_id=patient_id))

    conn.close()
    return render_template("add_medicine.html", patient_id=patient_id)


# ---------------------------------------------------------------------------
# Visits
# ---------------------------------------------------------------------------

@app.route("/patients/<int:patient_id>/visits/add", methods=["GET", "POST"])
@login_required
def add_visit(patient_id):
    key = _current_key()
    conn = db.get_connection()
    p = conn.execute(
        "SELECT * FROM Patient_Details WHERE patient_id = ? AND user_id = ?",
        (patient_id, session["user_id"]),
    ).fetchone()
    if not p:
        conn.close()
        flash("Patient not found.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        doctor_id = request.form.get("doctor_id", type=int)
        visit_date = request.form.get("visit_date", "").strip()
        next_visit_date = request.form.get("next_visit_date", "").strip()
        notes = request.form.get("notes", "").strip()

        doctor = conn.execute("SELECT doctor_id FROM Doctor_Details WHERE doctor_id = ? AND user_id = ?", (doctor_id, session["user_id"])).fetchone()
        if not doctor or not visit_date:
            conn.close()
            flash("Choose one of your doctors and provide a visit date.", "danger")
            return redirect(url_for("add_visit", patient_id=patient_id))

        conn.execute(
            "INSERT INTO Visit_Details (patient_id, doctor_id, visit_date, next_visit_date, notes) "
            "VALUES (?, ?, ?, ?, ?)",
            (patient_id, doctor_id, encrypt_field(visit_date, key),
             encrypt_field(next_visit_date, key), encrypt_field(notes, key)),
        )
        conn.commit()
        conn.close()
        flash("Visit recorded.", "success")
        return redirect(url_for("patient_detail", patient_id=patient_id))

    doctors_raw = conn.execute(
        "SELECT * FROM Doctor_Details WHERE user_id = ? ORDER BY doctor_id DESC",
        (session["user_id"],),
    ).fetchall()
    doctors = [{"doctor_id": d["doctor_id"], "name": decrypt_field(d["name"], key)}
               for d in doctors_raw]
    conn.close()
    return render_template("add_visit.html", patient_id=patient_id, doctors=doctors)


# ---------------------------------------------------------------------------
# Medication Compliance Workflow (Section IV-B)
#
#   Alert_refill = 1  <=>  RQ - 1 < RT
# ---------------------------------------------------------------------------

@app.route("/medicines/<int:medicine_id>/log", methods=["POST"])
@login_required
def log_dose(medicine_id):
    """
    Record a medication dose.

    For reminder-driven confirmation, the browser sends the original
    scheduled_time so the compliance log represents the scheduled dose
    rather than the time at which the caregiver happened to click.

    Manual TAKEN/MISSED buttons continue to work and default to now.
    """

    key = _current_key()
    status = request.form.get("status")

    if status not in ("TAKEN", "MISSED"):
        if request.is_json:
            return jsonify({"ok": False, "error": "Invalid dose status."}), 400

        flash("Invalid dose status.", "danger")
        return redirect(request.referrer or url_for("dashboard"))

    scheduled_time_raw = request.form.get("scheduled_time", "").strip()

    if scheduled_time_raw:
        try:
            scheduled_time = datetime.fromisoformat(scheduled_time_raw)
        except ValueError:
            if request.is_json:
                return jsonify({"ok": False, "error": "Invalid scheduled time."}), 400

            flash("Invalid scheduled time.", "danger")
            return redirect(request.referrer or url_for("dashboard"))
    else:
        scheduled_time = datetime.now()

    conn = db.get_connection()

    # Ensure the medicine belongs to a patient owned by the logged-in user.
    med = _owned_medicine(conn, medicine_id)

    if not med:
        conn.close()

        if request.is_json:
            return jsonify({"ok": False, "error": "Medicine not found."}), 404

        flash("Medicine not found.", "danger")
        return redirect(url_for("dashboard"))

    # Prevent duplicate confirmation of the same scheduled dose.
    existing = conn.execute(
        """
        SELECT log_id
        FROM Compliance_Log
        WHERE medicine_id = ?
          AND scheduled_time = ?
        LIMIT 1
        """,
        (
            medicine_id,
            scheduled_time.isoformat(timespec="seconds"),
        ),
    ).fetchone()

    if existing:
        conn.close()

        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({
                "ok": True,
                "already_logged": True,
                "status": status,
            })

        flash("That scheduled dose has already been recorded.", "info")
        return redirect(request.referrer or url_for("dashboard"))

    try:
        conn.execute(
            "INSERT INTO Compliance_Log (medicine_id, scheduled_time, status) VALUES (?, ?, ?)",
            (medicine_id, scheduled_time.isoformat(timespec="seconds"), encrypt_field(status, key)),
        )
    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()
        return jsonify({"ok": True, "already_logged": True, "status": status}) if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest" else redirect(request.referrer or url_for("dashboard"))

    refill_alert = False
    remaining_qty = None
    threshold = None

    # If a dose was taken, decrement refill inventory and evaluate:
    # Alert_refill = 1 <=> RQ - 1 < RT
    if status == "TAKEN":
        refill = conn.execute(
            """
            SELECT *
            FROM Refill_Details
            WHERE medicine_id = ?
            ORDER BY refill_id DESC
            LIMIT 1
            """,
            (medicine_id,),
        ).fetchone()

        if refill:
            remaining = int(
                decrypt_field(refill["remaining_qty"], key) or 0
            )

            new_remaining = max(remaining - 1, 0)

            conn.execute(
                """
                UPDATE Refill_Details
                SET remaining_qty = ?
                WHERE refill_id = ?
                """,
                (
                    encrypt_field(str(new_remaining), key),
                    refill["refill_id"],
                ),
            )

            remaining_qty = new_remaining
            threshold = _encrypted_int(refill["threshold"], key)
            refill_alert = new_remaining < threshold

    conn.commit()
    conn.close()

    # A successful response ends the pending reminder state immediately.
    acknowledge(
        medicine_id,
        scheduled_time,
    )

    if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({
            "ok": True,
            "status": status,
            "scheduled_time": scheduled_time.isoformat(timespec="seconds"),
            "remaining_qty": remaining_qty,
            "threshold": threshold,
            "refill_alert": refill_alert,
        })

    if refill_alert and status == "TAKEN":
        flash(
            f"Refill alert: {med['name']} is running low "
            f"({remaining_qty} remaining, threshold {threshold}).",
            "warning",
        )

    flash(f"Dose logged as {status.title()}.", "success")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/medicines/<int:medicine_id>/refill", methods=["POST"])
@login_required
def refill_medicine(medicine_id):
    key = _current_key()
    add_qty = request.form.get("add_qty", type=int) or 0

    conn = db.get_connection()
    med = _owned_medicine(conn, medicine_id)
    refill = conn.execute("SELECT * FROM Refill_Details WHERE medicine_id = ?", (medicine_id,)).fetchone()
    if not med or not refill or add_qty <= 0 or add_qty > 10000:
        conn.close()
        flash("No refill record found.", "danger")
        return redirect(request.referrer or url_for("dashboard"))

    remaining = int(decrypt_field(refill["remaining_qty"], key) or 0)
    new_remaining = remaining + add_qty

    conn.execute(
        "UPDATE Refill_Details SET remaining_qty = ?, last_refill_date = ? WHERE refill_id = ?",
        (encrypt_field(str(new_remaining), key),
         encrypt_field(datetime.now().strftime(DATE_FMT), key), refill["refill_id"]),
    )
    conn.commit()
    conn.close()
    flash(f"Refilled: {add_qty} added, {new_remaining} now remaining.", "success")
    return redirect(request.referrer or url_for("dashboard"))


# ---------------------------------------------------------------------------
# Medicine autocomplete (Section IV-D)
# ---------------------------------------------------------------------------

@app.route("/api/medicine-autocomplete")
@login_required
def medicine_autocomplete():
    q = request.args.get("q", "")
    return jsonify(search_medicines(q))


# ---------------------------------------------------------------------------
# Notification Manager integration
# ---------------------------------------------------------------------------

def _parse_schedule_times(time_of_day):
    """
    Return a list of time strings accepted by notification_manager.py.

    The database keeps the existing single TEXT field so existing records
    remain compatible. Multiple times may be entered as comma-separated
    values, for example:

        08:00, 20:00

    Both 24-hour and common 12-hour values are accepted by the manager.
    """
    if not time_of_day:
        return []

    values = [value.strip() for value in time_of_day.split(",") if value.strip()]
    if not values or len(values) > 6:
        return []
    for value in values:
        if not any(_is_time(value, fmt) for fmt in ("%H:%M", "%I:%M %p", "%I %p")):
            return []
    return values


def _is_time(value, fmt):
    try:
        datetime.strptime(value, fmt)
        return True
    except ValueError:
        return False


def _notification_schedule_provider():
    """
    Provide medication schedules for currently authenticated local users.

    The notification engine only receives data needed to schedule reminders.
    Encrypted dates are decrypted here, inside the application/security layer.
    """

    if not _ACTIVE_USERS:
        return []

    schedules = []
    seen_users = set()

    conn = db.get_connection()

    try:
        for user_id, key in list(_ACTIVE_USERS.items()):
            if user_id in seen_users:
                continue

            seen_users.add(user_id)

            rows = conn.execute(
                """
                SELECT
                    m.medicine_id,
                    m.patient_id,
                    m.name,
                    m.time_of_day,
                    m.start_date,
                    m.end_date
                FROM Medicine_Details m
                JOIN Patient_Details p
                  ON p.patient_id = m.patient_id
                WHERE p.user_id = ?
                  AND m.active = 1
                """,
                (user_id,),
            ).fetchall()

            today = datetime.now().date()

            for row in rows:
                start_date = decrypt_field(row["start_date"], key)
                end_date = decrypt_field(row["end_date"], key)

                # Respect the medicine's encrypted treatment dates.
                if start_date:
                    try:
                        if today < datetime.strptime(
                            start_date, DATE_FMT
                        ).date():
                            continue
                    except ValueError:
                        pass

                if end_date:
                    try:
                        if today > datetime.strptime(
                            end_date, DATE_FMT
                        ).date():
                            continue
                    except ValueError:
                        pass

                times = _parse_schedule_times(row["time_of_day"])

                if not times:
                    continue

                schedules.append({
                    "user_id": user_id,
                    "patient_id": row["patient_id"],
                    "medicine_id": row["medicine_id"],
                    "medicine_name": row["name"],
                    "scheduled_times": times,
                })

    finally:
        conn.close()

    return schedules


def _dose_exists_for_schedule(
    user_id,
    medicine_id,
    scheduled_time,
):
    """
    Check whether a particular scheduled dose already has a compliance log.

    Compliance status is encrypted at rest, so this function only checks
    for the presence of a log at the exact scheduled timestamp.
    """

    # Only allow checks for active local users.
    if user_id not in _ACTIVE_USERS:
        return False

    conn = db.get_connection()

    try:
        row = conn.execute(
            """
            SELECT log_id
            FROM Compliance_Log
            WHERE medicine_id = ?
              AND scheduled_time = ?
            LIMIT 1
            """,
            (
                medicine_id,
                scheduled_time.isoformat(timespec="seconds"),
            ),
        ).fetchone()

        return row is not None

    finally:
        conn.close()


def _record_automatic_dose(
    user_id,
    medicine_id,
    status,
    scheduled_time,
):
    """
    Secure application-layer callback used by the notification engine.

    Automatic MISSED records are encrypted with the same AES key used by
    the logged-in caregiver session.
    """

    if status not in ("TAKEN", "MISSED"):
        return False

    key = _ACTIVE_USERS.get(user_id)

    if key is None:
        return False

    conn = db.get_connection()

    try:
        # Verify that this medicine belongs to the user's patient.
        med = conn.execute(
            """
            SELECT m.*
            FROM Medicine_Details m
            JOIN Patient_Details p
              ON p.patient_id = m.patient_id
            WHERE m.medicine_id = ?
              AND p.user_id = ?
              AND m.active = 1
            """,
            (medicine_id, user_id),
        ).fetchone()

        if not med:
            return False

        scheduled_iso = scheduled_time.isoformat(timespec="seconds")

        # Prevent duplicate automatic logs.
        existing = conn.execute(
            """
            SELECT log_id
            FROM Compliance_Log
            WHERE medicine_id = ?
              AND scheduled_time = ?
            LIMIT 1
            """,
            (medicine_id, scheduled_iso),
        ).fetchone()

        if existing:
            return True

        conn.execute(
            """
            INSERT INTO Compliance_Log
                (medicine_id, scheduled_time, status)
            VALUES (?, ?, ?)
            """,
            (
                medicine_id,
                scheduled_iso,
                encrypt_field(status, key),
            ),
        )

        conn.commit()

        print(
            "[NotificationManager] "
            f"Automatically recorded {status} for "
            f"medicine_id={medicine_id}, "
            f"scheduled_time={scheduled_iso}"
        )

        return True

    finally:
        conn.close()


@app.route("/api/notifications")
@login_required
def notifications_api():
    """
    Return locally generated medication reminders to the browser.
    """

    return jsonify(get_notifications(session["user_id"]))


# Register the callbacks after the functions are defined.
register_schedule_provider(_notification_schedule_provider)
register_dose_logger(_record_automatic_dose)
register_dose_exists_checker(_dose_exists_for_schedule)


# ---------------------------------------------------------------------------
# Reports (Section IV-C, IV-E)
# ---------------------------------------------------------------------------

def _expected_doses(medicine, key, since_dt, until_dt):
    """Build expected dose timestamps from the prescribed schedule and dates."""
    times = _parse_schedule_times(medicine["time_of_day"])
    parsed_times = []
    for value in times:
        for fmt in ("%H:%M", "%I:%M %p", "%I %p"):
            try:
                parsed_times.append(datetime.strptime(value, fmt).time())
                break
            except ValueError:
                continue
    start_date = decrypt_field(medicine["start_date"], key)
    end_date = decrypt_field(medicine["end_date"], key)
    first_day = max(since_dt.date(), datetime.strptime(start_date, DATE_FMT).date()) if start_date else since_dt.date()
    last_day = min(until_dt.date(), datetime.strptime(end_date, DATE_FMT).date()) if end_date else until_dt.date()
    expected = []
    while first_day <= last_day:
        expected.extend(datetime.combine(first_day, t) for t in parsed_times if since_dt <= datetime.combine(first_day, t) <= until_dt)
        first_day += timedelta(days=1)
    return expected


def _compliance_summary(conn, key, patient_id, since_iso=None):
    since_dt = datetime.fromisoformat(since_iso) if since_iso else datetime.now() - timedelta(days=30)
    until_dt = datetime.now()
    meds = conn.execute(
        "SELECT * FROM Medicine_Details WHERE patient_id = ? AND active = 1",
        (patient_id,),
    ).fetchall()
    summary = []
    for m in meds:
        query = "SELECT * FROM Compliance_Log WHERE medicine_id = ?"
        params = [m["medicine_id"]]
        if since_iso:
            query += " AND scheduled_time >= ?"
            params.append(since_iso)
        logs = conn.execute(query, params).fetchall()

        taken = missed = 0
        for log in logs:
            status = decrypt_field(log["status"], key)
            if status == "TAKEN":
                taken += 1
            elif status == "MISSED":
                missed += 1
        scheduled = len(_expected_doses(m, key, since_dt, until_dt))
        unconfirmed = max(0, scheduled - taken - missed)
        adherence = (taken / scheduled * 100) if scheduled > 0 else 0.0
        summary.append({"medicine": m["name"], "scheduled": scheduled,
                         "taken": taken, "missed": missed, "unconfirmed": unconfirmed,
                         "adherence": adherence})
    return summary


def _refill_status(conn, key, patient_id):
    meds = conn.execute(
        "SELECT * FROM Medicine_Details WHERE patient_id = ? AND active = 1",
        (patient_id,),
    ).fetchall()
    out = []
    for m in meds:
        refill = conn.execute(
            "SELECT * FROM Refill_Details WHERE medicine_id = ? ORDER BY refill_id DESC LIMIT 1",
            (m["medicine_id"],),
        ).fetchone()
        if refill:
            remaining = int(decrypt_field(refill["remaining_qty"], key) or 0)
            out.append({
                "medicine": m["name"], "remaining_qty": remaining,
                "threshold": _encrypted_int(refill["threshold"], key),
                "alert": (remaining - 1) < _encrypted_int(refill["threshold"], key),
                "last_refill_date": decrypt_field(refill["last_refill_date"], key),
            })
    return out


@app.route("/patients/<int:patient_id>/reports/weekly")
@login_required
def weekly_report(patient_id):
    key = _current_key()
    conn = db.get_connection()
    p = conn.execute("SELECT * FROM Patient_Details WHERE patient_id = ? AND user_id = ?",
                      (patient_id, session["user_id"])).fetchone()
    if not p:
        conn.close()
        flash("Patient not found.", "danger")
        return redirect(url_for("dashboard"))

    patient_info = {
        "name": decrypt_field(p["name"], key), "dob": decrypt_field(p["dob"], key),
        "gender": p["gender"], "contact_number": decrypt_field(p["contact_number"], key),
        "family_email": decrypt_field(p["family_email"], key),
    }

    meds_raw = conn.execute(
        "SELECT * FROM Medicine_Details WHERE patient_id = ? AND active = 1", (patient_id,)
    ).fetchall()
    medicines = [{
        "name": m["name"], "dosage": m["dosage"], "frequency": m["frequency"],
        "time_of_day": m["time_of_day"], "start_date": decrypt_field(m["start_date"], key),
        "end_date": decrypt_field(m["end_date"], key),
    } for m in meds_raw]

    since = (datetime.now() - timedelta(days=7)).isoformat(timespec="seconds")
    compliance_summary = _compliance_summary(conn, key, patient_id, since_iso=since)
    refills = _refill_status(conn, key, patient_id)

    last_visit_row = conn.execute(
        """SELECT v.*, d.name AS doctor_name_enc FROM Visit_Details v
           LEFT JOIN Doctor_Details d ON v.doctor_id = d.doctor_id
           WHERE v.patient_id = ? ORDER BY v.visit_id DESC LIMIT 1""",
        (patient_id,),
    ).fetchone()
    last_visit = {
        "doctor_name": decrypt_field(last_visit_row["doctor_name_enc"], key) if last_visit_row and last_visit_row["doctor_name_enc"] else "N/A",
        "visit_date": decrypt_field(last_visit_row["visit_date"], key) if last_visit_row else "-",
        "notes": decrypt_field(last_visit_row["notes"], key) if last_visit_row and last_visit_row["notes"] else "-",
    }
    next_visit = {
        "doctor_name": last_visit["doctor_name"],
        "visit_date": decrypt_field(last_visit_row["next_visit_date"], key) if last_visit_row else "-",
    }

    conn.close()
    pdf_bytes = generate_weekly_report(patient_info, medicines, compliance_summary,
                                        refills, last_visit, next_visit)
    filename = f"weekly_report_{patient_info['name'] or patient_id}_{datetime.now().strftime('%Y%m%d')}.pdf"
    return send_file(
        __import__("io").BytesIO(pdf_bytes), mimetype="application/pdf",
        as_attachment=True, download_name=filename,
    )


@app.route("/patients/<int:patient_id>/reports/visit-summary")
@login_required
def visit_summary_report(patient_id):
    key = _current_key()
    conn = db.get_connection()
    p = conn.execute("SELECT * FROM Patient_Details WHERE patient_id = ? AND user_id = ?",
                      (patient_id, session["user_id"])).fetchone()
    if not p:
        conn.close()
        flash("Patient not found.", "danger")
        return redirect(url_for("dashboard"))

    patient_info = {"name": decrypt_field(p["name"], key), "dob": decrypt_field(p["dob"], key),
                     "gender": p["gender"]}

    last_visit_row = conn.execute(
        """SELECT v.*, d.name AS doctor_name_enc FROM Visit_Details v
           LEFT JOIN Doctor_Details d ON v.doctor_id = d.doctor_id
           WHERE v.patient_id = ? ORDER BY v.visit_id DESC LIMIT 1""",
        (patient_id,),
    ).fetchone()
    last_visit = {
        "doctor_name": decrypt_field(last_visit_row["doctor_name_enc"], key) if last_visit_row and last_visit_row["doctor_name_enc"] else "N/A",
        "visit_date": decrypt_field(last_visit_row["visit_date"], key) if last_visit_row else "-",
        "notes": decrypt_field(last_visit_row["notes"], key) if last_visit_row and last_visit_row["notes"] else "-",
    }

    since = (decrypt_field(last_visit_row["visit_date"], key) + "T00:00:00") if last_visit_row else (datetime.now() - timedelta(days=30)).isoformat(timespec="seconds")
    compliance = _compliance_summary(conn, key, patient_id, since_iso=since)
    medicines_since = []
    meds_raw = conn.execute(
        "SELECT * FROM Medicine_Details WHERE patient_id = ? AND active = 1", (patient_id,)
    ).fetchall()
    comp_by_name = {c["medicine"]: c for c in compliance}
    for m in meds_raw:
        c = comp_by_name.get(m["name"], {"adherence": 0.0, "missed": 0})
        medicines_since.append({"name": m["name"], "dosage": m["dosage"],
                                 "adherence": c["adherence"], "missed": c["missed"]})

    conn.close()
    pdf_bytes = generate_visit_summary_report(patient_info, medicines_since, last_visit)
    filename = f"visit_summary_{patient_info['name'] or patient_id}_{datetime.now().strftime('%Y%m%d')}.pdf"
    return send_file(
        __import__("io").BytesIO(pdf_bytes), mimetype="application/pdf",
        as_attachment=True, download_name=filename,
    )


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    db.init_db()

    # Start the fully local/offline notification worker.
    start_notification_manager()

    try:
        app.run(debug=False, host="127.0.0.1", port=5000)
    finally:
        stop_notification_manager()
