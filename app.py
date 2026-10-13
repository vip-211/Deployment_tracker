import logging
import json
import os
import secrets
import hashlib
import hmac
from datetime import datetime, time, timedelta,date
from pathlib import Path
import re
import psycopg2
from psycopg2 import errors
from dotenv import load_dotenv
from flask import (Flask,flash,jsonify,redirect,render_template,request,url_for,session)

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "")
if not app.secret_key:
    raise RuntimeError(
        "FLASK_SECRET_KEY is missing. Add it to your .env file."
    )

# Keep AUDIT_PASSCODE_PEPPER stable across restarts; existing passcodes depend on it.
AUDIT_PASSCODE_PEPPER = os.getenv("AUDIT_PASSCODE_PEPPER") or app.secret_key
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(
            LOG_DIR / "app.log",
            encoding="utf-8",
        ),
        logging.StreamHandler(),
    ],
)

CHANGE_TYPES = [
    "Normal CR",
    "Emergency CR",
    "Standard CR",
    "Forward Fix CR",
    "Bug Fix CR",
]

DEPLOYMENT_TYPES = ["Automation", "Manual"]

VERIFIED_BY_OPTIONS = ["DBA TEAM", "MW TEAM", "DevOps Team"]

STATUSES = ["Pending","Approved","Rejected","Scheduled","In Progress","Successful","Failed","Rolled Back","Cancelled"]

SLOT_STARTS = ["18:30","19:00","19:30","20:00","20:30","21:00","21:30","22:00","22:30","23:00"]

SLOT_CONSTRAINT = "no_overlapping_deployment_slots"
# def get_connection():
#     return psycopg2.connect(
#         host=os.environ["DB_HOST"],
#         port=int(os.getenv("DB_PORT", "5432")),
#         dbname=os.environ["DB_NAME"],
#         user=os.environ["DB_USER"],
#         password=os.environ["DB_PASSWORD"],
#         sslmode=os.getenv("DB_SSLMODE", "require"),
#         connect_timeout=15,
#         application_name="Flask Deployment Tracker",
#     )

def get_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT", "5432")),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        sslmode="disable",
        connect_timeout=10
    )

def normalize_audit_email(value):
    """Normalize and validate an email used as a Modified By identity."""
    email = (value or "").strip().lower()
    if len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("Enter a valid email address for Modified By.")
    return email


def audit_passcode_digest(passcode):
    """Return a deterministic keyed digest so passcodes are not stored as text."""
    return hmac.new(
        AUDIT_PASSCODE_PEPPER.encode("utf-8"),
        ("deployment-tracker-audit-v1:" + passcode).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def get_audit_user_emails():
    """Fetch registered audit identities for the Modified By dropdown."""
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT email FROM public.audit_users ORDER BY email")
            return [row[0] for row in cur.fetchall()]
    except Exception:
        app.logger.exception("Could not load audit user registry; run audit_user_registry.sql")
        return []
    finally:
        if conn is not None:
            conn.close()


def verify_audit_user_credentials(email_value, passcode):
    """Verify email + its unique 4-digit code and apply a five-failure lockout."""
    try:
        email = normalize_audit_email(email_value)
    except ValueError as exc:
        return False, str(exc), 400

    if not re.fullmatch(r"\d{4}", str(passcode or "")):
        return False, "Enter the 4-digit passcode for this email address.", 400

    conn = None
    try:
        conn = get_connection()
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT passcode_digest, failed_attempts, locked_until
                FROM public.audit_users
                WHERE email = %s
                FOR UPDATE
                """,
                (email,),
            )
            row = cur.fetchone()
            if row is None:
                conn.rollback()
                return False, "This email is not registered. Select Add Email to register it.", 401

            stored_digest, failed_attempts, locked_until = row
            now = datetime.now()
            if locked_until and locked_until > now:
                remaining = max(1, int((locked_until - now).total_seconds() // 60) + 1)
                conn.commit()
                return False, f"Too many failed attempts. Try again in about {remaining} minute(s).", 429

            if locked_until and locked_until <= now:
                failed_attempts = 0
                cur.execute(
                    "UPDATE public.audit_users SET failed_attempts = 0, locked_until = NULL WHERE email = %s",
                    (email,),
                )

            candidate_digest = audit_passcode_digest(str(passcode))
            if hmac.compare_digest(str(stored_digest).strip(), candidate_digest):
                cur.execute(
                    """
                    UPDATE public.audit_users
                    SET failed_attempts = 0,
                        locked_until = NULL,
                        last_used_at = CURRENT_TIMESTAMP
                    WHERE email = %s
                    """,
                    (email,),
                )
                conn.commit()
                return True, email, 200

            new_failures = int(failed_attempts or 0) + 1
            if new_failures >= 5:
                cur.execute(
                    """
                    UPDATE public.audit_users
                    SET failed_attempts = %s,
                        locked_until = %s
                    WHERE email = %s
                    """,
                    (new_failures, now + timedelta(minutes=15), email),
                )
                conn.commit()
                return False, "Five incorrect attempts reached. This email is locked for 15 minutes.", 429

            cur.execute(
                "UPDATE public.audit_users SET failed_attempts = %s WHERE email = %s",
                (new_failures, email),
            )
            conn.commit()
            return False, f"Incorrect passcode. {5 - new_failures} attempt(s) remaining before a 15-minute lock.", 401

    except Exception:
        if conn is not None:
            conn.rollback()
        app.logger.exception("Audit user passcode verification failed")
        return False, "Audit identity storage is unavailable. Run audit_user_registry.sql and retry.", 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/audit-users/register", methods=["POST"])
def register_audit_user():
    """Register a new email and return its unique passcode only once."""
    payload = request.get_json(silent=True) or {}
    try:
        email = normalize_audit_email(payload.get("email"))
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400

    conn = None
    try:
        conn = get_connection()
        # Each INSERT is an independent transaction. ON CONFLICT protects both
        # email uniqueness and the global unique-passcode rule under concurrency.
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM public.audit_users WHERE email = %s", (email,))
            if cur.fetchone():
                return jsonify({
                    "success": False,
                    "message": "This email is already registered. Select it and enter its passcode.",
                }), 409

            for _ in range(500):
                passcode = f"{secrets.randbelow(10000):04d}"
                digest = audit_passcode_digest(passcode)
                cur.execute(
                    """
                    INSERT INTO public.audit_users (email, passcode_digest)
                    VALUES (%s, %s)
                    ON CONFLICT DO NOTHING
                    RETURNING email
                    """,
                    (email, digest),
                )
                if cur.fetchone():
                    app.logger.info("Audit identity registered: %s", email)
                    return jsonify({
                        "success": True,
                        "email": email,
                        "passcode": passcode,
                        "message": "Email registered. Save this 4-digit passcode now; it will not be shown again.",
                    }), 201

                # If the email won a concurrent registration, do not generate a
                # second passcode for it. If only the code collided, try another.
                cur.execute("SELECT 1 FROM public.audit_users WHERE email = %s", (email,))
                if cur.fetchone():
                    return jsonify({
                        "success": False,
                        "message": "This email is already registered. Select it and enter its passcode.",
                    }), 409

            return jsonify({
                "success": False,
                "message": "Could not find an unused 4-digit passcode. Contact the application administrator.",
            }), 503
    except Exception:
        app.logger.exception("Audit user registration failed")
        return jsonify({
            "success": False,
            "message": "Could not register the email. Ensure audit_user_registry.sql has been applied.",
        }), 500
    finally:
        if conn is not None:
            conn.close()


def is_manager_user():
    return str(session.get("role", "")).strip().lower() == "manager"

def validate_deployment_date(deployment_date, is_manager=False):
    """
    Engineers: only today or future weekdays.
    Managers: may override past-date and weekend restrictions.
    """
    if is_manager:
        return
    if deployment_date < date.today():
        raise ValueError(
            "Past deployment dates are not allowed. Please choose today or a future date."
        )
    if deployment_date.weekday() in (5, 6):
        raise ValueError(
            "Deployments cannot be booked on Saturday or Sunday."
        )

def write_audit_log(level, message,cr_number=None,rfid=None):
    """Write to the application log and, when available, the DB log."""
    app.logger.log(
        getattr(logging, level.upper(), logging.INFO),
        message,
    )
    conn = None
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO public.deployment_tracker_logs
                        (
                            event_time,
                            log_level,
                            message,
                            cr_number,
                            rfid
                        )
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        datetime.now(),
                        level.upper(),
                        message[:2000],
                        cr_number,
                        rfid,
                    ),
                )
    except Exception:
        app.logger.exception(
            "Could not write to deployment_tracker_logs"
        )
    finally:
        if conn is not None:
            conn.close()

def insert_change_history(cur, deployment_id, cr_number, rfid, modified_by, action, changes):
    """Persist field-level audit history in the same transaction as the update."""
    cur.execute(
        """
        INSERT INTO public.deployment_change_history
            (deployment_id, cr_number, rfid, modified_by, action, changes)
        VALUES (%s, %s, %s, %s, %s, %s::jsonb)
        """,
        (
            deployment_id,
            cr_number,
            rfid,
            modified_by,
            action,
            json.dumps(changes, default=lambda value: value.isoformat() if hasattr(value, "isoformat") else str(value)),
        ),
    )


def audit_value(value):
    """Convert database values to JSON-friendly values for old/new snapshots."""
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    return value


def generate_rfid():
    return f"{secrets.randbelow(100_000_000):08d}"

def get_existing_rfid(cur, cr_number):
    """Find the RFID associated with a CR, ignoring case and spaces."""
    cur.execute(
        """
        SELECT rfid
        FROM public.deployment_tracker
        WHERE LOWER(TRIM(cr_number)) = LOWER(TRIM(%s))
          AND rfid IS NOT NULL
        ORDER BY id
        LIMIT 1
        """,
        (cr_number,),
    )
    row = cur.fetchone()
    return row[0] if row else None

def save_deployment(data):
    cr_number = (data.get("cr_number") or "").strip()
    cr_number = re.sub(
        r"^CR-", "", cr_number, flags=re.IGNORECASE
    ).strip()
    if not cr_number.isdigit():
        raise ValueError(
            "CR Number must contain digits after the CR- prefix."
        )
    cr_number = f"CR-{cr_number}"
    application_name = (
        data.get("application_name") or ""
    ).strip()
    change_requestor = (data.get("change_requestor") or "").strip()
    if not change_requestor:
        raise ValueError("Change Requestor is required.")
    if len(change_requestor) > 150:
        raise ValueError("Change Requestor cannot exceed 150 characters.")

    # Released By and Verified and Deployed By are not collected on the
    # Release Calendar form anymore. Store NULL for these optional columns;
    # DevOps can still populate them later from the Governance Tracker.
    released_by = None
    verified_and_deployed_by = None

    if not cr_number:
        raise ValueError("CR Number is required.")
    if not application_name:
        raise ValueError("Application Name is required.")
    try:
        deployment_date = datetime.strptime(
            data["deployment_date"],
            "%Y-%m-%d",
        ).date()
        start_time = datetime.strptime(
            data["slot_start"],
            "%H:%M",
        ).time()
    except (ValueError, KeyError) as exc:
        raise ValueError(
            "Enter a valid deployment date and time slot."
        ) from exc
    validate_deployment_date(
        deployment_date,
        is_manager=is_manager_user(),
    )
    if start_time.strftime("%H:%M") not in SLOT_STARTS:
        raise ValueError(
            "Choose a 30-minute slot between 6:30 PM and 11:00 PM."
        )
    if data.get("deployment_type") not in DEPLOYMENT_TYPES:
        raise ValueError("Invalid deployment type.")
    if data.get("change_type") not in CHANGE_TYPES:
        raise ValueError("Invalid change type.")
    data["status"] = "Pending"

    # Roll Back is no longer collected on the Release Calendar form.
    # Keep the database field valid by defaulting new requests to "No".
    roll_back = (data.get("roll_back") or "No").strip()
    if roll_back not in ("Yes", "No"):
        raise ValueError("Invalid rollback selection.")
    data["roll_back"] = roll_back

    slot_start = datetime.combine(
        deployment_date,
        start_time,
    )
    slot_end = slot_start + timedelta(minutes=30)
    conn = None
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                normalized_cr = cr_number.casefold()
                cur.execute(
                    """
                    SELECT pg_advisory_xact_lock(hashtext(%s))
                    """,
                    (normalized_cr,),
                )
                rfid = get_existing_rfid(cur, cr_number)
                if not rfid:
                    for _ in range(20):
                        candidate = generate_rfid()
                        cur.execute(
                            """
                            SELECT 1
                            FROM public.deployment_tracker
                            WHERE rfid = %s
                            LIMIT 1
                            """,
                            (candidate,),
                        )
                        if cur.fetchone() is None:
                            rfid = candidate
                            break
                    if not rfid:
                        raise RuntimeError(
                            "Could not generate an available RFID. "
                            "Please retry."
                        )
                cur.execute(
                             """
                             SELECT status
                             FROM public.deployment_tracker
                             WHERE slot_start < %s
                               AND slot_end > %s
                              AND LOWER(TRIM(COALESCE(status, '')))
                              NOT IN ('cancelled', 'rejected')
                                 LIMIT 1
                                  """,
                      (slot_end, slot_start),
                                )
                occupied = cur.fetchone()
                if occupied:
                    status = (occupied[0] or "Booked").strip()
                    raise ValueError(
                        f"This slot is unavailable ({status}). "
                        "Please choose a green slot."
                    )
                cur.execute(
                    """
                    INSERT INTO public.deployment_tracker (
                        cr_number,
                        rfid,
                        deployment_date,
                        slots,
                        slot_start,
                        slot_end,
                        application_name,
                        deployment_type,
                        change_type,
                        released_by,
                        verified_and_deployed_by,
                        change_requestor,
                        release_notes,
                        incident_number,
                        roll_back,
                        status
                    )
                    VALUES (
                        %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s, %s
                    )
                    RETURNING id
                    """,
                    (
                        cr_number,
                        rfid,
                        deployment_date,
                        (
                            f"{slot_start:%H:%M} - "
                            f"{slot_end:%H:%M}"
                        ),
                        slot_start,
                        slot_end,
                        application_name,
                        data["deployment_type"],
                        data["change_type"],
                        released_by,
                        verified_and_deployed_by,
                        change_requestor,
                        (
                            data.get("release_notes") or ""
                        ).strip() or None,
                        (
                            data.get("incident_number") or ""
                        ).strip() or None,
                        data["roll_back"],
                        data["status"],
                    ),
                )
                record_id = cur.fetchone()[0]
        write_audit_log(
            "INFO",
            (
                f"Request submitted successfully. "
                f"Record ID={record_id}; slot={slot_start}"
            ),
            cr_number,
            rfid,
        )
        return rfid
    except errors.ExclusionViolation as exc:
        app.logger.warning(
            "Deployment slot conflict for CR %s",
            cr_number,
        )
        raise ValueError(
            "This slot was just booked by another request. "
            "Please refresh and choose another green slot."
        ) from exc
    except errors.UniqueViolation as exc:
        constraint = (
            getattr(exc.diag, "constraint_name", None) or ""
        )
        app.logger.exception(
            "Unique constraint violation: %s",
            constraint,
        )
        raise RuntimeError(
            "A database uniqueness constraint rejected this request. "
            "Check your database constraints and server logs."
        ) from exc
    except psycopg2.Error as exc:
        app.logger.exception(
            "Database save failed; SQLSTATE=%s",
            exc.pgcode,
        )
        raise RuntimeError(
            "Could not save the request to the database. "
            "Check the server logs."
        ) from exc
    finally:
        if conn is not None:
            conn.close()

def get_released_by_users():
    """Fetch existing Released By names from PostgreSQL."""
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT TRIM(released_by)
                FROM public.deployment_tracker
                WHERE NULLIF(TRIM(released_by), '') IS NOT NULL
                ORDER BY 1
            """)
            return [row[0] for row in cur.fetchall()]
    except Exception:
        app.logger.exception(
            "Could not load Released By users"
        )
        return []
    finally:
        if conn is not None:
            conn.close()

def resolve_verified_deployed_by(data):
    """Validate the team selection or required custom name."""
    choice = (data.get("verified_and_deployed_by") or "").strip()

    if choice == "__others__":
        custom_name = (
            data.get("verified_and_deployed_by_other") or ""
        ).strip()
        if not custom_name:
            raise ValueError(
                "Please enter a name for Verified and Deployed By."
            )
        if len(custom_name) > 100:
            raise ValueError(
                "Verified and Deployed By name cannot exceed 100 characters."
            )
        return custom_name

    if choice in VERIFIED_BY_OPTIONS:
        return choice

    raise ValueError(
        "Please select DBA TEAM, MW TEAM, DevOps Team, or Others."
    )


def form_context(data=None):
    # Release Calendar no longer collects Released By or Verified and Deployed By.
    # These fields remain available in Governance Tracker for later editing.
    return {
        "data": data or {},
        "change_types": CHANGE_TYPES,
        "deployment_types": DEPLOYMENT_TYPES,
        "statuses": STATUSES,
        "slot_starts": SLOT_STARTS,
    }

@app.route("/governance_tracker", methods=["GET"])

def devops_page():
    return render_template(
        "governance_tracker.html",
        deployment_types=DEPLOYMENT_TYPES,
        change_types=CHANGE_TYPES,
        statuses=STATUSES,
        released_by_users=get_released_by_users(),
        verified_by_options=VERIFIED_BY_OPTIONS,
        audit_user_emails=get_audit_user_emails(),
    )

@app.route("/api/deployment-by-cr", methods=["GET"])

def get_deployment_by_cr():
    cr_number = (request.args.get("cr_number") or "").strip()
    cr_number = re.sub(r"^CR-", "", cr_number, flags=re.IGNORECASE).strip()
    if not cr_number.isdigit():
        return jsonify({
            "success": False,
            "message": "Enter a valid CR Number, for example CR-12345."
        }), 400
    normalized_cr = f"CR-{cr_number}"
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                id,
                cr_number,
                rfid,
                deployment_date,
                slot_start,
                slot_end,
                slots,
                application_name,
                deployment_type,
                change_type,
                released_by,
                verified_and_deployed_by,
                change_requestor,
                release_notes,
                incident_number,
                roll_back,
                status
            FROM public.deployment_tracker
            WHERE UPPER(
                REGEXP_REPLACE(TRIM(cr_number), '^CR-', '', 'i')
            ) = %s
            ORDER BY id DESC
            LIMIT 1
            """,
            (cr_number.upper(),)
        )
        row = cursor.fetchone()
        if not row:
            return jsonify({
                "success": False,
                "message": f"No deployment found for {normalized_cr}."
            }), 404
        columns = [description[0] for description in cursor.description]
        deployment = dict(zip(columns, row))
        for key, value in deployment.items():
            if isinstance(value, (datetime, date, time)):
                deployment[key] = value.isoformat()
            elif value is not None and not isinstance(
                value, (str, int, float, bool)
            ):
                deployment[key] = str(value)
        deployment["cr_number"] = normalized_cr
        return jsonify({
            "success": True,
            "message": "Deployment details retrieved successfully.",
            "deployment": deployment
        })
    except Exception:
        app.logger.exception("DevOps CR lookup failed")
        return jsonify({
            "success": False,
            "message": "Could not retrieve deployment details. Check the server logs."
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route("/api/deployment-by-id/<int:deployment_id>", methods=["PUT"])

def update_devops_deployment(deployment_id):
    """Update an existing deployment row from the DevOps page."""
    data = request.get_json(silent=True) or {}
    try:
        modified_by = normalize_audit_email(data.get("modified_by"))
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400
    modified_by_passcode = str(data.get("modified_by_passcode") or "").strip()
    if not re.fullmatch(r"\d{4}", modified_by_passcode):
        return jsonify({"success": False, "message": "Enter the 4-digit passcode for the selected email."}), 400

    required_fields = [
        "deployment_date", "slot_start", "application_name",
        "deployment_type", "change_type", "roll_back", "status",
        "released_by", "verified_and_deployed_by", "change_requestor",
    ]
    for field in required_fields:
        if not str(data.get(field) or "").strip():
            return jsonify({
                "success": False,
                "message": f"{field.replace('_', ' ').title()} is required.",
            }), 400
    if data["deployment_type"] not in DEPLOYMENT_TYPES:
        return jsonify({"success": False, "message": "Invalid deployment type."}), 400
    if data["change_type"] not in CHANGE_TYPES:
        return jsonify({"success": False, "message": "Invalid change type."}), 400
    if data["status"] not in STATUSES:
        return jsonify({"success": False, "message": "Invalid status."}), 400
    if data["roll_back"] not in ("Yes", "No"):
        return jsonify({"success": False, "message": "Invalid rollback selection."}), 400

    released_by = (data.get("released_by") or "").strip()
    if not released_by or released_by == "__add__":
        return jsonify({
            "success": False,
            "message": "Select a Released By user or enter a new name.",
        }), 400
    if len(released_by) > 100:
        return jsonify({
            "success": False,
            "message": "Released By name cannot exceed 100 characters.",
        }), 400

    try:
        verified_and_deployed_by = resolve_verified_deployed_by(data)
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400

    change_requestor = (data.get("change_requestor") or "").strip()
    if not change_requestor:
        return jsonify({
            "success": False,
            "message": "Change Requestor is required.",
        }), 400
    if len(change_requestor) > 150:
        return jsonify({
            "success": False,
            "message": "Change Requestor cannot exceed 150 characters.",
        }), 400

    try:
        deployment_date = datetime.strptime(data["deployment_date"], "%Y-%m-%d").date()
        start_time = datetime.strptime(data["slot_start"], "%H:%M").time()
    except ValueError:
        return jsonify({"success": False, "message": "Invalid deployment date or slot."}), 400
    # Governance Tracker edits may update historical deployment dates.
    # Keep date-format validation above and slot-time validation below, but do
    # not apply the booking-only past-date/weekend restriction to edits here.
    if start_time.strftime("%H:%M") not in SLOT_STARTS:
        return jsonify({
            "success": False,
            "message": "Choose a 30-minute slot between 6:30 PM and 11:00 PM.",
        }), 400
    if not data["application_name"].strip():
        return jsonify({"success": False, "message": "Application Name is required."}), 400

    credentials_ok, credential_message, credential_status = verify_audit_user_credentials(
        modified_by, modified_by_passcode
    )
    if not credentials_ok:
        return jsonify({"success": False, "message": credential_message}), credential_status

    slot_start = datetime.combine(deployment_date, start_time)
    slot_end = slot_start + timedelta(minutes=30)
    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.autocommit = False
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, cr_number, rfid, deployment_date, slot_start, slot_end,
                   application_name, deployment_type, change_type, released_by,
                   verified_and_deployed_by, change_requestor, release_notes,
                   incident_number, roll_back, status
            FROM public.deployment_tracker
            WHERE id = %s
            FOR UPDATE
            """,
            (deployment_id,),
        )
        old_row = cursor.fetchone()
        if old_row is None:
            conn.rollback()
            return jsonify({"success": False, "message": "Deployment record not found."}), 404
        old_columns = [description[0] for description in cursor.description]
        old_record = dict(zip(old_columns, old_row))
        cursor.execute(
            """
            UPDATE public.deployment_tracker
            SET deployment_date = %s,
                slots = %s,
                slot_start = %s,
                slot_end = %s,
                application_name = %s,
                deployment_type = %s,
                change_type = %s,
                released_by = %s,
                verified_and_deployed_by = %s,
                change_requestor = %s,
                release_notes = %s,
                incident_number = %s,
                roll_back = %s,
                status = %s
            WHERE id = %s
            """,
            (
                deployment_date,
                f"{slot_start:%H:%M} - {slot_end:%H:%M}",
                slot_start,
                slot_end,
                data["application_name"].strip(),
                data["deployment_type"],
                data["change_type"],
                released_by,
                verified_and_deployed_by,
                change_requestor,
                (data.get("release_notes") or "").strip() or None,
                (data.get("incident_number") or "").strip() or None,
                data["roll_back"],
                data["status"],
                deployment_id,
            ),
        )
        new_record = {
            "deployment_date": deployment_date,
            "slot_start": slot_start,
            "slot_end": slot_end,
            "application_name": data["application_name"].strip(),
            "deployment_type": data["deployment_type"],
            "change_type": data["change_type"],
            "released_by": released_by,
            "verified_and_deployed_by": verified_and_deployed_by,
            "change_requestor": change_requestor,
            "release_notes": (data.get("release_notes") or "").strip() or None,
            "incident_number": (data.get("incident_number") or "").strip() or None,
            "roll_back": data["roll_back"],
            "status": data["status"],
        }
        changes = {}
        for field, new_value in new_record.items():
            old_value = old_record.get(field)
            if audit_value(old_value) != audit_value(new_value):
                changes[field] = {
                    "old": audit_value(old_value),
                    "new": audit_value(new_value),
                }
        if changes:
            insert_change_history(
                cursor,
                deployment_id,
                old_record.get("cr_number"),
                old_record.get("rfid"),
                modified_by,
                "Updated",
                changes,
            )
        conn.commit()
        write_audit_log(
            "INFO",
            f"DevOps updated deployment record ID={deployment_id}; changed_by={modified_by}; fields={','.join(changes.keys()) or 'no changes'}",
            old_record.get("cr_number"),
            old_record.get("rfid"),
        )
        return jsonify({"success": True, "message": "Deployment details updated successfully."})
    except errors.ExclusionViolation:
        if conn:
            conn.rollback()
        return jsonify({
            "success": False,
            "message": "This slot is already occupied. Choose another available slot.",
        }), 409
    except psycopg2.Error:
        if conn:
            conn.rollback()
        app.logger.exception("DevOps deployment update failed")
        return jsonify({"success": False, "message": "Database update failed. Check server logs."}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route("/api/pending-deployments", methods=["GET"])

def pending_deployments():
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                id,
                cr_number,
                rfid,
                deployment_date,
                slot_start,
                slot_end,
                slots,
                application_name,
                deployment_type,
                change_type,
                released_by,
                verified_and_deployed_by,
                change_requestor,
                release_notes,
                incident_number,
                roll_back,
                status
            FROM public.deployment_tracker
            WHERE LOWER(TRIM(COALESCE(status, 'Pending'))) = 'pending'
            ORDER BY id DESC
        """)
        columns = [column[0] for column in cursor.description]
        requests_list = []
        for row in cursor.fetchall():
            record = dict(zip(columns, row))
            for key, value in record.items():
                if isinstance(value, (datetime, date, time)):
                    record[key] = value.isoformat()
                elif value is not None and not isinstance(
                    value, (str, int, float, bool)
                ):
                    record[key] = str(value)
            requests_list.append(record)
        return jsonify({
            "success": True,
            "requests": requests_list,
            "count": len(requests_list)
        })
    except Exception:
        app.logger.exception("Unable to load pending requests")
        return jsonify({
            "success": False,
            "message": "Unable to load pending requests."
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/deployments-by-date", methods=["GET"])
def deployments_by_date():
    """Return deployment records for the selected local calendar date."""
    date_text = (request.args.get("date") or "").strip()
    try:
        selected_date = date.fromisoformat(date_text)
    except ValueError:
        return jsonify({
            "success": False,
            "message": "Choose a valid date in YYYY-MM-DD format.",
        }), 400

    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                id,
                cr_number,
                rfid,
                deployment_date,
                slot_start,
                slot_end,
                slots,
                application_name,
                deployment_type,
                change_type,
                released_by,
                verified_and_deployed_by,
                change_requestor,
                release_notes,
                incident_number,
                roll_back,
                status
            FROM public.deployment_tracker
            WHERE deployment_date = %s
            ORDER BY slot_start NULLS LAST, id ASC
        """, (selected_date,))

        columns = [column[0] for column in cursor.description]
        deployments = []
        for row in cursor.fetchall():
            record = dict(zip(columns, row))
            for key, value in record.items():
                if isinstance(value, (datetime, date, time)):
                    record[key] = value.isoformat()
                elif value is not None and not isinstance(value, (str, int, float, bool)):
                    record[key] = str(value)
            deployments.append(record)

        return jsonify({
            "success": True,
            "date": selected_date.isoformat(),
            "deployments": deployments,
            "count": len(deployments),
        })
    except Exception:
        app.logger.exception("Unable to load deployments for selected date %s", date_text)
        return jsonify({
            "success": False,
            "message": "Unable to load the deployment schedule. Check server logs.",
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route(
    "/api/deployment-approval/<int:deployment_id>",
    methods=["POST"]
)

def decide_deployment_request(deployment_id):
    payload = request.get_json(silent=True) or {}
    try:
        modified_by = normalize_audit_email(payload.get("modified_by"))
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400
    modified_by_passcode = str(payload.get("modified_by_passcode") or "").strip()
    if not re.fullmatch(r"\d{4}", modified_by_passcode):
        return jsonify({"success": False, "message": "Enter the 4-digit passcode for the selected email."}), 400
    decision = (payload.get("decision") or "").strip().lower()
    status_map = {
        "approve": "Approved",
        "reject": "Rejected"
    }
    if decision not in status_map:
        return jsonify({
            "success": False,
            "message": "Decision must be approve or reject."
        }), 400
    credentials_ok, credential_message, credential_status = verify_audit_user_credentials(
        modified_by, modified_by_passcode
    )
    if not credentials_ok:
        return jsonify({"success": False, "message": credential_message}), credential_status
    conn = None
    cursor = None
    new_status = status_map[decision]
    try:
        conn = get_connection()
        conn.autocommit = False
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE public.deployment_tracker
            SET status = %s
            WHERE id = %s
              AND LOWER(TRIM(COALESCE(status, 'Pending'))) = 'pending'
            RETURNING cr_number, rfid
        """, (new_status, deployment_id))
        row = cursor.fetchone()
        if row is None:
            conn.rollback()
            return jsonify({
                "success": False,
                "message": (
                    "Request not found or it is no longer pending. "
                    "Refresh the pending list."
                )
            }), 409
        insert_change_history(
            cursor,
            deployment_id,
            row[0],
            row[1],
            modified_by,
            decision.title(),
            {"status": {"old": "Pending", "new": new_status}},
        )
        conn.commit()
        write_audit_log(
            "INFO",
            f"Deployment request {decision}d: "
            f"ID={deployment_id}, CR={row[0]}, status={new_status}, changed_by={modified_by}",
            row[0],
            row[1]
        )
        return jsonify({
            "success": True,
            "message": f"Request {new_status.lower()} successfully.",
            "status": new_status
        })
    except Exception:
        if conn:
            conn.rollback()
        app.logger.exception("Approval/rejection failed")
        return jsonify({
            "success": False,
            "message": "Could not save the decision."
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route("/slot-status", methods=["GET"])

def slot_status():
    date_text = (request.args.get("date") or "").strip()
    try:
        selected_date = datetime.strptime(
            date_text,
            "%Y-%m-%d",
        ).date()
    except ValueError:
        return jsonify(
            error="Choose a valid deployment date."
        ), 400
    if not is_manager_user():
     if selected_date < date.today():
        return jsonify({
            "error": "Past deployment dates are not available for booking."
        }), 400
        if selected_date.weekday() in (5, 6):
         return jsonify({
            "error": "Deployments cannot be booked on Saturday or Sunday."
        }), 400
    slots = []
    for start_text in SLOT_STARTS:
        start_time = datetime.strptime(
            start_text,
            "%H:%M",
        ).time()
        start_dt = datetime.combine(
            selected_date,
            start_time,
        )
        end_dt = start_dt + timedelta(minutes=30)
        slots.append({
            "start": start_text,
            "end": end_dt.strftime("%H:%M"),
            "state": "available",
            "status": "Available",
        })
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                 """
                    SELECT slot_start, slot_end, status
                 FROM public.deployment_tracker
                  WHERE deployment_date = %s
                   AND slot_start IS NOT NULL
                   AND slot_end IS NOT NULL
                  AND LOWER(TRIM(COALESCE(status, '')))
                  NOT IN ('cancelled', 'rejected')
             """,
                (selected_date,),
            )
            rows = cur.fetchall()
        for start_dt, end_dt, status in rows:
            for slot in slots:
                slot_start = datetime.combine(
                    selected_date,
                    datetime.strptime(
                        slot["start"],
                        "%H:%M",
                    ).time(),
                )
                slot_end = slot_start + timedelta(minutes=30)
                if start_dt < slot_end and end_dt > slot_start:
                    status_text = (status or "Booked").strip()
                    slot["status"] = status_text
                    if status_text.casefold() == "pending":
                        slot["state"] = "pending"
                    else:
                        slot["state"] = "booked"
        return jsonify({
            "date": date_text,
            "slots": slots,
        })
    except psycopg2.Error:
        app.logger.exception(
            "Could not load slot availability"
        )
        return jsonify(
            error="Unable to load slot availability. Please retry."
        ), 500
    finally:
        if conn is not None:
            conn.close()

@app.route("/lookup-cr", methods=["GET"])

def lookup_cr():
    cr_number = (request.args.get("cr_number") or "").strip()
    if not cr_number:
        return jsonify(
            exists=False,
            rfid=None,
        ), 200
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT rfid
                FROM public.deployment_tracker
                WHERE LOWER(TRIM(cr_number)) = LOWER(TRIM(%s))
                  AND rfid IS NOT NULL
                ORDER BY id
                LIMIT 1
                """,
                (cr_number,),
            )
            row = cur.fetchone()
        if row:
            return jsonify(
                exists=True,
                rfid=str(row[0]),
            ), 200
        return jsonify(
            exists=False,
            rfid=None,
        ), 200
    except psycopg2.Error:
        app.logger.exception("CR lookup failed")
        return jsonify(
            error="Database lookup failed. Please retry."
        ), 500
    finally:
        if conn is not None:
            conn.close()

@app.route("/", methods=["GET", "POST"])

def Release_Calender():
    if request.method == "GET":
        return render_template(
            "Release_Calender.html",
            **form_context(),
        )
    data = request.form.to_dict()
    required_fields = [
        "cr_number",
        "deployment_date",
        "slot_start",
        "application_name",
        "deployment_type",
        "change_type",
        "change_requestor",
    ]
    for field in required_fields:
        if not (data.get(field) or "").strip():
            flash(
                f"{field.replace('_', ' ').title()} is required.",
                "error",
            )
            return render_template(
                "Release_Calender.html",
                **form_context(data),
            ), 400
    try:
        rfid = save_deployment(data)
        cr_number = (data.get("cr_number") or "").strip()
        flash(
            (
                "Request submitted successfully! "
                f"CR Number: {cr_number} | RFID: {rfid}"
            ),
            "success",
        )
        return redirect(url_for("Release_Calender"))
    except ValueError as exc:
        flash(str(exc), "error")
        return render_template(
            "Release_Calender.html",
            **form_context(data),
        ), 400
    except (RuntimeError, KeyError) as exc:
        app.logger.exception("Request submission failed")
        flash(str(exc), "error")
        return render_template(
            "Release_Calender.html",
            **form_context(data),
        ), 500

@app.route("/manager", methods=["GET"])
def manager_dashboard():
    """Manager dashboard with a week-selectable deployment activity chart."""
    conn = None
    cursor = None
    try:
        # Read ?week_start=YYYY-MM-DD. Always align to Monday so the chart
        # consistently displays a Monday-to-Sunday calendar week.
        week_start_text = (request.args.get("week_start") or "").strip()
        try:
            selected_day = date.fromisoformat(week_start_text) if week_start_text else date.today()
        except ValueError:
            selected_day = date.today()

        activity_week_start = selected_day - timedelta(days=selected_day.weekday())
        activity_week_end = activity_week_start + timedelta(days=6)
        activity_week_end_exclusive = activity_week_start + timedelta(days=7)
        previous_week_start = activity_week_start - timedelta(days=7)
        next_week_start = activity_week_start + timedelta(days=7)

        # Prepare each day, including days with no deployments.
        day_counts = {activity_week_start + timedelta(days=i): 0 for i in range(7)}

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE deployment_date = CURRENT_DATE) AS daily,
                COUNT(*) FILTER (
                    WHERE deployment_date >= date_trunc('week', CURRENT_DATE)::date
                      AND deployment_date < (date_trunc('week', CURRENT_DATE) + INTERVAL '1 week')::date
                ) AS weekly,
                COUNT(*) FILTER (
                    WHERE deployment_date >= date_trunc('month', CURRENT_DATE)::date
                      AND deployment_date < (date_trunc('month', CURRENT_DATE) + INTERVAL '1 month')::date
                ) AS monthly,
                COUNT(*) FILTER (WHERE LOWER(TRIM(COALESCE(roll_back, ''))) = 'yes') AS rollbacks
            FROM public.deployment_tracker
        """)
        metric_row = cursor.fetchone()
        metrics = {
            "total": metric_row[0] or 0,
            "daily": metric_row[1] or 0,
            "weekly": metric_row[2] or 0,
            "monthly": metric_row[3] or 0,
            "rollbacks": metric_row[4] or 0,
        }

        # Counts for the selected calendar week, grouped by deployment date.
        cursor.execute("""
            SELECT deployment_date, COUNT(*)
            FROM public.deployment_tracker
            WHERE deployment_date >= %s
              AND deployment_date < %s
            GROUP BY deployment_date
            ORDER BY deployment_date
        """, (activity_week_start, activity_week_end_exclusive))
        for deployment_day, count in cursor.fetchall():
            if deployment_day in day_counts:
                day_counts[deployment_day] = count

        chart_scale_max = max(4, max(day_counts.values(), default=0))
        activity_chart = []
        for chart_day, count in day_counts.items():
            activity_chart.append({
                "date": chart_day.isoformat(),
                "label": chart_day.strftime("%a"),
                "count": count,
                "height_percent": round((count / chart_scale_max) * 100, 1),
            })
        chart_y_ticks = sorted({
            chart_scale_max,
            round(chart_scale_max * 0.75),
            round(chart_scale_max * 0.5),
            round(chart_scale_max * 0.25),
            0,
        }, reverse=True)

        # Load all records for the existing manager table.
        cursor.execute("""
            SELECT id, cr_number, rfid, deployment_date, slot_start, slot_end,
                   application_name, deployment_type, change_type, released_by,
                   verified_and_deployed_by, change_requestor, incident_number,
                   roll_back, status
            FROM public.deployment_tracker
            ORDER BY deployment_date DESC, slot_start DESC, id DESC
        """)
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        records = [dict(zip(columns, row)) for row in rows]

        cursor.execute("""
            SELECT id, deployment_id, cr_number, rfid, modified_at,
                   modified_by, action, changes
            FROM public.deployment_change_history
            ORDER BY modified_at DESC, id DESC
            LIMIT 200
        """)
        history_rows = cursor.fetchall()
        history_columns = [desc[0] for desc in cursor.description]
        change_history = [dict(zip(history_columns, row)) for row in history_rows]

        return render_template(
            "manager.html",
            metrics=metrics,
            records=records,
            activity_chart=activity_chart,
            chart_y_ticks=chart_y_ticks,
            chart_scale_max=chart_scale_max,
            activity_week_start=activity_week_start,
            activity_week_end=activity_week_end,
            previous_week_start=previous_week_start,
            next_week_start=next_week_start,
            change_history=change_history,
        )
    except Exception:
        app.logger.exception("Unable to load manager dashboard")
        return "Unable to load manager dashboard. Check the Flask logs and database connection.", 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_PORT", "5000")),
        debug=False,
    )
