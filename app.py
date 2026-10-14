import logging
import os
import secrets
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

    released_by_choice = (
        data.get("released_by") or ""
    ).strip()
    if released_by_choice == "__add__":
        released_by = (
            data.get("released_by_new") or ""
        ).strip()
        if not released_by:
            raise ValueError(
                "Please enter the new Released By user name."
            )
        if len(released_by) > 100:
            raise ValueError(
                "Released By name cannot exceed 100 characters."
            )
    elif released_by_choice in get_released_by_users():
        released_by = released_by_choice
    else:
        raise ValueError(
            "Please select a valid Released By user."
        )

    verified_and_deployed_by = resolve_verified_deployed_by(data)

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
    if data.get("roll_back") not in ("Yes", "No"):
        raise ValueError("Invalid rollback selection.")
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
    return {
        "data": data or {},
        "change_types": CHANGE_TYPES,
        "deployment_types": DEPLOYMENT_TYPES,
        "statuses": STATUSES,
        "slot_starts": SLOT_STARTS,
        "released_by_users": get_released_by_users(),
        "verified_by_options": VERIFIED_BY_OPTIONS,
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
    )

@app.route("/api/deployments-by-date", methods=["GET"])
def get_deployments_by_date():
    """Return all deployment records for a selected calendar date as JSON."""
    date_text = (request.args.get("date") or "").strip()
    try:
        selected_date = date.fromisoformat(date_text)
    except ValueError:
        return jsonify({"success": False, "message": "Provide a valid date in YYYY-MM-DD format."}), 400

    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, cr_number, rfid, deployment_date, slot_start, slot_end,
                   application_name, deployment_type, change_type,
                   released_by, verified_and_deployed_by, change_requestor,
                   release_notes, incident_number, roll_back, status
            FROM public.deployment_tracker
            WHERE deployment_date = %s
            ORDER BY slot_start ASC NULLS LAST, id ASC
            """,
            (selected_date,),
        )
        rows = cursor.fetchall()
        columns = [description[0] for description in cursor.description]
        deployments = []
        for row in rows:
            record = dict(zip(columns, row))
            for key, value in record.items():
                if isinstance(value, (datetime, date, time)):
                    record[key] = value.isoformat()
                elif value is not None and not isinstance(value, (str, int, float, bool)):
                    record[key] = str(value)
            deployments.append(record)
        return jsonify({"success": True, "date": selected_date.isoformat(), "deployments": deployments})
    except Exception:
        app.logger.exception("Daily deployment schedule API failed for %s", date_text)
        return jsonify({"success": False, "message": "Could not load deployments for this date. Check Flask logs."}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/deployment-by-cr", methods=["GET"])
def get_deployment_by_cr():
    """Return every deployment request associated with the supplied CR number."""
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
                id, cr_number, rfid, deployment_date, slot_start, slot_end,
                slots, application_name, deployment_type, change_type,
                released_by, verified_and_deployed_by, change_requestor,
                release_notes, incident_number, roll_back, status
            FROM public.deployment_tracker
            WHERE UPPER(REGEXP_REPLACE(TRIM(cr_number), '^CR-', '', 'i')) = %s
            ORDER BY deployment_date DESC NULLS LAST, slot_start DESC NULLS LAST, id DESC
            """,
            (cr_number.upper(),)
        )
        rows = cursor.fetchall()
        if not rows:
            return jsonify({
                "success": False,
                "message": f"No deployment requests found for {normalized_cr}."
            }), 404

        columns = [description[0] for description in cursor.description]
        deployments = []
        for row in rows:
            deployment = dict(zip(columns, row))
            for key, value in deployment.items():
                if isinstance(value, (datetime, date, time)):
                    deployment[key] = value.isoformat()
                elif value is not None and not isinstance(value, (str, int, float, bool)):
                    deployment[key] = str(value)
            deployment["cr_number"] = normalized_cr
            deployments.append(deployment)

        return jsonify({
            "success": True,
            "message": f"Found {len(deployments)} request(s) for {normalized_cr}.",
            "requests": deployments
        })
    except Exception:
        app.logger.exception("DevOps CR lookup failed")
        return jsonify({
            "success": False,
            "message": "Could not retrieve deployment requests. Check the server logs."
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
    try:
        validate_deployment_date(
        deployment_date,
        is_manager=is_manager_user()
    )
    except ValueError as exc:
        return jsonify({
        "success": False,
        "message": str(exc)
    }), 400
    if start_time.strftime("%H:%M") not in SLOT_STARTS:
        return jsonify({
            "success": False,
            "message": "Choose a 30-minute slot between 6:30 PM and 11:00 PM.",
        }), 400
    if not data["application_name"].strip():
        return jsonify({"success": False, "message": "Application Name is required."}), 400
    slot_start = datetime.combine(deployment_date, start_time)
    slot_end = slot_start + timedelta(minutes=30)
    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.autocommit = False
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM public.deployment_tracker WHERE id = %s FOR UPDATE",
            (deployment_id,),
        )
        if cursor.fetchone() is None:
            conn.rollback()
            return jsonify({"success": False, "message": "Deployment record not found."}), 404
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
        conn.commit()
        write_audit_log(
            "INFO",
            f"DevOps updated deployment record ID={deployment_id}; status={data['status']}",
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

@app.route(
    "/api/deployment-approval/<int:deployment_id>",
    methods=["POST"]
)

def decide_deployment_request(deployment_id):
    payload = request.get_json(silent=True) or {}
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
        conn.commit()
        write_audit_log(
            "INFO",
            f"Deployment request {decision}d: "
            f"ID={deployment_id}, CR={row[0]}, status={new_status}",
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
        "cr_number", "deployment_date", "slot_start", "application_name",
        "deployment_type", "change_type", "roll_back", "released_by",
        "verified_and_deployed_by", "change_requestor",
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
    """Read-only dashboard; counts are based on deployment_date."""
    conn = None
    cursor = None
    try:
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
        return render_template("manager.html", metrics=metrics, records=records)
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
