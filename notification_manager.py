"""
notification_manager.py
-----------------------
Local/offline medication notification engine for MySmartMed.

Implements the two-phase reminder workflow described in the INDICON 2026 paper:

    Scheduled time
          |
          v
    First reminder
          |
     TAKEN? ---- YES ---> record TAKEN + inventory/refill logic
       |
       NO / no response
       |
    wait 5 minutes
       |
       v
    Second reminder
       |
     response?
       |
       NO
       |
       v
    record MISSED

The notification engine itself never performs cryptographic operations.
It calls callbacks supplied by app.py so that encryption remains inside
the Security/Application layers.
"""

import threading
import time
from datetime import datetime, timedelta


CHECK_INTERVAL_SECONDS = 1
SECOND_REMINDER_DELAY_MINUTES = 5

# The paper specifies a second reminder after 5 minutes and says that a
# second unresponsiveness is considered missed. For this prototype we give
# the caregiver another 5-minute response window after the second reminder.
AUTO_MISS_AFTER_SECOND_MINUTES = 5

# The first reminder is only created for a dose that became due recently.
# This prevents a server restart from generating old reminders.
FIRST_REMINDER_GRACE_SECONDS = 60


_lock = threading.RLock()

_running = False
_worker_thread = None

_pending = {}
_notification_queue = []

_schedule_provider = None
_dose_logger = None
_dose_exists_checker = None


def register_schedule_provider(provider):
    """
    Register a callback that returns the currently active medication
    schedules.

    Expected item format:

    {
        "user_id": 1,
        "patient_id": 2,
        "medicine_id": 3,
        "medicine_name": "Metformin",
        "scheduled_times": ["08:00", "20:00"]
    }
    """
    global _schedule_provider
    _schedule_provider = provider


def register_dose_logger(callback):
    """
    Register the secure callback used to write TAKEN/MISSED records.

    Signature:

        callback(
            user_id,
            medicine_id,
            status,
            scheduled_time
        )
    """
    global _dose_logger
    _dose_logger = callback


def register_dose_exists_checker(callback):
    """
    Register a callback that checks whether the scheduled dose has already
    been logged.

    Signature:

        callback(
            user_id,
            medicine_id,
            scheduled_time
        ) -> bool
    """
    global _dose_exists_checker
    _dose_exists_checker = callback


def _occurrence_key(medicine_id, scheduled_time):
    return (
        medicine_id,
        scheduled_time.strftime("%Y-%m-%d %H:%M"),
    )


def _queue_notification(pending):
    """
    Add one notification to the local browser queue.
    """

    notification_key = (
        pending["medicine_id"],
        pending["scheduled_key"],
        pending["stage"],
    )

    with _lock:
        for item in _notification_queue:
            existing_key = (
                item["medicine_id"],
                item["scheduled_time"],
                item["stage"],
            )
            if existing_key == notification_key:
                return

        if pending["stage"] == "FIRST":
            title = "Medication Reminder"
            message = (
                f"Time to take {pending['medicine_name']}. "
                "Please confirm whether the dose was taken."
            )
        else:
            title = "Second Medication Reminder"
            message = (
                f"Reminder: {pending['medicine_name']} "
                "has not been acknowledged. Please confirm the dose."
            )

        _notification_queue.append({
            "medicine_id": pending["medicine_id"],
            "patient_id": pending["patient_id"],
            "user_id": pending["user_id"],
            "medicine_name": pending["medicine_name"],
            "scheduled_time": pending["scheduled_key"],
            "stage": pending["stage"],
            "title": title,
            "message": message,
            "created_at": datetime.now().isoformat(timespec="seconds"),
        })


def get_notifications(user_id):
    """
    Return and clear pending browser notifications for one caregiver only.

    The database remains the source of truth for compliance; this queue
    only transports reminder events from the local background worker to
    the browser.
    """

    with _lock:
        result = [item for item in _notification_queue if item["user_id"] == user_id]
        _notification_queue[:] = [item for item in _notification_queue if item["user_id"] != user_id]

    return result


def acknowledge(medicine_id, scheduled_time):
    """
    Remove a pending reminder after the caregiver has responded.
    """

    if isinstance(scheduled_time, str):
        scheduled_time = datetime.fromisoformat(scheduled_time)

    key = _occurrence_key(medicine_id, scheduled_time)

    with _lock:
        _pending.pop(key, None)


def _dose_already_logged(user_id, medicine_id, scheduled_time):
    if _dose_exists_checker is None:
        return False

    try:
        return bool(
            _dose_exists_checker(
                user_id,
                medicine_id,
                scheduled_time,
            )
        )
    except Exception as exc:
        print(f"[NotificationManager] Dose check error: {exc}")
        return False


def _record_missed(pending):
    """
    Record an automatically missed dose through the secure application
    callback.
    """

    if _dose_logger is None:
        print(
            "[NotificationManager] No dose logger registered; "
            "cannot record MISSED dose."
        )
        return

    try:
        _dose_logger(
            pending["user_id"],
            pending["medicine_id"],
            "MISSED",
            pending["scheduled_time"],
        )
    except Exception as exc:
        print(
            f"[NotificationManager] Could not record MISSED dose: {exc}"
        )


def _parse_time(value):
    """
    Parse both 24-hour and common 12-hour time formats.

    Examples:
        08:00
        20:00
        8:00 AM
        8:00 PM
    """

    value = value.strip()

    for fmt in ("%H:%M", "%I:%M %p", "%I %p"):
        try:
            return datetime.strptime(value, fmt).time()
        except ValueError:
            continue

    return None


def _build_today_occurrences(schedule, now):
    """
    Convert the medicine's time strings into today's datetime occurrences.
    """

    occurrences = []

    for raw_time in schedule.get("scheduled_times", []):
        parsed = _parse_time(raw_time)

        if parsed is None:
            continue

        occurrences.append(
            datetime.combine(now.date(), parsed)
        )

    return occurrences


def _process_once():
    """
    Process medication schedules for the current minute.
    """

    if _schedule_provider is None:
        return

    now = datetime.now()

    try:
        schedules = _schedule_provider()
    except Exception as exc:
        print(f"[NotificationManager] Schedule provider error: {exc}")
        return

    active_keys = set()

    for schedule in schedules:
        user_id = schedule.get("user_id")
        medicine_id = schedule.get("medicine_id")

        if user_id is None or medicine_id is None:
            continue

        occurrences = _build_today_occurrences(schedule, now)

        for scheduled_time in occurrences:
            occurrence_key = _occurrence_key(
                medicine_id,
                scheduled_time,
            )

            active_keys.add(occurrence_key)

            # -----------------------------------------------------------
            # If the caregiver already responded, there is nothing to do.
            # -----------------------------------------------------------
            if _dose_already_logged(
                user_id,
                medicine_id,
                scheduled_time,
            ):
                with _lock:
                    _pending.pop(occurrence_key, None)
                continue

            # -----------------------------------------------------------
            # FIRST REMINDER
            # -----------------------------------------------------------
            seconds_since_due = (
                now - scheduled_time
            ).total_seconds()

            if (
                0 <= seconds_since_due <= FIRST_REMINDER_GRACE_SECONDS
            ):
                with _lock:
                    pending = _pending.get(occurrence_key)

                    if pending is None:
                        pending = {
                            "user_id": user_id,
                            "patient_id": schedule.get("patient_id"),
                            "medicine_id": medicine_id,
                            "medicine_name": schedule.get(
                                "medicine_name",
                                "medication",
                            ),
                            "scheduled_time": scheduled_time,
                            "scheduled_key": scheduled_time.strftime(
                                "%Y-%m-%d %H:%M"
                            ),
                            "stage": "FIRST",
                        }

                        _pending[occurrence_key] = pending

                        _queue_notification(pending)

            # -----------------------------------------------------------
            # SECOND REMINDER
            # -----------------------------------------------------------
            with _lock:
                pending = _pending.get(occurrence_key)

            if pending is None:
                continue

            elapsed = now - scheduled_time

            if (
                pending["stage"] == "FIRST"
                and elapsed
                >= timedelta(minutes=SECOND_REMINDER_DELAY_MINUTES)
            ):
                if _dose_already_logged(
                    user_id,
                    medicine_id,
                    scheduled_time,
                ):
                    with _lock:
                        _pending.pop(occurrence_key, None)
                    continue

                pending["stage"] = "SECOND"

                with _lock:
                    _queue_notification(pending)

            # -----------------------------------------------------------
            # AUTOMATIC MISSED
            # -----------------------------------------------------------
            elif (
                pending["stage"] == "SECOND"
                and elapsed
                >= timedelta(
                    minutes=(
                        SECOND_REMINDER_DELAY_MINUTES
                        + AUTO_MISS_AFTER_SECOND_MINUTES
                    )
                )
            ):
                if not _dose_already_logged(
                    user_id,
                    medicine_id,
                    scheduled_time,
                ):
                    _record_missed(pending)

                with _lock:
                    _pending.pop(occurrence_key, None)

    # Clean up stale pending reminders.
    cutoff = now - timedelta(days=2)

    with _lock:
        stale = [
            key
            for key, item in _pending.items()
            if item["scheduled_time"] < cutoff
        ]

        for key in stale:
            _pending.pop(key, None)


def _worker():
    global _running

    while _running:
        try:
            _process_once()
        except Exception as exc:
            print(f"[NotificationManager] Worker error: {exc}")

        time.sleep(CHECK_INTERVAL_SECONDS)


def start_notification_manager():
    """
    Start the notification worker once.
    """

    global _running, _worker_thread

    with _lock:
        if _running:
            return

        _running = True

        _worker_thread = threading.Thread(
            target=_worker,
            name="MySmartMed-NotificationManager",
            daemon=True,
        )

        _worker_thread.start()

    print("[NotificationManager] Started.")


def stop_notification_manager():
    """
    Stop the notification worker.
    """

    global _running

    with _lock:
        _running = False

    print("[NotificationManager] Stopped.")


def pending_count():
    """
    Diagnostic helper for the prototype.
    """

    with _lock:
        return len(_pending)
