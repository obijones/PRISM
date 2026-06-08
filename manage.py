#!/usr/bin/env python3
"""
PRISM Tool — management CLI

Commands:
    python manage.py init-db
    python manage.py add-user           <username>
    python manage.py remove-user        <username>
    python manage.py reset-password     <username>
    python manage.py list-users
    python manage.py audit
    python manage.py clear-assessments
"""
import getpass
import os
import sqlite3
import sys

from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "carver.db")


def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    # Ensure the users table exists even if app.py hasn't run yet.
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            password   TEXT    NOT NULL,
            created_at TEXT    DEFAULT (datetime('now'))
        );
    """)
    conn.commit()
    return conn


def _prompt_password(username):
    pw = getpass.getpass(f"Password for '{username}': ")
    if not pw:
        print("Password cannot be empty.")
        sys.exit(1)
    confirm = getpass.getpass("Confirm password: ")
    if pw != confirm:
        print("Passwords do not match.")
        sys.exit(1)
    return pw


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_init_db():
    from app import init_db
    init_db()
    print("Database initialised.")


def cmd_add_user(username):
    pw = _prompt_password(username)
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, generate_password_hash(pw)),
        )
        conn.commit()
        print(f"User '{username}' created.")
    except sqlite3.IntegrityError:
        print(f"Error: user '{username}' already exists.")
        sys.exit(1)
    finally:
        conn.close()


def cmd_remove_user(username):
    answer = input(f"Remove user '{username}'? This cannot be undone. [yes/N]: ")
    if answer.strip().lower() != "yes":
        print("Cancelled.")
        return
    conn = get_db()
    cur = conn.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    if cur.rowcount == 0:
        print(f"Error: user '{username}' not found.")
        sys.exit(1)
    print(f"User '{username}' removed.")


def cmd_reset_password(username):
    conn = get_db()
    row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        print(f"Error: user '{username}' not found.")
        conn.close()
        sys.exit(1)
    pw = _prompt_password(username)
    conn.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (generate_password_hash(pw), username),
    )
    conn.commit()
    conn.close()
    print(f"Password updated for '{username}'.")


def cmd_list_users():
    conn = get_db()
    rows = conn.execute(
        "SELECT username, created_at FROM users ORDER BY created_at"
    ).fetchall()
    conn.close()
    if not rows:
        print("No users found. Use 'add-user' to create the first account.")
        return
    print(f"{'Username':<24}  Created (UTC)")
    print("-" * 48)
    for r in rows:
        print(f"{r['username']:<24}  {r['created_at']}")


def cmd_audit():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """SELECT timestamp, actor, action, assessment_id, detail
           FROM audit_log ORDER BY timestamp DESC LIMIT 200"""
    ).fetchall()
    conn.close()
    if not rows:
        print("Audit log is empty.")
        return
    print(f"{'Timestamp (UTC)':<24}  {'Actor':<20}  {'Action':<8}  {'ID':<6}  Detail")
    print("-" * 82)
    for r in rows:
        print(
            f"{r['timestamp']:<24}  {r['actor']:<20}  {r['action']:<8}"
            f"  {str(r['assessment_id'] or ''):<6}  {r['detail'] or ''}"
        )


def cmd_clear_assessments():
    answer = input(
        "Hard-delete ALL assessments (including soft-deleted records and audit log)?"
        " This cannot be undone. [yes/N]: "
    )
    if answer.strip().lower() != "yes":
        print("Cancelled.")
        return
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    cur = conn.execute("DELETE FROM assessments")
    conn.execute("DELETE FROM audit_log")
    conn.commit()
    conn.close()
    print(f"Deleted {cur.rowcount} assessment(s) and cleared the audit log.")


# ── Dispatch ──────────────────────────────────────────────────────────────────

COMMANDS = {
    "init-db":           (cmd_init_db,           ""),
    "add-user":          (cmd_add_user,          "USERNAME"),
    "remove-user":       (cmd_remove_user,       "USERNAME"),
    "reset-password":    (cmd_reset_password,    "USERNAME"),
    "list-users":        (cmd_list_users,        ""),
    "audit":             (cmd_audit,             ""),
    "clear-assessments": (cmd_clear_assessments, ""),
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        sys.exit(0 if len(sys.argv) == 1 else 1)

    cmd_name = sys.argv[1]
    fn, arg_label = COMMANDS[cmd_name]

    if arg_label and len(sys.argv) < 3:
        print(f"Usage: python manage.py {cmd_name} {arg_label}")
        sys.exit(1)

    if arg_label:
        fn(sys.argv[2])
    else:
        fn()
