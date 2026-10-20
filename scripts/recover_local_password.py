"""Local, sudo-authorized password recovery; intentionally no HTTP route.

The invoking OS account must be independently authenticated by sudo/PAM.
This command only changes the verifier: it does not alter identity, roles,
MFA enrollment, or account status. Run from the reviewed Auth checkout.
"""
from __future__ import annotations

import getpass
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.password_policy import PasswordPolicyError, validate_new_password
from app.core.security import hash_password
from app.db.models import RefreshToken, User, UserSession
from app.db.session import SessionLocal
from app.services import audit_service


def main() -> int:
    operator = os.environ.get("SUDO_USER", "").strip()
    if os.geteuid() != 0 or not operator or operator == "root" or not sys.stdin.isatty():
        print("Run this local command through sudo from an interactive terminal.", file=sys.stderr)
        return 2

    email = input("Target account email: ").strip()
    confirmation = input("Retype target email to confirm: ").strip()
    if not email or email != confirmation:
        print("Target confirmation did not match.", file=sys.stderr)
        return 2
    password = getpass.getpass("New password: ")
    repeated = getpass.getpass("Repeat new password: ")
    if not password or password != repeated:
        print("Password confirmation failed.", file=sys.stderr)
        return 2

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).with_for_update().one_or_none()
        if user is None or user.status != "active":
            print("No active account matched that email.", file=sys.stderr)
            return 1
        try:
            validate_new_password(password, email)
        except PasswordPolicyError as exc:
            print(str(exc), file=sys.stderr)
            return 1

        now = datetime.utcnow()
        user.hashed_password = hash_password(password)
        db.query(RefreshToken).filter(
            RefreshToken.user_id == user.id, RefreshToken.revoked.is_(False)
        ).update({RefreshToken.revoked: True}, synchronize_session=False)
        db.query(UserSession).filter(
            UserSession.user_id == user.id, UserSession.status == "active"
        ).update(
            {
                UserSession.status: "revoked",
                UserSession.revoked_at: now,
                UserSession.revoked_reason: "operator_credential_recovery",
            },
            synchronize_session=False,
        )
        audit_service.log_event(
            db,
            "credential_recovered_by_operator",
            actor_user_id=None,
            target_user_id=user.id,
            resource_type="user",
            resource_id=str(user.id),
            metadata={"operator_os_account": operator, "sessions_revoked": True},
            commit=False,
        )
        db.commit()
        print("Credential updated; existing refresh sessions were revoked. MFA settings were preserved.")
        return 0
    except Exception:
        db.rollback()
        print("Credential recovery failed; no change was committed.", file=sys.stderr)
        return 1
    finally:
        password = repeated = ""
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
