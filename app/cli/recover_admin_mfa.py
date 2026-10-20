"""Reset an unknown Admin authenticator using a separate Owner-signed approval."""
from __future__ import annotations

import argparse
import os
import pwd
import sys

from app.core.recovery_approval import RecoveryApprovalError, load_signed_recovery_approval
from app.db.models import User
from app.db.session import SessionLocal
from app.services.credential_recovery_service import CredentialRecoveryError, recover_admin_mfa


def _operator_login() -> str:
    return pwd.getpwuid(os.getuid()).pw_name


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replace an unknown Admin MFA enrollment")
    parser.add_argument("--user-id", type=int, required=True)
    parser.add_argument("--approval-file", required=True)
    args = parser.parse_args(argv)
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("MFA recovery requires an interactive terminal.", file=sys.stderr)
        return 2

    operator_login = _operator_login()
    db = SessionLocal()
    try:
        approval = load_signed_recovery_approval(args.approval_file)
        if approval.target_user_id != args.user_id or approval.operator_login != operator_login:
            raise CredentialRecoveryError("Approval does not authorize this operator or target")
        target = db.query(User).filter(User.id == args.user_id).one_or_none()
        if target is None or target.email != approval.target_email or not target.mfa_enabled:
            raise CredentialRecoveryError("Approved Admin MFA enrollment is not eligible")
        confirmation = input(
            f"Type exactly RECOVER-MFA {approval.target_user_id} {approval.target_email} {approval.ticket_id}: "
        )
        result = recover_admin_mfa(
            db,
            target_user_id=args.user_id,
            operator_login=operator_login,
            confirmation=confirmation,
            approval=approval,
        )
        print(
            f"MFA recovery completed for user ID {result['user_id']}; "
            f"revoked {result['sessions_revoked']} sessions. The Admin must enroll a new authenticator."
        )
        return 0
    except (RecoveryApprovalError, CredentialRecoveryError) as exc:
        print(f"MFA recovery denied: {exc}", file=sys.stderr)
        return 1
    except Exception:
        db.rollback()
        print("MFA recovery failed; no change was committed. Contact the Auth operator.", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
