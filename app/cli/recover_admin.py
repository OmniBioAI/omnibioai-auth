"""Recover an existing disabled-password administrator using an Owner approval.

This command is intentionally not registered as an HTTP route. The privileged
runtime must mount the trusted Platform Owner public key read-only and limit
execution to approved operators.
"""
from __future__ import annotations

import argparse
import getpass
import os
import pwd
import sys

from app.core.recovery_approval import RecoveryApprovalError, load_signed_recovery_approval
from app.core.security import password_verifier_scheme
from app.db.models import User
from app.db.session import SessionLocal
from app.services.credential_recovery_service import CredentialRecoveryError, recover_admin_password


def _operator_login() -> str:
    return pwd.getpwuid(os.getuid()).pw_name


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Recover an existing disabled-password Admin")
    parser.add_argument("--user-id", type=int, required=True, help="Stable user ID authorized in the signed approval")
    parser.add_argument("--approval-file", required=True, help="Path to the signed, out-of-band Platform Owner approval")
    args = parser.parse_args(argv)

    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Recovery requires an interactive terminal.", file=sys.stderr)
        return 2

    operator_login = _operator_login()
    db = SessionLocal()
    try:
        approval = load_signed_recovery_approval(args.approval_file)
        if approval.target_user_id != args.user_id or approval.operator_login != operator_login:
            raise CredentialRecoveryError("Approval does not authorize this operator or target")

        target = db.query(User).filter(User.id == args.user_id).one_or_none()
        if (
            target is None
            or target.email != approval.target_email
            or target.status != "active"
            or not any(role.name == "admin" and role.organization_id is None for role in target.roles)
            or password_verifier_scheme(target.hashed_password) is not None
        ):
            raise CredentialRecoveryError("Approved disabled-password Admin identity is not eligible")

        confirmation = input(
            f"Type exactly RECOVER {approval.target_user_id} {approval.target_email} {approval.ticket_id}: "
        )
        password = getpass.getpass("New Admin password: ")
        repeated = getpass.getpass("Repeat new Admin password: ")
        if password != repeated:
            raise CredentialRecoveryError("The entered passwords do not match")

        result = recover_admin_password(
            db,
            target_user_id=args.user_id,
            operator_login=operator_login,
            confirmation=confirmation,
            password=password,
            approval=approval,
        )
        print(
            f"Recovery completed for user ID {result['user_id']}; "
            f"revoked {result['sessions_revoked']} sessions; MFA reset={str(result['mfa_reset']).lower()}."
        )
        return 0
    except (RecoveryApprovalError, CredentialRecoveryError) as exc:
        print(f"Recovery denied: {exc}", file=sys.stderr)
        return 1
    except Exception:
        # Do not print exception strings, DB values, SQL parameters, or any
        # password material. Operators correlate the failure using service
        # diagnostics and the ticket without exposing credentials.
        db.rollback()
        print("Recovery failed; no change was committed. Contact the Auth operator.", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
