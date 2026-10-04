"""Set/enroll a local password for one existing active user.

Usage: python scripts/set_user_password.py <email>
The password is accepted only through hidden interactive prompts, never argv
or environment variables. Run this only against an explicitly selected auth
database after operator authorization and backup.
"""
import argparse
import getpass
import sys
import warnings

from app.db.session import SessionLocal
from app.services.password_enrollment_service import (
    PasswordEnrollmentError,
    enroll_existing_user_password,
    inspect_user_auth_profile,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Enroll a password for an existing active auth user")
    parser.add_argument("identity", help="existing user's email identity")
    args = parser.parse_args()

    if not sys.stdin.isatty():
        print("Interactive terminal input is required; no changes made.", file=sys.stderr)
        return 2

    db = SessionLocal()
    try:
        profile = inspect_user_auth_profile(db, args.identity)
        print(f"Target: user_id={profile.user_id}, email={profile.email}, status={profile.status}")
        print(
            "Existing methods: "
            f"local_password={'yes' if profile.password_credential_present else 'no'}, "
            f"oauth_accounts={profile.oauth_account_count}, "
            f"mfa_enabled={'yes' if profile.mfa_enabled else 'no'}, "
            f"active_mfa_devices={profile.mfa_device_count}"
        )
        # End the read-only inspection transaction before waiting for the
        # operator. The mutation starts a fresh transaction and locks the
        # exact user ID while revalidating email and active status.
        db.rollback()
        expected = f"SET PASSWORD FOR USER ID {profile.user_id} ({profile.email})"
        if input(f"Type exactly '{expected}' to continue: ") != expected:
            print("Confirmation did not match; no changes made.", file=sys.stderr)
            return 2

        try:
            # getpass normally suppresses terminal echo. Promote its
            # documented fallback warning to an exception so no echoed
            # fallback input is ever accepted or passed to the service.
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                password = getpass.getpass("New password: ")
                confirmation = getpass.getpass("Confirm new password: ")
        except getpass.GetPassWarning:
            print("Secure hidden password input is unavailable; aborting.", file=sys.stderr)
            return 2
        except (EOFError, KeyboardInterrupt):
            print("Secure password input cancelled; aborting.", file=sys.stderr)
            return 2
        except Exception:
            print("Secure hidden password input failed; aborting.", file=sys.stderr)
            return 2

        result = enroll_existing_user_password(
            db, profile, password, confirmation
        )
        # Drop references as soon as practical. Python strings cannot be
        # reliably zeroized; neither value is emitted or persisted plaintext.
        del password, confirmation
        print(
            f"Password credential updated for user_id={result.user_id}; "
            f"revoked_refresh_tokens={result.revoked_refresh_tokens}; "
            f"revoked_sessions={result.revoked_sessions}."
        )
        return 0
    except PasswordEnrollmentError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("Input cancelled; no changes made.", file=sys.stderr)
        return 2
    finally:
        if "password" in locals():
            del password
        if "confirmation" in locals():
            del confirmation
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
