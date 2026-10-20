"""Narrow Auth adapter for the existing OmniBioAI transactional email service."""
import httpx

from app.core.config import settings


class EmailDeliveryError(RuntimeError):
    """Delivery failed without exposing provider response or message content."""


def send_mfa_code(recipient: str, code: str, expires_minutes: int = 5) -> None:
    """Send one MFA message. Callers must never log ``code`` or this payload."""
    if not settings.EMAIL_SERVICE_SEND_URL or not settings.EMAIL_SERVICE_TOKEN:
        raise EmailDeliveryError("Email delivery is unavailable")
    try:
        response = httpx.post(
            settings.EMAIL_SERVICE_SEND_URL,
            headers={
                "Authorization": f"Bearer {settings.EMAIL_SERVICE_TOKEN}",
                "Content-Type": "application/json",
            },
            json={
                "from": settings.EMAIL_FROM_ADDRESS,
                "to": [recipient],
                "subject": "Your OmniBioAI Admin verification code",
                "text": (
                    f"Your OmniBioAI Admin verification code is {code}. "
                    f"It expires in {expires_minutes} minutes and can be used once. "
                    "If you did not attempt to sign in, contact your security administrator."
                ),
                "tags": [{"name": "message_type", "value": "admin_mfa"}],
            },
            timeout=5,
        )
        response.raise_for_status()
    except (httpx.HTTPError, ValueError):
        raise EmailDeliveryError("Email delivery is unavailable") from None


def send_organization_invitation(
    recipient: str, *, organization_name: str, roles: list[str], accept_url: str,
) -> None:
    """Deliver the single-use invitation link. The caller must not log the
    token-bearing URL or provider payload; errors deliberately omit both.
    """
    if not settings.EMAIL_SERVICE_SEND_URL or not settings.EMAIL_SERVICE_TOKEN:
        raise EmailDeliveryError("Email delivery is unavailable")
    try:
        response = httpx.post(
            settings.EMAIL_SERVICE_SEND_URL,
            headers={
                "Authorization": f"Bearer {settings.EMAIL_SERVICE_TOKEN}",
                "Content-Type": "application/json",
            },
            json={
                "from": settings.EMAIL_FROM_ADDRESS,
                "to": [recipient],
                "subject": f"Invitation to join {organization_name} on OmniBioAI",
                "text": (
                    f"You have been invited to join {organization_name} on OmniBioAI.\n"
                    f"Organization roles requested: {', '.join(roles)}.\n\n"
                    f"Accept this invitation using the secure link: {accept_url}\n\n"
                    "The link is single-use and expires automatically. If you did not expect this invitation, ignore this message."
                ),
                "tags": [{"name": "message_type", "value": "organization_invitation"}],
            },
            timeout=5,
        )
        response.raise_for_status()
    except (httpx.HTTPError, ValueError):
        raise EmailDeliveryError("Email delivery is unavailable") from None
