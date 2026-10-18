"""Narrow adapter for the configured transactional email service."""
import httpx

from app.core.config import settings


class EmailDeliveryError(RuntimeError):
    """Delivery failed without exposing provider details or message content."""


def send_mfa_code(recipient: str, code: str, expires_minutes: int = 5) -> None:
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
                "subject": "Your OmniBioAI verification code",
                "text": (
                    f"Your OmniBioAI verification code is {code}. It expires in "
                    f"{expires_minutes} minutes and can be used once. If you did not "
                    "attempt to sign in, contact your security administrator."
                ),
                "tags": [{"name": "message_type", "value": "admin_mfa"}],
            },
            timeout=5,
        )
        response.raise_for_status()
    except httpx.HTTPError:
        raise EmailDeliveryError("Email delivery is unavailable") from None
