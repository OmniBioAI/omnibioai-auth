"""Liveness and metrics endpoints of the auth service: /health answers without
authentication and /metrics exposes the Prometheus JWT counters.

Developer: Manish Kumar <manish@omnibioai.org>
"""


def test_health(client):
    """The /health endpoint returns 200 with the body {"status": "ok"}."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_metrics(client):
    """The /metrics endpoint returns 200 and exposes the jwt_auth_total counter."""
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert b"jwt_auth_total" in resp.content
