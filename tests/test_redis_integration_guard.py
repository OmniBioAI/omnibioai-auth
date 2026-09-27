import pytest

from _redis_integration_guard import (
    MissingTestRedisAttestation,
    ProductionRedisEndpointRejected,
    validate_test_redis_isolation,
    validate_test_redis_url,
)


def test_production_service_and_port_are_rejected():
    with pytest.raises(ProductionRedisEndpointRejected):
        validate_test_redis_url("redis://redis:6379/0", "B2_TEST_REDIS_URL")
    with pytest.raises(ProductionRedisEndpointRejected):
        validate_test_redis_url("redis://127.0.0.1:6380/0", "B2_TEST_REDIS_URL")


def test_explicit_isolation_attestation_is_required():
    with pytest.raises(MissingTestRedisAttestation):
        validate_test_redis_isolation(
            "redis://127.0.0.1:16379/3", "B2_TEST_REDIS_URL",
            attested=None, database="3", key_prefix="shadow",
        )
    assert validate_test_redis_isolation(
        "redis://127.0.0.1:16379/3", "B2_TEST_REDIS_URL",
        attested="1", database="3", key_prefix="shadow",
    ) == "redis://127.0.0.1:16379/3"
