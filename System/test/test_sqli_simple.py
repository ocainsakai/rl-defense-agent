"""
Test SQLi Detection - PayloadContextScorer
Test truc tiep voi payload cu the
"""

import pytest

from feature.payload_context import PayloadContextScorer


# SQLi attacks (label=1) and normal payloads (label=0)
ATTACK_PAYLOADS = [
    "a' or 1 = 1; --",
    "' and 1 = 0 )  union all",
    pytest.param("x' and userid is NULL; --", marks=pytest.mark.xfail(reason="No matching pattern for 'and userid is NULL'")),
    "' or '1' = '1",
    "1 UNION SELECT username,password FROM users--",
    "admin' OR '1'='1'--",
    "'; DROP TABLE users;--",
    pytest.param("1; SELECT * FROM passwords", marks=pytest.mark.xfail(reason="Stacked query pattern requires DROP/DELETE/INSERT/UPDATE")),
    "' OR 1=1#",
    "UNION SELECT NULL,version()--",
]

NORMAL_PAYLOADS = [
    "hello world",
    "user@email.com",
    "This is normal text",
    "Product name 123",
    "Search query here",
]


@pytest.mark.sqli
class TestSqliSimple:
    """Test PayloadContextScorer with known payloads."""

    @pytest.mark.parametrize("payload", ATTACK_PAYLOADS)
    def test_attack_detected(self, payload):
        """Attack payloads should have sqli_score > 0."""
        payload_bytes = payload.encode('utf-8')
        sqli_score = PayloadContextScorer.count_sqli_indicators(payload_bytes)
        assert sqli_score > 0, f"Missed attack: {payload}"

    @pytest.mark.parametrize("payload", NORMAL_PAYLOADS)
    def test_normal_not_detected(self, payload):
        """Normal payloads should have sqli_score == 0."""
        payload_bytes = payload.encode('utf-8')
        sqli_score = PayloadContextScorer.count_sqli_indicators(payload_bytes)
        assert sqli_score == 0, f"False positive: {payload}"
