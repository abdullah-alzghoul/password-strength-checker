"""Unit tests for the breach_checker module. Network calls are mocked —
no real request hits the HIBP API during testing."""

import hashlib
from unittest.mock import Mock, patch

import requests

from src.core.breach_checker import check_breach, sha1_hash


def _hash_parts(password: str) -> tuple[str, str]:
    """Test helper: compute the same prefix/suffix split the production code uses."""
    full = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return full[:5], full[5:]


class TestSha1Hash:
    def test_matches_hashlib_reference(self):
        expected = hashlib.sha1(b"password").hexdigest().upper()
        assert sha1_hash("password") == expected

    def test_output_is_40_char_uppercase_hex(self):
        result = sha1_hash("anything")
        assert len(result) == 40
        assert result == result.upper()
        assert all(c in "0123456789ABCDEF" for c in result)

    def test_different_passwords_different_hashes(self):
        assert sha1_hash("password1") != sha1_hash("password2")


class TestCheckBreach:
    @patch("src.core.breach_checker.requests.get")
    def test_breached_password_detected(self, mock_get):
        _, suffix = _hash_parts("password")
        mock_response = Mock()
        mock_response.text = f"{suffix}:9999999\nAAAA1111:5"
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        result = check_breach("password")
        assert result.checked is True
        assert result.is_breached is True
        assert result.breach_count == 9999999

    @patch("src.core.breach_checker.requests.get")
    def test_clean_password_not_breached(self, mock_get):
        mock_response = Mock()
        mock_response.text = "AAAA1111:5\nBBBB2222:10"
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        result = check_breach("Xk9$mQ2vL7!p_unique_test_string")
        assert result.checked is True
        assert result.is_breached is False

    @patch("src.core.breach_checker.requests.get")
    def test_correct_prefix_sent_to_api(self, mock_get):
        prefix, _ = _hash_parts("password")
        mock_response = Mock()
        mock_response.text = ""
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        check_breach("password")
        called_url = mock_get.call_args[0][0]
        assert prefix in called_url

    @patch("src.core.breach_checker.requests.get")
    def test_network_failure_handled_gracefully(self, mock_get):
        mock_get.side_effect = requests.ConnectionError("network down")

        result = check_breach("anything")
        assert result.checked is False
        assert result.error is not None
