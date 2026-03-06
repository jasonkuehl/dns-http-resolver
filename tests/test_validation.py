"""Tests for validation functions."""

import pytest
from app import is_valid_domain_input


class TestDomainValidation:
    """Test is_valid_domain_input function."""

    def test_valid_domain(self):
        """Test valid domain names pass validation."""
        assert is_valid_domain_input("example.com") is True
        assert is_valid_domain_input("sub.example.com") is True
        assert is_valid_domain_input("deep.sub.example.com") is True

    def test_valid_fqdn_with_trailing_dot(self):
        """Test FQDN with trailing dot passes validation."""
        assert is_valid_domain_input("example.com.") is True

    def test_valid_ipv4(self):
        """Test valid IPv4 addresses pass validation."""
        assert is_valid_domain_input("8.8.8.8") is True
        assert is_valid_domain_input("1.1.1.1") is True
        assert is_valid_domain_input("192.168.1.1") is True

    def test_valid_ipv6(self):
        """Test valid IPv6 addresses pass validation."""
        assert is_valid_domain_input("::1") is True
        assert is_valid_domain_input("2001:4860:4860::8888") is True

    def test_single_label_hostname(self):
        """Test single-label hostnames pass validation."""
        assert is_valid_domain_input("localhost") is True
        assert is_valid_domain_input("myserver") is True

    def test_empty_string_rejected(self):
        """Test empty string is rejected."""
        assert is_valid_domain_input("") is False
        assert is_valid_domain_input("   ") is False

    def test_none_rejected(self):
        """Test None is rejected."""
        assert is_valid_domain_input(None) is False

    def test_spaces_rejected(self):
        """Test strings with internal spaces are rejected."""
        assert is_valid_domain_input("example .com") is False
        # Note: Leading/trailing spaces are stripped, so those pass
        assert is_valid_domain_input(" example.com") is True  # strips leading space

    def test_too_long_domain_rejected(self):
        """Test domain names over 253 chars are rejected."""
        long_domain = "a" * 254
        assert is_valid_domain_input(long_domain) is False

    def test_label_too_long_rejected(self):
        """Test labels over 63 chars are rejected."""
        long_label = "a" * 64 + ".com"
        assert is_valid_domain_input(long_label) is False

    def test_valid_with_hyphens(self):
        """Test domains with hyphens pass validation."""
        assert is_valid_domain_input("my-domain.com") is True
        assert is_valid_domain_input("sub-domain.example.com") is True

    def test_valid_with_numbers(self):
        """Test domains with numbers pass validation."""
        assert is_valid_domain_input("domain123.com") is True
        assert is_valid_domain_input("123domain.com") is True
