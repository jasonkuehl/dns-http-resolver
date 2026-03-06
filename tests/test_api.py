"""Tests for DNS API endpoints."""

import pytest


class TestResolveAPI:
    """Test /api/resolve endpoint."""

    def test_resolve_requires_domain(self, client):
        """Test /api/resolve returns error without domain."""
        response = client.get("/api/resolve")
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_resolve_invalid_domain(self, client):
        """Test /api/resolve returns error for invalid domain."""
        response = client.get("/api/resolve?domain=")
        assert response.status_code == 400

    def test_resolve_valid_domain(self, client):
        """Test /api/resolve works for valid domain."""
        response = client.get("/api/resolve?domain=google.com&type=A")
        assert response.status_code == 200
        data = response.get_json()
        assert "domain" in data
        assert data["domain"] == "google.com"
        assert "results" in data

    def test_resolve_with_type(self, client):
        """Test /api/resolve accepts record type parameter."""
        response = client.get("/api/resolve?domain=google.com&type=MX")
        assert response.status_code == 200
        data = response.get_json()
        assert "results" in data


class TestTraceAPI:
    """Test /api/trace endpoint."""

    def test_trace_requires_domain(self, client):
        """Test /api/trace returns error without domain."""
        response = client.get("/api/trace")
        assert response.status_code == 400

    def test_trace_invalid_domain(self, client):
        """Test /api/trace returns error for invalid domain."""
        response = client.get("/api/trace?domain=")
        assert response.status_code == 400


class TestReverseAPI:
    """Test /api/reverse endpoint."""

    def test_reverse_requires_ip(self, client):
        """Test /api/reverse returns error without IP."""
        response = client.get("/api/reverse")
        assert response.status_code == 400

    def test_reverse_invalid_ip(self, client):
        """Test /api/reverse returns error for invalid IP."""
        response = client.get("/api/reverse?ip=notanip")
        assert response.status_code == 400

    def test_reverse_valid_ip(self, client):
        """Test /api/reverse works for valid IP."""
        response = client.get("/api/reverse?ip=8.8.8.8")
        assert response.status_code == 200
        data = response.get_json()
        assert "ip" in data


class TestPropagationAPI:
    """Test /api/propagation endpoint."""

    def test_propagation_requires_domain(self, client):
        """Test /api/propagation returns error without domain."""
        response = client.get("/api/propagation")
        assert response.status_code == 400


class TestBlacklistAPI:
    """Test /api/blacklist endpoint."""

    def test_blacklist_requires_ip(self, client):
        """Test /api/blacklist returns error without IP."""
        response = client.get("/api/blacklist")
        assert response.status_code == 400

    def test_blacklist_rejects_ipv6(self, client):
        """Test /api/blacklist rejects IPv6 addresses."""
        response = client.get("/api/blacklist?ip=::1")
        assert response.status_code == 400


class TestCompareAPI:
    """Test /api/compare endpoint."""

    def test_compare_requires_domain(self, client):
        """Test /api/compare returns error without domain."""
        response = client.get("/api/compare")
        assert response.status_code == 400


class TestSubdomainScanAPI:
    """Test /api/subdomain-scan endpoint."""

    def test_subdomain_scan_requires_domain(self, client):
        """Test /api/subdomain-scan returns error without domain."""
        response = client.get("/api/subdomain-scan")
        assert response.status_code == 400


class TestZoneInfoAPI:
    """Test /api/zone-info endpoint."""

    def test_zone_info_requires_domain(self, client):
        """Test /api/zone-info returns error without domain."""
        response = client.get("/api/zone-info")
        assert response.status_code == 400
