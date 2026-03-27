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

class TestDnsDiffAPI:
    """Test /api/dns-diff endpoint."""

    def test_dns_diff_requires_domain(self, client):
        """Test /api/dns-diff requires domain1 parameter."""
        response = client.get("/api/dns-diff")
        assert response.status_code == 400

    def test_dns_diff_rejects_invalid_domain(self, client):
        """Test /api/dns-diff rejects invalid domain."""
        response = client.get("/api/dns-diff?domain1=")
        assert response.status_code == 400

    def test_dns_diff_rejects_invalid_type(self, client):
        """Test /api/dns-diff rejects invalid record type."""
        response = client.get("/api/dns-diff?domain1=example.com&type=INVALID")
        assert response.status_code == 400


class TestEmailSecurityAPI:
    """Test /api/email-security endpoint."""

    def test_email_security_requires_domain(self, client):
        """Test /api/email-security requires domain parameter."""
        response = client.get("/api/email-security")
        assert response.status_code == 400

    def test_email_security_rejects_invalid_domain(self, client):
        """Test /api/email-security rejects invalid domain."""
        response = client.get("/api/email-security?domain=")
        assert response.status_code == 400


class TestSecurityAuditAPI:
    """Test /api/security-audit endpoint."""

    def test_security_audit_requires_domain(self, client):
        """Test /api/security-audit requires domain parameter."""
        response = client.get("/api/security-audit")
        assert response.status_code == 400

    def test_security_audit_rejects_invalid_domain(self, client):
        """Test /api/security-audit rejects invalid domain."""
        response = client.get("/api/security-audit?domain=")
        assert response.status_code == 400


class TestResolveEdgeCases:
    """Test edge cases for /api/resolve."""

    def test_resolve_rejects_invalid_type(self, client):
        """Test /api/resolve rejects invalid record type."""
        response = client.get("/api/resolve?domain=example.com&type=INVALID")
        assert response.status_code == 400

    def test_resolve_rejects_invalid_server_ip(self, client):
        """Test /api/resolve rejects non-IP server parameter."""
        response = client.get("/api/resolve?domain=example.com&servers=notanip")
        assert response.status_code == 400

    def test_resolve_accepts_all_type(self, client):
        """Test /api/resolve accepts ALL record type."""
        response = client.get("/api/resolve?domain=example.com&type=ALL")
        assert response.status_code == 200


class TestErrorHandlers:
    """Test custom error handlers."""

    def test_404_html(self, client):
        """Test 404 for non-API routes returns HTML."""
        response = client.get("/nonexistent-page")
        assert response.status_code == 404

    def test_404_api(self, client):
        """Test 404 for API routes returns JSON."""
        response = client.get("/api/nonexistent")
        assert response.status_code == 404
        data = response.get_json()
        assert "error" in data