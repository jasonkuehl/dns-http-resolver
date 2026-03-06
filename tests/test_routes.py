"""Tests for basic routes and health endpoints."""


class TestHealthEndpoints:
    """Test health check and status endpoints."""

    def test_health_check(self, client):
        """Test /health endpoint returns healthy status."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "healthy"
        assert data["service"] == "dns-http-resolver"
        assert "timestamp" in data

    def test_favicon_returns_204(self, client):
        """Test /favicon.ico returns 204 No Content."""
        response = client.get("/favicon.ico")
        assert response.status_code == 204


class TestPageRoutes:
    """Test HTML page routes return successfully."""

    def test_home_page(self, client):
        """Test home page loads."""
        response = client.get("/")
        assert response.status_code == 200
        assert b"<!DOCTYPE html>" in response.data or b"<html" in response.data

    def test_resolve_page(self, client):
        """Test resolve page loads."""
        response = client.get("/resolve")
        assert response.status_code == 200

    def test_trace_page(self, client):
        """Test trace page loads."""
        response = client.get("/trace")
        assert response.status_code == 200

    def test_readme_page(self, client):
        """Test readme page loads."""
        response = client.get("/readme")
        assert response.status_code == 200

    def test_email_security_page(self, client):
        """Test email-security page loads."""
        response = client.get("/email-security")
        assert response.status_code == 200

    def test_propagation_page(self, client):
        """Test propagation page loads."""
        response = client.get("/propagation")
        assert response.status_code == 200

    def test_blacklist_page(self, client):
        """Test blacklist page loads."""
        response = client.get("/blacklist")
        assert response.status_code == 200

    def test_security_audit_page(self, client):
        """Test security-audit page loads."""
        response = client.get("/security-audit")
        assert response.status_code == 200

    def test_zone_info_page(self, client):
        """Test zone-info page loads."""
        response = client.get("/zone-info")
        assert response.status_code == 200

    def test_subdomain_scan_page(self, client):
        """Test subdomain-scan page loads."""
        response = client.get("/subdomain-scan")
        assert response.status_code == 200

    def test_dns_diff_page(self, client):
        """Test dns-diff page loads."""
        response = client.get("/dns-diff")
        assert response.status_code == 200


class TestServersEndpoint:
    """Test the /api/servers endpoint."""

    def test_servers_returns_json(self, client):
        """Test /api/servers returns server list."""
        response = client.get("/api/servers")
        assert response.status_code == 200
        data = response.get_json()
        assert "servers" in data
        assert "configured" in data
        assert isinstance(data["servers"], dict)
