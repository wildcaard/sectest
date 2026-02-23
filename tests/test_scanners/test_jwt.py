"""Tests for JWT Security Scanner."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from security_agent.scanners.jwt import JWTAnalyzer, parse_jwt, base64url_decode, WEAK_SECRETS
from security_agent.models.vulnerability import Severity, VulnerabilityCategory


# Sample JWT tokens for testing
# These are valid JWT structure tokens (not cryptographically valid)
TOKEN_NONE_ALGORITHM = "eyJhbGciOiJub25lIiwieDIiOiIifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."

TOKEN_NO_EXP = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signature"

TOKEN_NO_NBF = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature"

TOKEN_NO_IAT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwLCJleHAiOjE1MTYyMzkwMjJ9.signature"

TOKEN_VALID = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE5MTYyMzkwMjIsIm5iZiI6MTUxNjIzOTAyMn0.signature"

TOKEN_RS256 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signature"

TOKEN_WITH_JWK = "eyJhbGciOiJSUzI1NiIsImprcSI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImFiY3RlZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoiLCJ5IjoiMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAifX0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"


@pytest.fixture
def mock_http_client():
    """Create a mock HTTP client."""
    client = AsyncMock()
    return client


@pytest.fixture
def config():
    """Create a test config."""
    return {
        "scan": {"timeout": 30, "max_concurrent": 5},
        "scanners": {
            "jwt": {"enabled": True, "phase": 2}
        }
    }


@pytest.fixture
def jwt_scanner(mock_http_client, config):
    """Create a JWT scanner instance."""
    return JWTAnalyzer(mock_http_client, config)


class TestBase64UrlDecode:
    """Tests for base64url_decode function."""

    def test_valid_base64url(self):
        """Test decoding valid base64url encoded string."""
        # "test" encoded
        result = base64url_decode("dGVzdA")
        assert result == b"test"

    def test_valid_base64url_with_padding(self):
        """Test decoding base64url with padding."""
        result = base64url_decode("YQ")
        assert result == b"a"

    def test_invalid_base64url(self):
        """Test decoding invalid base64url returns None."""
        result = base64url_decode("!!!invalid!!!")
        assert result is None


class TestParseJWT:
    """Tests for parse_jwt function."""

    def test_valid_jwt(self):
        """Test parsing a valid JWT token."""
        header, payload = parse_jwt(TOKEN_VALID)
        assert header is not None
        assert payload is not None
        assert header.get("alg") == "HS256"
        assert "exp" in payload
        assert "iat" in payload
        assert "nbf" in payload

    def test_none_algorithm(self):
        """Test parsing JWT with none algorithm."""
        header, payload = parse_jwt(TOKEN_NONE_ALGORITHM)
        assert header is not None
        assert header.get("alg") == "none"

    def test_invalid_jwt_wrong_parts(self):
        """Test parsing invalid JWT with wrong number of parts."""
        header, payload = parse_jwt("invalid.token")
        assert header is None
        assert payload is None

    def test_invalid_jwt_malformed(self):
        """Test parsing malformed JWT."""
        header, payload = parse_jwt("not.a.jwt.token")
        assert header is None


class TestJWTScannerProperties:
    """Tests for JWT scanner properties."""

    def test_name(self, jwt_scanner):
        """Test scanner name."""
        assert jwt_scanner.name == "JWT Security Scanner"

    def test_description(self, jwt_scanner):
        """Test scanner description."""
        assert "JWT" in jwt_scanner.description

    def test_phase(self, jwt_scanner):
        """Test scanner phase."""
        assert jwt_scanner.phase == 2

    def test_is_enabled(self, jwt_scanner):
        """Test scanner is enabled."""
        assert jwt_scanner.is_enabled() is True


class TestJWTNoneAlgorithm:
    """Tests for detecting none algorithm."""

    @pytest.mark.asyncio
    async def test_detects_none_algorithm(self, jwt_scanner, mock_http_client):
        """Test detection of none algorithm."""
        # Create a mock response with JWT in body
        response = MagicMock()
        response.text = f'{{"token": "{TOKEN_NONE_ALGORITHM}"}}'
        response.headers = {}
        mock_http_client.get = AsyncMock(return_value=response)

        vulnerabilities = await jwt_scanner.scan("https://example.com")

        # Should find critical vulnerability for none algorithm
        none_vulns = [v for v in vulnerabilities if "none" in v.title.lower()]
        assert len(none_vulns) > 0
        assert none_vulns[0].severity == Severity.CRITICAL


class TestJWTMissingClaims:
    """Tests for detecting missing claims."""

    @pytest.mark.asyncio
    async def test_missing_exp_claim(self, jwt_scanner, mock_http_client):
        """Test detection of missing exp claim."""
        response = MagicMock()
        response.text = f'{{"token": "{TOKEN_NO_EXP}"}}'
        response.headers = {}
        mock_http_client.get = AsyncMock(return_value=response)

        vulnerabilities = await jwt_scanner.scan("https://example.com")

        exp_vulns = [v for v in vulnerabilities if "expiration" in v.title.lower()]
        assert len(exp_vulns) > 0
        assert exp_vulns[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_missing_nbf_claim(self, jwt_scanner, mock_http_client):
        """Test detection of missing nbf claim."""
        response = MagicMock()
        response.text = f'{{"token": "{TOKEN_NO_NBF}"}}'
        response.headers = {}
        mock_http_client.get = AsyncMock(return_value=response)

        vulnerabilities = await jwt_scanner.scan("https://example.com")

        nbf_vulns = [v for v in vulnerabilities if "not before" in v.title.lower()]
        assert len(nbf_vulns) > 0
        assert nbf_vulns[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_missing_iat_claim(self, jwt_scanner, mock_http_client):
        """Test detection of missing iat claim."""
        response = MagicMock()
        response.text = f'{{"token": "{TOKEN_NO_IAT}"}}'
        response.headers = {}
        mock_http_client.get = AsyncMock(return_value=response)

        vulnerabilities = await jwt_scanner.scan("https://example.com")

        iat_vulns = [v for v in vulnerabilities if "issued at" in v.title.lower()]
        assert len(iat_vulns) > 0
        assert iat_vulns[0].severity == Severity.MEDIUM


class TestJWTAlgorithmConfusion:
    """Tests for algorithm confusion detection."""

    @pytest.mark.asyncio
    async def test_rs256_algorithm(self, jwt_scanner, mock_http_client):
        """Test detection of RS256 algorithm."""
        response = MagicMock()
        response.text = f'{{"token": "{TOKEN_RS256}"}}'
        response.headers = {}
        mock_http_client.get = AsyncMock(return_value=response)

        vulnerabilities = await jwt_scanner.scan("https://example.com")

        rs256_vulns = [v for v in vulnerabilities if "RS256" in v.title]
        assert len(rs256_vulns) > 0
        assert rs256_vulns[0].severity == Severity.HIGH


class TestJWTKeyConfusion:
    """Tests for key confusion detection."""

    @pytest.mark.asyncio
    async def test_embedded_public_key(self, jwt_scanner, mock_http_client):
        """Test detection of embedded public key."""
        response = MagicMock()
        response.text = f'{{"token": "{TOKEN_WITH_JWK}"}}'
        response.headers = {}
        mock_http_client.get = AsyncMock(return_value=response)

        vulnerabilities = await jwt_scanner.scan("https://example.com")

        key_vulns = [v for v in vulnerabilities if "key" in v.title.lower()]
        assert len(key_vulns) > 0
        assert key_vulns[0].severity == Severity.HIGH


class TestJWTValidToken:
    """Tests for valid JWT tokens."""

    @pytest.mark.asyncio
    async def test_valid_token_no_vulnerabilities(self, jwt_scanner, mock_http_client):
        """Test that valid JWT with all claims has no vulnerabilities."""
        response = MagicMock()
        response.text = f'{{"token": "{TOKEN_VALID}"}}'
        response.headers = {}
        mock_http_client.get = AsyncMock(return_value=response)

        vulnerabilities = await jwt_scanner.scan("https://example.com")

        # Should have no critical or high vulnerabilities
        critical_high = [v for v in vulnerabilities 
                        if v.severity in [Severity.CRITICAL, Severity.HIGH]]
        assert len(critical_high) == 0


class TestJWTInHeaders:
    """Tests for JWT detection in headers."""

    @pytest.mark.asyncio
    async def test_jwt_in_authorization_header(self, jwt_scanner, mock_http_client):
        """Test detection of JWT in Authorization header."""
        response = MagicMock()
        response.text = "{}"
        response.headers = {"Authorization": f"Bearer {TOKEN_VALID}"}
        mock_http_client.get = AsyncMock(return_value=response)

        vulnerabilities = await jwt_scanner.scan("https://example.com")

        # Should not have critical/high vulnerabilities for valid token
        critical_high = [v for v in vulnerabilities 
                        if v.severity in [Severity.CRITICAL, Severity.HIGH]]
        assert len(critical_high) == 0


class TestWeakSecrets:
    """Tests for weak secret detection."""

    def test_weak_secrets_list(self):
        """Test that weak secrets list contains expected values."""
        assert "secret" in WEAK_SECRETS
        assert "password" in WEAK_SECRETS
        assert "123456" in WEAK_SECRETS
        assert "admin" in WEAK_SECRETS
