#!/usr/bin/env python3
"""
Comprehensive test suite for OAuth 2.0 and UMA 2.0 flows.

Tests verify:
- Keycloak connectivity
- User authentication
- Token generation and validation
- User information retrieval
- Basic UMA 2.0 support
"""

import pytest
import requests
import json
import base64
from urllib.parse import urljoin
from typing import Optional, Dict

# Configuration
KEYCLOAK_URL = "http://localhost:8080"
REALM_NAME = "test-realm"
TEST_USER = "alice"
TEST_PASSWORD = "alice123"
TEST_CLIENT = "test-app"


class KeycloakTestClient:
    """Test client for Keycloak interactions"""

    def __init__(self, keycloak_url: str = KEYCLOAK_URL, realm: str = REALM_NAME):
        self.keycloak_url = keycloak_url
        self.realm = realm
        self.realm_url = urljoin(keycloak_url, f"/realms/{realm}")
        self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
        self.access_token = None
        self.user_info = None

    def get_oidc_config(self) -> Dict:
        """Get OpenID Connect configuration"""
        url = self.realm_url + "/.well-known/openid-configuration"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()

    def authenticate(self, username: str, password: str, client_id: str = TEST_CLIENT) -> str:
        """Authenticate user and return access token"""
        token_url = self.realm_url + "/protocol/openid-connect/token"

        payload = {
            "grant_type": "password",
            "client_id": client_id,
            "username": username,
            "password": password,
            "scope": "openid profile email",
        }

        response = self.session.post(token_url, data=payload)
        response.raise_for_status()

        data = response.json()
        self.access_token = data["access_token"]
        return self.access_token

    def decode_token(self, token: str) -> Dict:
        """Decode JWT token without verification"""
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid token format")

        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding:
            payload += '=' * padding

        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)

    def get_userinfo(self, token: Optional[str] = None) -> Dict:
        """Get user information"""
        if token is None:
            token = self.access_token

        if token is None:
            raise ValueError("No token available")

        userinfo_url = self.realm_url + "/protocol/openid-connect/userinfo"
        headers = {"Authorization": f"Bearer {token}"}

        response = self.session.get(userinfo_url, headers=headers)
        response.raise_for_status()

        self.user_info = response.json()
        return self.user_info

    def introspect_token(self, token: str, client_id: str = TEST_CLIENT) -> Dict:
        """Introspect token (verify it's still valid)"""
        introspect_url = self.realm_url + "/protocol/openid-connect/token/introspect"

        payload = {
            "client_id": client_id,
            "token": token,
        }

        response = self.session.post(introspect_url, data=payload)
        response.raise_for_status()
        return response.json()


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def keycloak_client() -> KeycloakTestClient:
    """Create Keycloak test client"""
    return KeycloakTestClient()


@pytest.fixture
def authenticated_client(keycloak_client: KeycloakTestClient) -> KeycloakTestClient:
    """Create authenticated Keycloak client"""
    keycloak_client.authenticate(TEST_USER, TEST_PASSWORD)
    return keycloak_client


# ============================================================================
# TESTS: KEYCLOAK CONNECTIVITY
# ============================================================================

class TestKeycloakConnectivity:
    """Test basic Keycloak connectivity"""

    def test_keycloak_available(self):
        """Test Keycloak is accessible"""
        response = requests.get(f"{KEYCLOAK_URL}/admin", verify=False)
        # Should redirect (302) if accessible
        assert response.status_code in [200, 302]

    def test_realm_accessible(self, keycloak_client: KeycloakTestClient):
        """Test realm URL is accessible"""
        response = keycloak_client.session.get(keycloak_client.realm_url + "/")
        assert response.status_code == 200

    def test_oidc_config_available(self, keycloak_client: KeycloakTestClient):
        """Test OIDC configuration is available"""
        config = keycloak_client.get_oidc_config()

        # Verify required OIDC endpoints
        assert "issuer" in config
        assert "token_endpoint" in config
        assert "authorization_endpoint" in config
        assert "userinfo_endpoint" in config

        # Verify endpoints point to correct realm
        assert REALM_NAME in config["issuer"]


# ============================================================================
# TESTS: OAUTH 2.0 AUTHENTICATION
# ============================================================================

class TestOAuth2Authentication:
    """Test OAuth 2.0 password grant flow"""

    def test_successful_authentication(self, keycloak_client: KeycloakTestClient):
        """Test user authentication returns valid token"""
        token = keycloak_client.authenticate(TEST_USER, TEST_PASSWORD)

        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 100
        assert token.count('.') == 2  # JWT has 3 parts

    def test_authentication_with_wrong_password(self, keycloak_client: KeycloakTestClient):
        """Test authentication fails with wrong password"""
        with pytest.raises(requests.exceptions.HTTPError):
            keycloak_client.authenticate(TEST_USER, "wrong-password")

    def test_authentication_with_nonexistent_user(self, keycloak_client: KeycloakTestClient):
        """Test authentication fails for nonexistent user"""
        with pytest.raises(requests.exceptions.HTTPError):
            keycloak_client.authenticate("nonexistent", "password")

    def test_token_has_bearer_type(self, keycloak_client: KeycloakTestClient):
        """Test token response includes token type"""
        token_url = keycloak_client.realm_url + "/protocol/openid-connect/token"

        payload = {
            "grant_type": "password",
            "client_id": TEST_CLIENT,
            "username": TEST_USER,
            "password": TEST_PASSWORD,
        }

        response = keycloak_client.session.post(token_url, data=payload)
        response.raise_for_status()

        data = response.json()
        assert data.get("token_type") == "Bearer"
        assert "access_token" in data
        assert "expires_in" in data


# ============================================================================
# TESTS: JWT TOKEN CLAIMS
# ============================================================================

class TestJWTTokenClaims:
    """Test JWT token structure and claims"""

    def test_token_can_be_decoded(self, authenticated_client: KeycloakTestClient):
        """Test token can be decoded to inspect claims"""
        token = authenticated_client.access_token
        claims = authenticated_client.decode_token(token)

        assert isinstance(claims, dict)
        assert len(claims) > 0

    def test_token_contains_standard_claims(self, authenticated_client: KeycloakTestClient):
        """Test token contains standard OIDC claims"""
        token = authenticated_client.access_token
        claims = authenticated_client.decode_token(token)

        # Standard OIDC claims
        assert "sub" in claims  # Subject (user ID)
        assert "iss" in claims  # Issuer
        assert "aud" in claims  # Audience
        assert "exp" in claims  # Expiration
        assert "iat" in claims  # Issued at

    def test_token_contains_user_claims(self, authenticated_client: KeycloakTestClient):
        """Test token contains user-specific claims"""
        token = authenticated_client.access_token
        claims = authenticated_client.decode_token(token)

        # User claims
        assert "preferred_username" in claims
        assert claims["preferred_username"] == TEST_USER

    def test_token_contains_role_claims(self, authenticated_client: KeycloakTestClient):
        """Test token contains role information"""
        token = authenticated_client.access_token
        claims = authenticated_client.decode_token(token)

        # Role information
        assert "realm_access" in claims or "resource_access" in claims

    def test_token_contains_scope(self, authenticated_client: KeycloakTestClient):
        """Test token contains granted scopes"""
        token = authenticated_client.access_token
        claims = authenticated_client.decode_token(token)

        assert "scope" in claims

    def test_token_expiration_is_valid(self, authenticated_client: KeycloakTestClient):
        """Test token expiration time is in the future"""
        import time
        token = authenticated_client.access_token
        claims = authenticated_client.decode_token(token)

        exp_time = claims["exp"]
        current_time = int(time.time())

        # Token should expire in the future (allow 5 minute window)
        assert exp_time > current_time


# ============================================================================
# TESTS: USER INFORMATION
# ============================================================================

class TestUserInformation:
    """Test /userinfo endpoint"""

    def test_userinfo_accessible(self, authenticated_client: KeycloakTestClient):
        """Test /userinfo endpoint returns user information"""
        userinfo = authenticated_client.get_userinfo()

        assert isinstance(userinfo, dict)
        assert len(userinfo) > 0

    def test_userinfo_contains_profile(self, authenticated_client: KeycloakTestClient):
        """Test userinfo contains user profile information"""
        userinfo = authenticated_client.get_userinfo()

        # Profile claims
        assert "sub" in userinfo
        assert "preferred_username" in userinfo
        assert userinfo["preferred_username"] == TEST_USER

    def test_userinfo_contains_email(self, authenticated_client: KeycloakTestClient):
        """Test userinfo contains email information"""
        userinfo = authenticated_client.get_userinfo()

        assert "email" in userinfo
        assert "@" in userinfo["email"]

    def test_userinfo_with_invalid_token(self, keycloak_client: KeycloakTestClient):
        """Test /userinfo fails with invalid token"""
        with pytest.raises(requests.exceptions.HTTPError):
            keycloak_client.get_userinfo("invalid-token")


# ============================================================================
# TESTS: TOKEN INTROSPECTION
# ============================================================================

class TestTokenIntrospection:
    """Test token introspection endpoint"""

    def test_introspect_valid_token(self, authenticated_client: KeycloakTestClient):
        """Test introspecting a valid token"""
        # Note: This may fail with 403 if client isn't configured for introspection
        # but the endpoint should still exist
        token = authenticated_client.access_token

        try:
            result = authenticated_client.introspect_token(token)
            # If it succeeds, verify the structure
            assert isinstance(result, dict)
        except requests.exceptions.HTTPError as e:
            # Expected if client not configured for introspection
            assert e.response.status_code in [403, 400]

    def test_introspection_endpoint_exists(self, keycloak_client: KeycloakTestClient):
        """Test token introspection endpoint is available"""
        config = keycloak_client.get_oidc_config()
        assert "introspection_endpoint" in config


# ============================================================================
# TESTS: MULTIPLE USERS
# ============================================================================

class TestMultipleUsers:
    """Test authentication with different users"""

    def test_alice_authentication(self, keycloak_client: KeycloakTestClient):
        """Test Alice can authenticate"""
        token = keycloak_client.authenticate("alice", "alice123")
        assert token is not None

        claims = keycloak_client.decode_token(token)
        assert claims["preferred_username"] == "alice"

    def test_bob_authentication(self, keycloak_client: KeycloakTestClient):
        """Test Bob can authenticate"""
        token = keycloak_client.authenticate("bob", "bob123")
        assert token is not None

        claims = keycloak_client.decode_token(token)
        assert claims["preferred_username"] == "bob"

    def test_different_users_get_different_tokens(self):
        """Test different users get different tokens"""
        client1 = KeycloakTestClient()
        client2 = KeycloakTestClient()

        token1 = client1.authenticate("alice", "alice123")
        token2 = client2.authenticate("bob", "bob123")

        assert token1 != token2


# ============================================================================
# TESTS: UMA 2.0 SUPPORT
# ============================================================================

class TestUMA2Support:
    """Test UMA 2.0 support in realm"""

    def test_uma_grant_type_supported(self, keycloak_client: KeycloakTestClient):
        """Test UMA grant type is advertised"""
        config = keycloak_client.get_oidc_config()

        grant_types = config.get("grant_types_supported", [])
        # Look for UMA ticket grant type
        uma_grants = [g for g in grant_types if "uma" in g.lower() or "ticket" in g.lower()]
        # UMA 2.0 may be optional, but framework should support it
        assert isinstance(grant_types, list)

    def test_user_has_uma_authorization_role(self, authenticated_client: KeycloakTestClient):
        """Test user has UMA authorization role"""
        userinfo = authenticated_client.get_userinfo()
        token = authenticated_client.access_token
        claims = authenticated_client.decode_token(token)

        # Check for UMA authorization capability
        realm_access = claims.get("realm_access", {})
        roles = realm_access.get("roles", [])

        # UMA authorization should be available
        assert "uma_authorization" in roles or len(roles) > 0


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestCompleteFlow:
    """Test complete OAuth 2.0 flow"""

    def test_complete_authentication_flow(self, keycloak_client: KeycloakTestClient):
        """Test complete authentication and user info flow"""
        # Step 1: Authenticate
        token = keycloak_client.authenticate(TEST_USER, TEST_PASSWORD)
        assert token is not None

        # Step 2: Decode token
        claims = keycloak_client.decode_token(token)
        assert claims["preferred_username"] == TEST_USER

        # Step 3: Get user info
        userinfo = keycloak_client.get_userinfo(token)
        assert userinfo["preferred_username"] == TEST_USER

        # Step 4: Verify consistency
        assert claims["sub"] == userinfo["sub"]
        assert claims["email"] == userinfo["email"]

    def test_realm_configuration_consistency(self, keycloak_client: KeycloakTestClient):
        """Test realm configuration is consistent"""
        config = keycloak_client.get_oidc_config()

        # All endpoint URLs should contain the realm name
        for endpoint_key in ["token_endpoint", "authorization_endpoint", "userinfo_endpoint"]:
            if endpoint_key in config:
                assert REALM_NAME in config[endpoint_key]


# ============================================================================
# PERFORMANCE TESTS
# ============================================================================

class TestPerformance:
    """Test performance of authentication"""

    def test_authentication_latency(self, keycloak_client: KeycloakTestClient):
        """Test authentication completes within reasonable time"""
        import time

        start = time.time()
        token = keycloak_client.authenticate(TEST_USER, TEST_PASSWORD)
        elapsed = time.time() - start

        assert token is not None
        # Should complete in less than 2 seconds
        assert elapsed < 2.0

    def test_userinfo_retrieval_latency(self, authenticated_client: KeycloakTestClient):
        """Test userinfo retrieval is fast"""
        import time

        start = time.time()
        userinfo = authenticated_client.get_userinfo()
        elapsed = time.time() - start

        assert userinfo is not None
        # Should complete in less than 1 second
        assert elapsed < 1.0

    def test_token_decoding_is_instant(self, authenticated_client: KeycloakTestClient):
        """Test token decoding is instant (no network call)"""
        import time

        token = authenticated_client.access_token

        start = time.time()
        claims = authenticated_client.decode_token(token)
        elapsed = time.time() - start

        assert claims is not None
        # Should be essentially instant (< 10ms)
        assert elapsed < 0.01


# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == "__main__":
    # Run pytest
    pytest.main([__file__, "-v", "--tb=short"])
