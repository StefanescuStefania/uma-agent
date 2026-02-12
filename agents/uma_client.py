"""
UMA 2.0 Client Implementation

Implements the complete UMA 2.0 protocol flow:
1. Resource Server registers resources with Keycloak
2. Agent requests access → receives Permission Ticket
3. Agent exchanges Permission Ticket for RPT (Requesting Party Token)
4. Agent uses RPT to access protected resources

This is a production-ready implementation with proper error handling,
logging, and token management.
"""

import logging
import requests
from typing import Optional, Dict, List, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


@dataclass
class PermissionTicket:
    """Represents a UMA permission ticket"""
    ticket: str
    expires_at: datetime

    def is_expired(self) -> bool:
        """Check if ticket has expired"""
        return datetime.utcnow() >= self.expires_at


@dataclass
class RPT:
    """Requesting Party Token (RPT) - UMA access token"""
    access_token: str
    token_type: str
    expires_in: int
    issued_at: datetime
    refresh_token: Optional[str] = None
    permissions: Optional[List[Dict[str, Any]]] = None

    def is_expired(self) -> bool:
        """Check if RPT has expired"""
        elapsed = (datetime.utcnow() - self.issued_at).total_seconds()
        return elapsed >= (self.expires_in - 60)  # Refresh 1 min before expiry

    def has_permission(self, resource: str, scope: str) -> bool:
        """Check if RPT has specific permission"""
        if not self.permissions:
            return False

        for perm in self.permissions:
            if perm.get('rsname') == resource:
                if scope in perm.get('scopes', []):
                    return True
        return False


class UMAClient:
    """
    Production-ready UMA 2.0 Client

    Handles complete UMA flow:
    - Permission ticket requests
    - RPT token exchange
    - Token refresh
    - Resource registration
    """

    def __init__(
        self,
        keycloak_url: str,
        realm: str,
        client_id: str,
        client_secret: Optional[str] = None,
        timeout: int = 30
    ):
        """
        Initialize UMA client

        Args:
            keycloak_url: Keycloak server URL (e.g., http://localhost:8080)
            realm: Realm name
            client_id: Client ID for resource server
            client_secret: Client secret (for confidential clients)
            timeout: Request timeout in seconds
        """
        self.keycloak_url = keycloak_url.rstrip('/')
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout

        # Build endpoint URLs
        self.realm_url = f"{self.keycloak_url}/realms/{realm}"
        self.token_endpoint = f"{self.realm_url}/protocol/openid-connect/token"
        self.uma_config_endpoint = f"{self.realm_url}/.well-known/uma2-configuration"

        # Fetch UMA configuration
        self._uma_config = None
        self._load_uma_config()

        logger.info(f"UMA Client initialized for realm '{realm}'")

    def _load_uma_config(self):
        """Load UMA 2.0 configuration from Keycloak"""
        try:
            response = requests.get(
                self.uma_config_endpoint,
                timeout=self.timeout
            )
            response.raise_for_status()
            self._uma_config = response.json()
            logger.info("UMA configuration loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load UMA configuration: {e}")
            # Set default endpoints if config unavailable
            self._uma_config = {
                "permission_endpoint": f"{self.realm_url}/authz/protection/permission",
                "token_endpoint": self.token_endpoint,
                "resource_registration_endpoint": f"{self.realm_url}/authz/protection/resource_set"
            }

    def get_permission_endpoint(self) -> str:
        """Get permission endpoint URL"""
        return self._uma_config.get(
            "permission_endpoint",
            f"{self.realm_url}/authz/protection/permission"
        )

    def get_token_endpoint(self) -> str:
        """Get token endpoint URL"""
        return self._uma_config.get("token_endpoint", self.token_endpoint)

    def get_resource_endpoint(self) -> str:
        """Get resource registration endpoint URL"""
        return self._uma_config.get(
            "resource_registration_endpoint",
            f"{self.realm_url}/authz/protection/resource_set"
        )

    # ========================================================================
    # Resource Server Operations (PAT - Protection API Token)
    # ========================================================================

    def get_protection_api_token(self) -> Optional[str]:
        """
        Get Protection API Token (PAT) for resource server

        This token is used by the resource server to:
        - Register resources
        - Create permission tickets

        Returns:
            PAT access token or None if failed
        """
        try:
            data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
            }

            if self.client_secret:
                data["client_secret"] = self.client_secret

            response = requests.post(
                self.get_token_endpoint(),
                data=data,
                timeout=self.timeout
            )
            response.raise_for_status()

            token_data = response.json()
            pat = token_data.get("access_token")

            logger.debug("Protection API Token obtained")
            return pat

        except Exception as e:
            logger.error(f"Failed to get Protection API Token: {e}")
            return None

    def register_resource(
        self,
        pat: str,
        name: str,
        resource_scopes: List[str],
        resource_type: Optional[str] = None,
        uri: Optional[str] = None
    ) -> Optional[str]:
        """
        Register a protected resource with Keycloak

        Args:
            pat: Protection API Token
            name: Resource name
            resource_scopes: List of scopes for this resource
            resource_type: Optional resource type
            uri: Optional resource URI

        Returns:
            Resource ID or None if failed
        """
        try:
            resource_data = {
                "name": name,
                "resource_scopes": [{"name": scope} for scope in resource_scopes],
                "type": resource_type or name,
                "ownerManagedAccess": True  # Enable UMA for this resource
            }

            if uri:
                resource_data["uris"] = [uri]

            response = requests.post(
                self.get_resource_endpoint(),
                json=resource_data,
                headers={
                    "Authorization": f"Bearer {pat}",
                    "Content-Type": "application/json"
                },
                timeout=self.timeout
            )

            # If resource already exists (409 Conflict), query for its ID
            if response.status_code == 409:
                logger.info(f"Resource '{name}' already exists, querying for ID...")
                # Query for existing resource by name
                query_response = requests.get(
                    self.get_resource_endpoint(),
                    params={"name": name},
                    headers={"Authorization": f"Bearer {pat}"},
                    timeout=self.timeout
                )
                if query_response.status_code == 200:
                    resources = query_response.json()
                    # Response is a list of resource IDs (strings), not objects
                    if resources and len(resources) > 0:
                        resource_id = resources[0]  # First element is the ID string
                        logger.info(f"Found existing resource '{name}' with ID: {resource_id}")
                        return resource_id

                logger.error(f"Resource '{name}' exists but couldn't retrieve ID")
                return None

            response.raise_for_status()

            result = response.json()
            resource_id = result.get("_id")

            logger.info(f"Registered resource '{name}' with ID: {resource_id}")
            return resource_id

        except Exception as e:
            logger.error(f"Failed to register resource '{name}': {e}")
            return None

    def create_permission_ticket(
        self,
        pat: str,
        resource_id: str,
        resource_scopes: List[str]
    ) -> Optional[PermissionTicket]:
        """
        Create a permission ticket (Resource Server calls this when unauthorized access detected)

        Args:
            pat: Protection API Token
            resource_id: ID of the protected resource
            resource_scopes: Requested scopes

        Returns:
            PermissionTicket or None if failed
        """
        try:
            permission_data = [{
                "resource_id": resource_id,
                "resource_scopes": resource_scopes
            }]

            response = requests.post(
                self.get_permission_endpoint(),
                json=permission_data,
                headers={
                    "Authorization": f"Bearer {pat}",
                    "Content-Type": "application/json"
                },
                timeout=self.timeout
            )
            response.raise_for_status()

            result = response.json()
            ticket = result.get("ticket")

            if not ticket:
                logger.error("No ticket in response")
                return None

            # Tickets typically expire in 5 minutes
            expires_at = datetime.utcnow() + timedelta(minutes=5)

            logger.info(f"Created permission ticket for resource {resource_id}")
            return PermissionTicket(ticket=ticket, expires_at=expires_at)

        except Exception as e:
            logger.error(f"Failed to create permission ticket: {e}")
            return None

    # ========================================================================
    # Agent Operations (RPT - Requesting Party Token)
    # ========================================================================

    def exchange_ticket_for_rpt(
        self,
        ticket: str,
        agent_access_token: str
    ) -> Optional[RPT]:
        """
        Exchange permission ticket for RPT (Agent calls this)

        Args:
            ticket: Permission ticket from resource server
            agent_access_token: Agent's OAuth access token

        Returns:
            RPT or None if failed
        """
        try:
            data = {
                "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
                "ticket": ticket,
                "client_id": self.client_id,
            }

            if self.client_secret:
                data["client_secret"] = self.client_secret

            response = requests.post(
                self.get_token_endpoint(),
                data=data,
                headers={
                    "Authorization": f"Bearer {agent_access_token}",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                timeout=self.timeout
            )

            # Check for different response codes
            if response.status_code == 401:
                logger.error("Agent not authorized for requested resource")
                return None
            elif response.status_code == 403:
                logger.error("Access denied - insufficient permissions")
                return None

            response.raise_for_status()

            token_data = response.json()

            rpt = RPT(
                access_token=token_data["access_token"],
                token_type=token_data.get("token_type", "Bearer"),
                expires_in=token_data.get("expires_in", 300),
                issued_at=datetime.utcnow(),
                refresh_token=token_data.get("refresh_token"),
                permissions=token_data.get("permissions")
            )

            logger.info("Successfully exchanged ticket for RPT")
            return rpt

        except Exception as e:
            logger.error(f"Failed to exchange ticket for RPT: {e}")
            if hasattr(e, 'response') and e.response:
                logger.error(f"Response: {e.response.text}")
            return None

    def refresh_rpt(
        self,
        refresh_token: str
    ) -> Optional[RPT]:
        """
        Refresh an expired RPT

        Args:
            refresh_token: Refresh token from previous RPT

        Returns:
            New RPT or None if failed
        """
        try:
            data = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": self.client_id,
            }

            if self.client_secret:
                data["client_secret"] = self.client_secret

            response = requests.post(
                self.get_token_endpoint(),
                data=data,
                timeout=self.timeout
            )
            response.raise_for_status()

            token_data = response.json()

            rpt = RPT(
                access_token=token_data["access_token"],
                token_type=token_data.get("token_type", "Bearer"),
                expires_in=token_data.get("expires_in", 300),
                issued_at=datetime.utcnow(),
                refresh_token=token_data.get("refresh_token"),
                permissions=token_data.get("permissions")
            )

            logger.info("Successfully refreshed RPT")
            return rpt

        except Exception as e:
            logger.error(f"Failed to refresh RPT: {e}")
            return None

    def introspect_rpt(
        self,
        rpt: str,
        pat: str
    ) -> Optional[Dict[str, Any]]:
        """
        Introspect RPT to get detailed information

        Args:
            rpt: RPT access token
            pat: Protection API Token

        Returns:
            Token introspection data or None if failed
        """
        try:
            introspect_endpoint = f"{self.realm_url}/protocol/openid-connect/token/introspect"

            data = {
                "token": rpt,
                "client_id": self.client_id,
            }

            if self.client_secret:
                data["client_secret"] = self.client_secret

            response = requests.post(
                introspect_endpoint,
                data=data,
                headers={"Authorization": f"Bearer {pat}"},
                timeout=self.timeout
            )
            response.raise_for_status()

            return response.json()

        except Exception as e:
            logger.error(f"Failed to introspect RPT: {e}")
            return None
