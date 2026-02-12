"""
Keycloak Agent Authentication - OAuth 2.0 integration for agents

Provides:
- Agent registration with Keycloak
- Agent authentication
- Token management
- Scope assignment
"""

from typing import Optional, Dict, Any
from keycloak import KeycloakAdmin, KeycloakOpenIDConnection
import logging

from .base import BaseAgent, AgentToken

logger = logging.getLogger(__name__)


class KeycloakAgentAuth:
    """
    Manages agent authentication with Keycloak

    Integrates agents with Keycloak OAuth 2.0 server,
    handling registration, authentication, and token management.
    """

    def __init__(
        self,
        server_url: str = "http://localhost:8080",
        realm_name: str = "test-realm",
        admin_user: str = "admin",
        admin_password: str = "admin",
        client_id: str = "test-app",
        client_secret: Optional[str] = None,
    ):
        """
        Initialize Keycloak agent authentication

        Args:
            server_url: Keycloak server URL
            realm_name: Realm name in Keycloak
            admin_user: Admin username
            admin_password: Admin password
            client_id: Client ID for agent application
            client_secret: Client secret (if confidential client)
        """
        self.server_url = server_url
        self.realm_name = realm_name
        self.client_id = client_id
        self.client_secret = client_secret

        # Initialize Keycloak admin
        try:
            self.keycloak_admin = KeycloakAdmin(
                server_url=server_url,
                client_id="admin-cli",
                client_secret=None,
                realm_name="master",
                user_realm_name="master",
                username=admin_user,
                password=admin_password,
                verify=False,
            )
            logger.info(f"Connected to Keycloak at {server_url}")
        except Exception as e:
            logger.error(f"Failed to connect to Keycloak: {e}")
            raise

        # Initialize OpenID Connect for token operations
        self.oidc_client = KeycloakOpenIDConnection(
            server_url=server_url,
            realm_name=realm_name,
            client_id=client_id,
            client_secret=client_secret,
        )

    # ========================================================================
    # Agent Registration
    # ========================================================================

    def register_agent(
        self,
        agent: BaseAgent,
        password: str = "agent-password",
        email: Optional[str] = None,
    ) -> bool:
        """
        Register an agent as a Keycloak user

        Args:
            agent: The agent to register
            password: Password for the agent account
            email: Email address for the agent

        Returns:
            True if successful, False otherwise
        """
        try:
            # Switch to target realm
            self.keycloak_admin.realm_name = self.realm_name

            # Create user
            user_data = {
                "username": agent.agent_id,
                "firstName": agent.metadata.agent_name,
                "lastName": f"({agent.agent_type.value})",
                "email": email or f"{agent.agent_id}@agent.local",
                "enabled": True,
                "credentials": [
                    {
                        "type": "password",
                        "value": password,
                        "temporary": False,
                    }
                ],
                "attributes": {
                    "agent_type": agent.agent_type.value,
                    "agent_id": agent.agent_id,
                    "capabilities": ",".join([c.value for c in agent.capabilities]),
                },
            }

            # Register user
            response = self.keycloak_admin.create_user(user_data, exist_ok=False)
            logger.info(f"Registered agent {agent.agent_id} in Keycloak")
            return True

        except Exception as e:
            logger.error(f"Failed to register agent {agent.agent_id}: {e}")
            return False

    def unregister_agent(self, agent_id: str) -> bool:
        """
        Unregister an agent (delete Keycloak user)

        Args:
            agent_id: The agent ID to unregister

        Returns:
            True if successful, False otherwise
        """
        try:
            self.keycloak_admin.realm_name = self.realm_name
            user_id = self.keycloak_admin.get_user_id(agent_id)
            if user_id:
                self.keycloak_admin.delete_user(user_id)
                logger.info(f"Unregistered agent {agent_id}")
                return True
            else:
                logger.warning(f"Agent {agent_id} not found in Keycloak")
                return False
        except Exception as e:
            logger.error(f"Failed to unregister agent {agent_id}: {e}")
            return False

    # ========================================================================
    # Agent Authentication
    # ========================================================================

    def authenticate_agent(
        self,
        agent: BaseAgent,
        password: str = "agent-password",
    ) -> bool:
        """
        Authenticate an agent and set its token

        Args:
            agent: The agent to authenticate
            password: The agent's password

        Returns:
            True if successful, False otherwise
        """
        try:
            # Get token from Keycloak
            token_data = self.oidc_client.token(
                username=agent.agent_id,
                password=password,
            )

            # Create token object
            token = AgentToken(
                access_token=token_data["access_token"],
                token_type=token_data.get("token_type", "Bearer"),
                expires_in=token_data.get("expires_in", 3600),
                refresh_token=token_data.get("refresh_token"),
            )

            # Set token on agent
            agent.set_token(token)
            logger.info(f"Authenticated agent {agent.agent_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to authenticate agent {agent.agent_id}: {e}")
            return False

    def refresh_agent_token(self, agent: BaseAgent) -> bool:
        """
        Refresh an agent's access token

        Args:
            agent: The agent whose token to refresh

        Returns:
            True if successful, False otherwise
        """
        try:
            if not agent.token or not agent.token.refresh_token:
                logger.error(f"Agent {agent.agent_id} has no refresh token")
                return False

            # Refresh token
            token_data = self.oidc_client.token(
                grant_type="refresh_token",
                refresh_token=agent.token.refresh_token,
            )

            # Update token
            token = AgentToken(
                access_token=token_data["access_token"],
                token_type=token_data.get("token_type", "Bearer"),
                expires_in=token_data.get("expires_in", 3600),
                refresh_token=token_data.get("refresh_token"),
            )

            agent.set_token(token)
            logger.info(f"Refreshed token for agent {agent.agent_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to refresh token for agent {agent.agent_id}: {e}")
            return False

    # ========================================================================
    # Token Management
    # ========================================================================

    def validate_token(self, token: str) -> bool:
        """
        Validate a token with Keycloak

        Args:
            token: The access token to validate

        Returns:
            True if token is valid, False otherwise
        """
        try:
            self.oidc_client.introspect(token)
            return True
        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            return False

    def get_agent_token_info(self, agent: BaseAgent) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about an agent's token

        Args:
            agent: The agent

        Returns:
            Token introspection data, or None if error
        """
        try:
            if not agent.token:
                return None

            token_info = self.oidc_client.introspect(agent.token.access_token)
            return token_info
        except Exception as e:
            logger.error(f"Failed to get token info for agent {agent.agent_id}: {e}")
            return None

    # ========================================================================
    # Scope Management
    # ========================================================================

    def grant_scope_to_agent(
        self,
        agent: BaseAgent,
        scope: str,
    ) -> bool:
        """
        Grant a scope to an agent

        Args:
            agent: The agent
            scope: The scope to grant

        Returns:
            True if successful, False otherwise
        """
        try:
            agent.add_scope(scope)
            logger.info(f"Granted scope '{scope}' to agent {agent.agent_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to grant scope to agent {agent.agent_id}: {e}")
            return False

    def revoke_scope_from_agent(
        self,
        agent: BaseAgent,
        scope: str,
    ) -> bool:
        """
        Revoke a scope from an agent

        Args:
            agent: The agent
            scope: The scope to revoke

        Returns:
            True if successful, False otherwise
        """
        try:
            # In a real implementation, this would interact with
            # Keycloak's scope management. For now, just remove locally.
            if scope in agent.get_scopes():
                agent._scopes.remove(scope)
                logger.info(f"Revoked scope '{scope}' from agent {agent.agent_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to revoke scope from agent {agent.agent_id}: {e}")
            return False

    # ========================================================================
    # Agent Information
    # ========================================================================

    def get_agent_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a registered agent from Keycloak

        Args:
            agent_id: The agent ID

        Returns:
            Agent information from Keycloak, or None if not found
        """
        try:
            self.keycloak_admin.realm_name = self.realm_name
            user_data = self.keycloak_admin.get_user_by_username(agent_id)
            return user_data
        except Exception as e:
            logger.error(f"Failed to get agent info for {agent_id}: {e}")
            return None

    def list_registered_agents(self) -> list:
        """
        List all agents registered in Keycloak

        Returns:
            List of agent usernames
        """
        try:
            self.keycloak_admin.realm_name = self.realm_name
            users = self.keycloak_admin.get_users()
            # Filter for agents (those with agent_type attribute)
            agents = [
                u["username"]
                for u in users
                if u.get("attributes", {}).get("agent_type")
            ]
            return agents
        except Exception as e:
            logger.error(f"Failed to list agents: {e}")
            return []

    # ========================================================================
    # Connection Status
    # ========================================================================

    def is_connected(self) -> bool:
        """Check if connected to Keycloak"""
        try:
            self.keycloak_admin.realm_name = self.realm_name
            self.keycloak_admin.get_realms()
            return True
        except Exception:
            return False

    def __repr__(self) -> str:
        """String representation"""
        return (
            f"KeycloakAgentAuth("
            f"server={self.server_url}, "
            f"realm={self.realm_name}"
            f")"
        )
