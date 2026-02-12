"""
UMA-Protected Resource Server

Production-ready FastAPI resource server that:
- Registers resources with Keycloak UMA
- Issues permission tickets on unauthorized access
- Validates RPT tokens
- Protects resources with fine-grained permissions

This implements the Resource Server role in UMA 2.0.
"""

from fastapi import FastAPI, Depends, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from typing import Optional, List, Dict, Any
import logging
import jwt
from jwt import PyJWKClient
from datetime import datetime, timedelta
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.uma_client import UMAClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="UMA Protected Resource Server",
    description="Protected resources using UMA 2.0",
    version="1.0.0"
)

# Configuration
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
REALM = os.getenv("KEYCLOAK_REALM", "test-realm")
CLIENT_ID = os.getenv("CLIENT_ID", "resource-server")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", None)

# Initialize UMA client
uma_client = UMAClient(
    keycloak_url=KEYCLOAK_URL,
    realm=REALM,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET
)

# Resource registry (in production, this would be in database)
RESOURCES = {}

# Protection API Token cache
_pat_cache = {"token": None, "expires_at": None}


def get_pat() -> str:
    """Get cached Protection API Token or request new one"""
    now = datetime.utcnow()

    if _pat_cache["token"] and _pat_cache["expires_at"]:
        if now < _pat_cache["expires_at"]:
            return _pat_cache["token"]

    # Request new PAT
    pat = uma_client.get_protection_api_token()
    if not pat:
        raise HTTPException(status_code=500, detail="Failed to get Protection API Token")

    _pat_cache["token"] = pat
    _pat_cache["expires_at"] = now + timedelta(seconds=300)  # Cache for 5 min

    return pat


def get_jwks_client():
    """Get JWKS client for token validation"""
    jwks_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"
    return PyJWKClient(jwks_url)


def validate_rpt(token: str) -> Dict[str, Any]:
    """
    Validate RPT token

    Args:
        token: RPT access token

    Returns:
        Decoded token payload

    Raises:
        HTTPException: If token is invalid
    """
    try:
        jwks_client = get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        # Decode and validate
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=CLIENT_ID,  # RPT audience matches the client ID
            options={"verify_exp": True}
        )

        return payload

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        raise HTTPException(status_code=401, detail="Token validation failed")


def check_permission(token_payload: Dict[str, Any], resource: str, scope: str) -> bool:
    """
    Check if token has required permission

    Args:
        token_payload: Decoded RPT payload
        resource: Resource name
        scope: Required scope

    Returns:
        True if permission granted, False otherwise
    """
    authorization = token_payload.get("authorization", {})
    permissions = authorization.get("permissions", [])

    for perm in permissions:
        if perm.get("rsname") == resource:
            if scope in perm.get("scopes", []):
                return True

    return False


def require_rpt_dependency(resource: str, scope: str):
    """
    Factory to create RPT requirement dependency for specific resource/scope
    """
    async def dependency(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        """
        Dependency to require valid RPT

        Returns:
            Token payload if valid

        Raises:
            HTTPException: If unauthorized (with permission ticket in WWW-Authenticate)
        """
        return await _require_rpt_impl(authorization, resource, scope)
    return dependency

async def _require_rpt_impl(
    authorization: Optional[str],
    resource: str,
    scope: str
) -> Dict[str, Any]:
    """
    Internal implementation of RPT requirement logic
    """
    if not authorization or not authorization.startswith("Bearer "):
        # No token provided - create permission ticket
        pat = get_pat()
        resource_id = RESOURCES.get(resource)

        if not resource_id:
            raise HTTPException(
                status_code=404,
                detail=f"Resource '{resource}' not found"
            )

        ticket = uma_client.create_permission_ticket(
            pat=pat,
            resource_id=resource_id,
            resource_scopes=[scope] if scope else []
        )

        if not ticket:
            raise HTTPException(
                status_code=500,
                detail="Failed to create permission ticket"
            )

        # Return 401 with ticket in WWW-Authenticate header
        raise HTTPException(
            status_code=401,
            detail="UMA authorization required",
            headers={
                "WWW-Authenticate": f'UMA realm="{REALM}", as_uri="{KEYCLOAK_URL}/realms/{REALM}", ticket="{ticket.ticket}"'
            }
        )

    # Extract token
    token = authorization.replace("Bearer ", "")

    # Validate token
    payload = validate_rpt(token)

    # Check permission
    if resource and scope:
        if not check_permission(payload, resource, scope):
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions for {resource}:{scope}"
            )

    return payload


# ========================================================================
# Startup: Register Resources
# ========================================================================

@app.on_event("startup")
async def register_resources():
    """Register protected resources with Keycloak on startup"""
    logger.info("Registering resources with Keycloak...")

    pat = get_pat()

    # Define resources
    resources_to_register = [
        {
            "name": "documents",
            "scopes": ["read", "write", "delete"],
            "uri": "/api/documents"
        },
        {
            "name": "calendar",
            "scopes": ["read", "write"],
            "uri": "/api/calendar"
        },
        {
            "name": "database",
            "scopes": ["read", "write", "execute"],
            "uri": "/api/database"
        }
    ]

    for resource in resources_to_register:
        resource_id = uma_client.register_resource(
            pat=pat,
            name=resource["name"],
            resource_scopes=resource["scopes"],
            uri=resource.get("uri")
        )

        if resource_id:
            RESOURCES[resource["name"]] = resource_id
            logger.info(f"✓ Registered '{resource['name']}' with ID: {resource_id}")
        else:
            logger.error(f"✗ Failed to register '{resource['name']}'")

    logger.info(f"Resource registration complete. {len(RESOURCES)} resources registered.")


# ========================================================================
# API Endpoints
# ========================================================================

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": "UMA Protected Resource Server",
        "status": "running",
        "registered_resources": list(RESOURCES.keys())
    }


@app.get("/api/documents")
async def list_documents(
    token_payload: Dict = Depends(require_rpt_dependency("documents", "read"))
):
    """
    List documents (requires 'read' scope on 'documents' resource)

    Protected by UMA 2.0 - requires valid RPT with appropriate permissions
    """
    agent_id = token_payload.get("sub", "unknown")

    logger.info(f"Agent {agent_id} accessed documents list")

    return {
        "documents": [
            {"id": "doc1", "name": "Project Plan.pdf", "size": "2.5 MB"},
            {"id": "doc2", "name": "Requirements.docx", "size": "1.2 MB"},
            {"id": "doc3", "name": "Architecture.pptx", "size": "4.8 MB"}
        ],
        "accessed_by": agent_id,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/api/documents")
async def create_document(
    document: Dict[str, Any],
    token_payload: Dict = Depends(require_rpt_dependency("documents", "write"))
):
    """
    Create document (requires 'write' scope on 'documents' resource)

    Protected by UMA 2.0
    """
    agent_id = token_payload.get("sub", "unknown")

    logger.info(f"Agent {agent_id} created document: {document.get('name')}")

    return {
        "id": "doc4",
        "name": document.get("name", "Untitled"),
        "created_by": agent_id,
        "created_at": datetime.utcnow().isoformat(),
        "status": "created"
    }


@app.get("/api/calendar")
async def view_calendar(
    token_payload: Dict = Depends(require_rpt_dependency("calendar", "read"))
):
    """
    View calendar (requires 'read' scope on 'calendar' resource)

    Protected by UMA 2.0
    """
    agent_id = token_payload.get("sub", "unknown")

    logger.info(f"Agent {agent_id} accessed calendar")

    return {
        "events": [
            {
                "id": "evt1",
                "title": "Team Meeting",
                "start": "2025-12-06T10:00:00Z",
                "duration": "1h"
            },
            {
                "id": "evt2",
                "title": "Project Review",
                "start": "2025-12-06T14:00:00Z",
                "duration": "2h"
            }
        ],
        "accessed_by": agent_id,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/api/calendar/events")
async def create_event(
    event: Dict[str, Any],
    token_payload: Dict = Depends(require_rpt_dependency("calendar", "write"))
):
    """
    Create calendar event (requires 'write' scope on 'calendar' resource)

    Protected by UMA 2.0
    """
    agent_id = token_payload.get("sub", "unknown")

    logger.info(f"Agent {agent_id} created event: {event.get('title')}")

    return {
        "id": "evt3",
        "title": event.get("title", "Untitled Event"),
        "created_by": agent_id,
        "created_at": datetime.utcnow().isoformat(),
        "status": "scheduled"
    }


@app.get("/api/database")
async def access_database(
    token_payload: Dict = Depends(require_rpt_dependency("database", "read"))
):
    """
    Access database info (requires 'read' scope on 'database' resource)

    Protected by UMA 2.0
    """
    agent_id = token_payload.get("sub", "unknown")

    logger.info(f"Agent {agent_id} accessed database info")

    return {
        "databases": [
            {
                "id": "txn-db-001",
                "name": "Transactions Database",
                "description": "Financial transaction records",
                "record_count": 15234,
                "status": "active"
            },
            {
                "id": "audit-db-002",
                "name": "Audit Log Database",
                "description": "Compliance audit trail",
                "record_count": 98234,
                "status": "active"
            }
        ],
        "accessed_by": agent_id,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/database/query")
async def execute_query(
    query: str,
    token_payload: Dict = Depends(require_rpt_dependency("database", "execute"))
):
    """
    Execute database query (requires 'execute' scope on 'database' resource)

    Protected by UMA 2.0
    """
    agent_id = token_payload.get("sub", "unknown")

    logger.info(f"Agent {agent_id} executed query: {query[:50]}...")

    return {
        "query": query,
        "results": [
            {"id": 1, "name": "Alice", "role": "Admin"},
            {"id": 2, "name": "Bob", "role": "User"}
        ],
        "executed_by": agent_id,
        "timestamp": datetime.utcnow().isoformat()
    }


if __name__ == "__main__":
    import uvicorn

    logger.info("Starting UMA Protected Resource Server...")
    logger.info(f"Keycloak: {KEYCLOAK_URL}")
    logger.info(f"Realm: {REALM}")
    logger.info(f"Client ID: {CLIENT_ID}")

    uvicorn.run(app, host="0.0.0.0", port=5000, log_level="info")
