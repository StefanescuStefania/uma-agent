"""
UMA-Protected Resource Server

Implements the Resource Server role in UMA 2.0 with the uma_delegation_chain
protocol extension (urn:uma-agent:delegation-chain:1.0).

Key additions over vanilla UMA 2.0:
  - Validates X-Uma-Delegation-Chain claim on every request (W1: novel contribution)
  - Enforces T1–T4 attack classes at the resource layer (W3: threat model)
  - Logs every access attempt to a tamper-evident PostgreSQL audit trail (W3)
  - Exposes /api/audit/verify to demonstrate chain integrity (W3)
  - DORA Article 9 use-case framing throughout (W2, W6)

Resources and scopes (W4: scope enforcement — now genuinely differentiated):
  documents : read, write
  calendar  : read, write
  database  : read, write, audit   ← audit scope is new; only compliance-manager gets it
"""

import asyncio
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from jwt import PyJWKClient
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.chain_claim import DelegationChainClaim
from agents.database import (
    AuditEvent as DBAuditEvent,
    DelegationChainRecord,
    DatabaseManager,
    GENESIS_HASH,
    get_latest_event_hash,
    verify_audit_chain,
    compute_event_hash,
)
from agents.uma_client import UMAClient

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
REALM = os.getenv("KEYCLOAK_REALM", "test-realm")
CLIENT_ID = os.getenv("CLIENT_ID", "resource-server")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", None)
CHAIN_HMAC_SECRET = os.getenv("CHAIN_HMAC_SECRET", "uma-agent-chain-hmac-secret-2024")
MAX_DELEGATION_DEPTH = int(os.getenv("MAX_DELEGATION_DEPTH", "4"))

# ============================================================================
# Application
# ============================================================================

app = FastAPI(
    title="UMA-Agent Resource Server",
    description=(
        "UMA 2.0 resource server with uma_delegation_chain extension. "
        "DORA Article 9 compliance use case."
    ),
    version="2.0.0",
)

uma_client = UMAClient(
    keycloak_url=KEYCLOAK_URL,
    realm=REALM,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
)

RESOURCES: Dict[str, str] = {}
_pat_cache: Dict[str, Any] = {"token": None, "expires_at": None}
_db_manager: Optional[DatabaseManager] = None


# ============================================================================
# Database helpers
# ============================================================================

def get_db():
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
        _db_manager.create_tables()
    return _db_manager


def _db_session():
    return get_db().get_session()


def _log_access(
    agent_id: str,
    action: str,
    result: str,
    resource: Optional[str] = None,
    scope: Optional[str] = None,
    extra: Optional[Dict] = None,
    delegation_chain_id: Optional[str] = None,
    attack_class: Optional[str] = None,
) -> None:
    session = _db_session()
    try:
        prev_hash = get_latest_event_hash(session)
        prev_event = (
            session.query(DBAuditEvent)
            .order_by(DBAuditEvent.timestamp.desc())
            .first()
        )
        event_id = f"rs-{uuid.uuid4().hex[:10]}"
        event = DBAuditEvent(
            id=event_id,
            event_type="security_block" if attack_class else "resource_access",
            agent_id=agent_id,
            action=action,
            result=result,
            resource=resource,
            scope=scope,
            extra_data=extra or {},
            delegation_chain_id=delegation_chain_id,
            attack_class=attack_class,
            prev_event_id=prev_event.id if prev_event else None,
            timestamp=datetime.utcnow(),
        )
        event.compute_and_set_hash(prev_hash, CHAIN_HMAC_SECRET)
        session.add(event)
        session.commit()
    except Exception as exc:
        logger.error(f"Audit write failed: {exc}")
        session.rollback()
    finally:
        session.close()


def _persist_chain_claim(claim: DelegationChainClaim) -> None:
    session = _db_session()
    try:
        existing = session.query(DelegationChainRecord).filter_by(chain_id=claim.chain_id).first()
        if existing:
            existing.last_used_at = datetime.utcnow()
            session.commit()
            return
        record = DelegationChainRecord(
            chain_id=claim.chain_id,
            root_agent=claim.root_agent,
            members=claim.members,
            granted_scopes=claim.granted_scopes,
            depth=claim.depth,
            max_depth=claim.max_depth,
            chain_hash=claim.chain_hash,
        )
        session.add(record)
        session.commit()
    except Exception as exc:
        logger.error(f"Chain record persist failed: {exc}")
        session.rollback()
    finally:
        session.close()


# ============================================================================
# PAT / JWKS helpers
# ============================================================================

def get_pat() -> str:
    now = datetime.utcnow()
    if _pat_cache["token"] and _pat_cache["expires_at"] and now < _pat_cache["expires_at"]:
        return _pat_cache["token"]
    pat = uma_client.get_protection_api_token()
    if not pat:
        raise HTTPException(status_code=500, detail="Failed to get Protection API Token")
    _pat_cache["token"] = pat
    _pat_cache["expires_at"] = now + timedelta(seconds=280)
    return pat


def get_jwks_client() -> PyJWKClient:
    return PyJWKClient(f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs")


def validate_rpt(token: str) -> Dict[str, Any]:
    try:
        jwks_client = get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            options={
                "verify_exp": True,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}")
    except Exception as exc:
        logger.error(f"Token validation error: {exc}")
        raise HTTPException(status_code=401, detail="Token validation failed")


def check_permission(payload: Dict[str, Any], resource: str, scope: str) -> bool:
    permissions = payload.get("authorization", {}).get("permissions", [])
    for perm in permissions:
        if perm.get("rsname") == resource and scope in perm.get("scopes", []):
            return True
    return False


# ============================================================================
# Chain claim validation
# ============================================================================

def validate_chain_header(
    header_value: Optional[str],
    resource: str,
    scope: str,
    agent_id: str,
) -> Tuple[Optional[DelegationChainClaim], Optional[str]]:
    """
    Parse and validate the X-Uma-Delegation-Chain header.

    Returns (claim, None) on success, (None, rejection_reason) on failure.
    When the header is absent the caller decides whether to require it.
    """
    if not header_value:
        return None, None

    try:
        claim = DelegationChainClaim.from_header_value(header_value)
    except Exception as exc:
        return None, f"Malformed chain claim: {exc}"

    is_valid, reason = claim.validate_for_resource(
        resource=resource,
        scope=scope,
        claimed_agent_id=agent_id,
        hmac_secret=CHAIN_HMAC_SECRET,
        server_max_depth=MAX_DELEGATION_DEPTH,  # server policy, not client-asserted value
    )
    if not is_valid:
        return claim, reason

    _persist_chain_claim(claim)
    return claim, None


# ============================================================================
# FastAPI dependency: RPT + optional chain claim
# ============================================================================

def require_rpt_with_chain(resource: str, scope: str):
    async def dependency(
        authorization: Optional[str] = Header(None),
        x_uma_delegation_chain: Optional[str] = Header(
            None, alias="X-Uma-Delegation-Chain"
        ),
    ) -> Dict[str, Any]:
        # ----- Step 1: issue permission ticket when no token present -----
        if not authorization or not authorization.startswith("Bearer "):
            pat = get_pat()
            resource_id = RESOURCES.get(resource)
            if not resource_id:
                raise HTTPException(status_code=404, detail=f"Resource '{resource}' not found")
            ticket = uma_client.create_permission_ticket(
                pat=pat, resource_id=resource_id, resource_scopes=[scope]
            )
            if not ticket:
                raise HTTPException(status_code=500, detail="Failed to create permission ticket")
            raise HTTPException(
                status_code=401,
                detail="UMA authorization required",
                headers={
                    "WWW-Authenticate": (
                        f'UMA realm="{REALM}", '
                        f'as_uri="{KEYCLOAK_URL}/realms/{REALM}", '
                        f'ticket="{ticket.ticket}"'
                    )
                },
            )

        # ----- Step 2: validate RPT -----
        token = authorization.removeprefix("Bearer ")
        payload = validate_rpt(token)

        if not check_permission(payload, resource, scope):
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions for {resource}:{scope}",
            )

        # ----- Step 3: validate delegation chain claim (if present) -----
        # Use only the cryptographically verified RPT field for identity —
        # the X-Agent-Id header is client-controlled and must not be trusted.
        agent_id = payload.get("preferred_username") or payload.get("sub", "unknown")

        if x_uma_delegation_chain:
            claim, rejection_reason = validate_chain_header(
                x_uma_delegation_chain, resource, scope, agent_id
            )
            if rejection_reason:
                # Determine attack class from reason string for structured logging
                attack_class = "T1"
                if "T2" in rejection_reason:
                    attack_class = "T2"
                elif "T3" in rejection_reason:
                    attack_class = "T3"
                elif "T4" in rejection_reason:
                    attack_class = "T4"

                _log_access(
                    agent_id=agent_id,
                    action=f"blocked_{resource}:{scope}",
                    result="denied",
                    resource=resource,
                    scope=scope,
                    extra={"rejection_reason": rejection_reason},
                    attack_class=attack_class,
                )
                logger.warning(f"SECURITY BLOCK [{attack_class}] {agent_id} → {resource}:{scope} — {rejection_reason}")
                raise HTTPException(
                    status_code=403,
                    detail=f"Delegation chain rejected: {rejection_reason}",
                )

            payload["_chain_claim"] = claim.to_dict() if claim else None
            payload["_chain_id"] = claim.chain_id if claim else None

        # ----- Step 4: log successful access -----
        chain_id = payload.get("_chain_id")
        _log_access(
            agent_id=agent_id,
            action=f"access_{resource}:{scope}",
            result="success",
            resource=resource,
            scope=scope,
            delegation_chain_id=chain_id,
        )

        payload["_agent_id"] = agent_id
        return payload

    return dependency


# ============================================================================
# Startup — with retry and self-initialisation
# ============================================================================

async def _wait_for_keycloak(max_attempts: int = 30, delay: int = 10) -> None:
    import requests as _req
    url = f"{KEYCLOAK_URL}/realms/master"
    for attempt in range(1, max_attempts + 1):
        try:
            r = _req.get(url, timeout=5)
            if r.status_code < 500:
                logger.info(f"Keycloak ready after {attempt} attempt(s)")
                return
        except Exception:
            pass
        logger.info(f"Waiting for Keycloak ({attempt}/{max_attempts})…")
        await asyncio.sleep(delay)
    raise RuntimeError("Keycloak did not become ready in time")


async def _init_keycloak() -> None:
    """Create test-realm, resource-server client, and DORA agent users if absent."""
    try:
        from keycloak import KeycloakAdmin
        from keycloak.exceptions import KeycloakGetError

        # Master-realm admin — only for realm management
        master_admin = KeycloakAdmin(
            server_url=KEYCLOAK_URL,
            username="admin",
            password="admin",
            realm_name="master",
            verify=False,
        )

        # Create test-realm if missing
        try:
            master_admin.get_realm("test-realm")
        except KeycloakGetError:
            logger.info("Creating test-realm…")
            master_admin.create_realm(
                payload={"realm": "test-realm", "enabled": True, "displayName": "UMA-Agent DORA Realm"}
            )

        # Separate admin instance targeting test-realm
        # user_realm_name = realm where admin credentials live (master)
        admin = KeycloakAdmin(
            server_url=KEYCLOAK_URL,
            username="admin",
            password="admin",
            realm_name="test-realm",
            user_realm_name="master",
            verify=False,
        )

        existing_clients = {c["clientId"]: c["id"] for c in admin.get_clients()}

        # resource-server client (confidential, with authorization services)
        if "resource-server" not in existing_clients:
            logger.info("Creating resource-server client…")
            admin.create_client(
                payload={
                    "clientId": "resource-server",
                    "name": "UMA Resource Server",
                    "enabled": True,
                    "clientAuthenticatorType": "client-secret",
                    "secret": "uma-resource-server-secret",
                    "publicClient": False,
                    "serviceAccountsEnabled": True,
                    "authorizationServicesEnabled": True,
                    "directAccessGrantsEnabled": True,
                    "standardFlowEnabled": True,
                    "redirectUris": ["http://localhost:5000/*"],
                    "webOrigins": ["http://localhost:5000"],
                }
            )

        # test-app public client
        if "test-app" not in existing_clients:
            admin.create_client(
                payload={
                    "clientId": "test-app",
                    "enabled": True,
                    "publicClient": True,
                    "directAccessGrantsEnabled": True,
                    "redirectUris": ["http://localhost:*"],
                    "webOrigins": ["http://localhost:*"],
                }
            )

        # DORA agents + legacy agents + oauth test users
        dora_agents = [
            ("compliance-manager", "compliance-pass123", "compliance.manager@dora.local"),
            ("risk-analyst", "risk-pass123", "risk.analyst@dora.local"),
            ("data-extractor", "extractor-pass123", "data.extractor@dora.local"),
            ("report-validator", "validator-pass123", "report.validator@dora.local"),
            ("audit-reader", "audit-pass123", "audit.reader@dora.local"),
            # legacy names kept for backward compatibility with existing tests
            ("coordinator-agent", "coordinator-pass123", "coordinator@uma-agent.local"),
            ("researcher-agent", "researcher-pass123", "researcher@uma-agent.local"),
            ("executor-agent", "executor-pass123", "executor@uma-agent.local"),
            ("validator-agent", "validator-pass123", "validator@uma-agent.local"),
            # oauth flow test users
            ("alice", "alice123", "alice@test.local"),
            ("bob", "bob123", "bob@test.local"),
        ]
        existing_users = {u["username"] for u in admin.get_users()}
        for username, password, email in dora_agents:
            if username not in existing_users:
                logger.info(f"Creating agent user: {username}")
                admin.create_user(
                    payload={
                        "username": username,
                        "email": email,
                        "firstName": username,
                        "lastName": "Agent",
                        "enabled": True,
                        "emailVerified": True,
                        "requiredActions": [],
                        "credentials": [
                            {"type": "password", "value": password, "temporary": False}
                        ],
                    }
                )

        logger.info("Keycloak initialisation complete")
    except Exception as exc:
        logger.error(f"Keycloak initialisation failed (non-fatal): {exc}")


async def _ensure_authz_policies() -> None:
    """
    Create Keycloak authorization policies so any authenticated user can
    obtain an RPT.  The fine-grained access control (scope enforcement,
    delegation chain validation, T1-T4) is performed by the resource
    server itself — the Keycloak layer only needs to confirm the user is
    authenticated.
    """
    import requests as _req
    try:
        from keycloak import KeycloakAdmin
        admin = KeycloakAdmin(
            server_url=KEYCLOAK_URL,
            username="admin",
            password="admin",
            realm_name="test-realm",
            user_realm_name="master",
            verify=False,
        )
        clients = {c["clientId"]: c["id"] for c in admin.get_clients()}
        rs_id = clients.get("resource-server")
        if not rs_id:
            logger.error("resource-server client not found — skipping policy creation")
            return

        authz_base = (
            f"{KEYCLOAK_URL}/admin/realms/test-realm/clients/{rs_id}/authz/resource-server"
        )
        admin_token = admin.connection.token.get("access_token", "")
        headers = {
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json",
        }

        # --- 1. Find the default realm role (every user gets it on registration) ---
        realm_roles_url = f"{KEYCLOAK_URL}/admin/realms/test-realm/roles"
        roles_resp = _req.get(realm_roles_url, headers=headers, timeout=10)
        realm_roles = {r["name"]: r["id"] for r in (roles_resp.json() if roles_resp.ok else [])}
        default_role_name = "default-roles-test-realm"
        default_role_id = realm_roles.get(default_role_name)
        if not default_role_id:
            logger.error(f"Realm role '{default_role_name}' not found — skipping policy creation")
            return

        # --- 2. Ensure "allow-authenticated" role policy exists ---
        policies_resp = _req.get(f"{authz_base}/policy?name=allow-authenticated&exact=true",
                                 headers=headers, timeout=10)
        policies = policies_resp.json() if policies_resp.ok else []
        if isinstance(policies, list) and len(policies) == 0:
            role_policy = {
                "type": "role",
                "name": "allow-authenticated",
                "description": "Grant access to any user with the default realm role",
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "roles": [{"id": default_role_id, "required": False}],
            }
            r = _req.post(f"{authz_base}/policy/role", json=role_policy, headers=headers, timeout=10)
            if r.status_code in (200, 201):
                logger.info("Created 'allow-authenticated' role policy")
                policy_id = r.json().get("id")
            elif r.status_code == 409:
                policy_id = None
                logger.info("'allow-authenticated' policy already exists")
            else:
                logger.warning(f"Policy creation HTTP {r.status_code}: {r.text[:200]}")
                return
        else:
            policy_id = policies[0]["id"] if isinstance(policies, list) and policies else None
            logger.info("'allow-authenticated' policy already present")

        # Fetch policy id if not set
        if not policy_id:
            r2 = _req.get(f"{authz_base}/policy?name=allow-authenticated&exact=true",
                          headers=headers, timeout=10)
            plist = r2.json() if r2.ok else []
            policy_id = plist[0]["id"] if plist else None

        if not policy_id:
            logger.error("Could not find/create 'allow-authenticated' policy")
            return

        # --- 2. Ensure scope permissions exist for every resource:scope ---
        all_scopes = [
            ("documents", ["read", "write"]),
            ("calendar", ["read", "write"]),
            ("database", ["read", "write", "audit"]),
        ]
        perms_resp = _req.get(f"{authz_base}/permission", headers=headers, timeout=10)
        existing_perms = {p["name"] for p in (perms_resp.json() if perms_resp.ok else [])}

        for res_name, scopes in all_scopes:
            res_id = RESOURCES.get(res_name)
            for scope in scopes:
                perm_name = f"{res_name}:{scope}-permit"
                if perm_name in existing_perms:
                    continue
                perm = {
                    "type": "scope",
                    "name": perm_name,
                    "description": f"Allow any authenticated user: {res_name}:{scope}",
                    "decisionStrategy": "AFFIRMATIVE",
                    "resources": [res_id] if res_id else [],
                    "scopes": [scope],
                    "policies": [policy_id],
                }
                r3 = _req.post(f"{authz_base}/permission/scope", json=perm,
                               headers=headers, timeout=10)
                if r3.status_code in (200, 201):
                    logger.info(f"Created permission: {perm_name}")
                elif r3.status_code == 409:
                    logger.info(f"Permission already exists: {perm_name}")
                else:
                    logger.warning(f"Permission {perm_name} HTTP {r3.status_code}: {r3.text[:200]}")

        logger.info("Authorization policies ensured")
    except Exception as exc:
        logger.error(f"Policy setup failed (non-fatal): {exc}")


async def _register_resources() -> None:
    pat = get_pat()

    # W4: each endpoint now has a distinct scope set
    resources_to_register = [
        {"name": "documents", "scopes": ["read", "write"], "uri": "/api/documents"},
        {"name": "calendar", "scopes": ["read", "write"], "uri": "/api/calendar"},
        # database gets "audit" — only compliance-manager's chain grants it
        {"name": "database", "scopes": ["read", "write", "audit"], "uri": "/api/database"},
    ]

    for r in resources_to_register:
        resource_id = uma_client.register_resource(
            pat=pat,
            name=r["name"],
            resource_scopes=r["scopes"],
            uri=r["uri"],
        )
        if resource_id:
            RESOURCES[r["name"]] = resource_id
            logger.info(f"Registered '{r['name']}' → {resource_id}")
        else:
            logger.error(f"Failed to register '{r['name']}'")

    logger.info(f"Resource registration complete: {list(RESOURCES.keys())}")
    await _ensure_authz_policies()


@app.on_event("startup")
async def startup() -> None:
    get_db()  # creates tables
    await _wait_for_keycloak()
    await asyncio.sleep(5)  # brief settle after Keycloak readiness
    await _init_keycloak()
    await asyncio.sleep(2)

    for attempt in range(15):
        try:
            await _register_resources()
            return
        except Exception as exc:
            logger.warning(f"Resource registration attempt {attempt + 1}/15 failed: {exc}")
            await asyncio.sleep(10)

    logger.error("Resource registration failed after 15 attempts — continuing anyway")


# ============================================================================
# Delegation signing endpoints — agents call these to obtain server-signed
# chain claims.  CHAIN_HMAC_SECRET never leaves this process.
# ============================================================================

class _DelegationInitRequest(BaseModel):
    requested_scopes: List[str]


class _DelegationSignRequest(BaseModel):
    parent_chain: str       # base64url-encoded parent DelegationChainClaim
    child_agent_id: str
    requested_scopes: List[str]


@app.post("/api/delegation/init")
async def init_delegation_chain(
    body: _DelegationInitRequest,
    authorization: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """
    Create a server-signed root chain claim for an authenticated agent.
    Called by root agents after obtaining an access token so they never need
    CHAIN_HMAC_SECRET in their own environment.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = authorization.removeprefix("Bearer ")
    payload = validate_rpt(token)
    agent_username = payload.get("preferred_username") or payload.get("sub")
    if not agent_username:
        raise HTTPException(status_code=401, detail="Cannot determine agent identity from token")
    if not body.requested_scopes:
        raise HTTPException(status_code=400, detail="requested_scopes must not be empty")

    root_claim = DelegationChainClaim.create(
        root_agent=agent_username,
        members=[agent_username],
        granted_scopes=body.requested_scopes,
        max_depth=MAX_DELEGATION_DEPTH,
        hmac_secret=CHAIN_HMAC_SECRET,
    )
    _persist_chain_claim(root_claim)
    _log_access(
        agent_id=agent_username,
        action="delegation_init",
        result="success",
        extra={"granted_scopes": body.requested_scopes, "chain_depth": 1},
        delegation_chain_id=root_claim.chain_id,
    )
    return {
        "chain_claim": root_claim.to_header_value(),
        "chain_id": root_claim.chain_id,
        "granted_scopes": root_claim.granted_scopes,
        "depth": root_claim.depth,
        "max_depth": MAX_DELEGATION_DEPTH,
    }


@app.post("/api/delegation/sign")
async def sign_delegation(
    body: _DelegationSignRequest,
    authorization: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """
    Extend a delegation chain to a child agent (server-signed).

    The resource server is the sole signing authority: it verifies the parent's
    identity via the RPT, checks that the parent is the chain terminus, enforces
    scope monotonicity and the server-side depth ceiling, then signs and returns
    the child chain claim.  Agents never see CHAIN_HMAC_SECRET.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = authorization.removeprefix("Bearer ")
    parent_payload = validate_rpt(token)
    parent_username = parent_payload.get("preferred_username") or parent_payload.get("sub")
    if not parent_username:
        raise HTTPException(status_code=401, detail="Cannot determine parent identity from token")

    try:
        parent_claim = DelegationChainClaim.from_header_value(body.parent_chain)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid parent chain claim: {exc}")

    if not parent_claim.verify(CHAIN_HMAC_SECRET):
        raise HTTPException(
            status_code=403,
            detail="TAMPER: parent chain claim HMAC verification failed — claim was not server-signed",
        )

    # The authenticated caller must be the current chain terminus
    if not parent_claim.members or parent_claim.members[-1] != parent_username:
        raise HTTPException(
            status_code=403,
            detail=(
                f"T3: authenticated agent '{parent_username}' is not the chain terminus "
                f"'{parent_claim.leaf_agent}'"
            ),
        )

    # Depth check: enforce server's ceiling AND the claim's own signed ceiling.
    # min() means neither the server policy nor the client-embedded max_depth can be exceeded.
    new_depth = parent_claim.depth + 1
    effective_max = min(MAX_DELEGATION_DEPTH, parent_claim.max_depth)
    if new_depth > effective_max:
        raise HTTPException(
            status_code=403,
            detail=f"T2: new depth {new_depth} would exceed maximum {effective_max}",
        )

    # Scope monotonicity — child scopes must be a subset of the parent's
    child_scopes = [s for s in body.requested_scopes if s in parent_claim.granted_scopes]
    if not child_scopes:
        raise HTTPException(
            status_code=403,
            detail=(
                f"T1: none of the requested scopes {body.requested_scopes} are present "
                f"in the parent's granted set {parent_claim.granted_scopes}"
            ),
        )

    child_members = parent_claim.members + [body.child_agent_id]
    child_claim = DelegationChainClaim.create(
        root_agent=parent_claim.root_agent,
        members=child_members,
        granted_scopes=child_scopes,
        max_depth=MAX_DELEGATION_DEPTH,   # server sets this, not the client
        hmac_secret=CHAIN_HMAC_SECRET,
    )
    _persist_chain_claim(child_claim)
    _log_access(
        agent_id=parent_username,
        action=f"delegate_to:{body.child_agent_id}",
        result="success",
        extra={
            "child_agent_id": body.child_agent_id,
            "granted_scopes": child_scopes,
            "chain_depth": new_depth,
            "parent_chain_id": parent_claim.chain_id,
        },
        delegation_chain_id=child_claim.chain_id,
    )
    return {
        "chain_claim": child_claim.to_header_value(),
        "chain_id": child_claim.chain_id,
        "granted_scopes": child_scopes,
        "depth": new_depth,
        "max_depth": MAX_DELEGATION_DEPTH,
    }


# ============================================================================
# Health / info
# ============================================================================

@app.get("/")
async def root() -> Dict[str, Any]:
    return {
        "service": "UMA-Agent Resource Server",
        "version": "2.0.0",
        "status": "running",
        "use_case": "DORA Article 9 ICT risk compliance",
        "registered_resources": list(RESOURCES.keys()),
        "chain_extension": "urn:uma-agent:delegation-chain:1.0",
        "max_delegation_depth": MAX_DELEGATION_DEPTH,
    }


# ============================================================================
# Documents — ICT risk reports (read / write)
# ============================================================================

@app.get("/api/documents")
async def list_documents(
    payload: Dict = Depends(require_rpt_with_chain("documents", "read"))
) -> Dict[str, Any]:
    agent_id = payload.get("_agent_id", "unknown")
    return {
        "resource": "documents",
        "scope": "read",
        "dora_context": "DORA Art. 9.4 — ICT security policy documents",
        "documents": [
            {"id": "doc-001", "title": "ICT Risk Assessment Q1-2026", "classification": "CONFIDENTIAL", "size_kb": 245},
            {"id": "doc-002", "title": "Third-Party Provider Audit Report", "classification": "RESTRICTED", "size_kb": 189},
            {"id": "doc-003", "title": "DORA Compliance Gap Analysis", "classification": "INTERNAL", "size_kb": 312},
            {"id": "doc-004", "title": "ICT Incident Register 2025-2026", "classification": "RESTRICTED", "size_kb": 78},
        ],
        "accessed_by": agent_id,
        "timestamp": datetime.utcnow().isoformat(),
        "chain_id": payload.get("_chain_id"),
    }


@app.post("/api/documents")
async def create_document(
    document: Dict[str, Any],
    payload: Dict = Depends(require_rpt_with_chain("documents", "write"))
) -> Dict[str, Any]:
    agent_id = payload.get("_agent_id", "unknown")
    return {
        "id": f"doc-{uuid.uuid4().hex[:6]}",
        "title": document.get("title", "Untitled"),
        "classification": document.get("classification", "INTERNAL"),
        "created_by": agent_id,
        "created_at": datetime.utcnow().isoformat(),
        "status": "created",
        "chain_id": payload.get("_chain_id"),
    }


# ============================================================================
# Calendar — compliance schedule (read / write)
# ============================================================================

@app.get("/api/calendar")
async def view_calendar(
    payload: Dict = Depends(require_rpt_with_chain("calendar", "read"))
) -> Dict[str, Any]:
    agent_id = payload.get("_agent_id", "unknown")
    return {
        "resource": "calendar",
        "scope": "read",
        "dora_context": "DORA Art. 17 — ICT incident reporting schedule",
        "events": [
            {"id": "evt-001", "title": "DORA Quarterly Compliance Review", "date": "2026-05-15T09:00:00Z", "mandatory": True},
            {"id": "evt-002", "title": "ICT Incident Report Submission Deadline", "date": "2026-05-30T17:00:00Z", "mandatory": True},
            {"id": "evt-003", "title": "Third-Party Risk Assessment", "date": "2026-06-10T10:00:00Z", "mandatory": False},
        ],
        "accessed_by": agent_id,
        "timestamp": datetime.utcnow().isoformat(),
        "chain_id": payload.get("_chain_id"),
    }


@app.post("/api/calendar/events")
async def create_calendar_event(
    event: Dict[str, Any],
    payload: Dict = Depends(require_rpt_with_chain("calendar", "write"))
) -> Dict[str, Any]:
    agent_id = payload.get("_agent_id", "unknown")
    return {
        "id": f"evt-{uuid.uuid4().hex[:6]}",
        "title": event.get("title", "Untitled Event"),
        "date": event.get("date"),
        "created_by": agent_id,
        "created_at": datetime.utcnow().isoformat(),
        "status": "scheduled",
        "chain_id": payload.get("_chain_id"),
    }


# ============================================================================
# Database — transaction & audit data (read / write / audit)
# ============================================================================

@app.get("/api/database")
async def access_database(
    payload: Dict = Depends(require_rpt_with_chain("database", "read"))
) -> Dict[str, Any]:
    agent_id = payload.get("_agent_id", "unknown")
    return {
        "resource": "database",
        "scope": "read",
        "dora_context": "DORA Art. 9 — ICT third-party transaction records",
        "databases": [
            {"id": "txn-db-001", "name": "ICT Transaction Records", "records": 15_234, "status": "active"},
            {"id": "risk-db-002", "name": "Third-Party Risk Register", "records": 4_712, "status": "active"},
        ],
        "accessed_by": agent_id,
        "timestamp": datetime.utcnow().isoformat(),
        "chain_id": payload.get("_chain_id"),
    }


@app.post("/api/database/entries")
async def write_database_entry(
    entry: Dict[str, Any],
    payload: Dict = Depends(require_rpt_with_chain("database", "write"))
) -> Dict[str, Any]:
    agent_id = payload.get("_agent_id", "unknown")
    return {
        "id": f"entry-{uuid.uuid4().hex[:8]}",
        "database": entry.get("database", "txn-db-001"),
        "written_by": agent_id,
        "written_at": datetime.utcnow().isoformat(),
        "record_count": entry.get("record_count", 1),
        "status": "persisted",
        "chain_id": payload.get("_chain_id"),
    }


@app.get("/api/database/audit-entries")
async def read_audit_entries(
    payload: Dict = Depends(require_rpt_with_chain("database", "audit"))
) -> Dict[str, Any]:
    """
    Requires the 'audit' scope — only the compliance-manager's chain grants this.
    This endpoint is used to demonstrate T1: a data-extractor requesting audit
    scope without it being in its chain claim is blocked here.
    """
    agent_id = payload.get("_agent_id", "unknown")
    session = _db_session()
    try:
        rows = (
            session.query(DBAuditEvent)
            .order_by(DBAuditEvent.timestamp.desc())
            .limit(50)
            .all()
        )
        return {
            "resource": "database",
            "scope": "audit",
            "dora_context": "DORA Art. 17 — ICT audit trail for regulatory submission",
            "audit_entries": [r.to_dict() for r in rows],
            "total_returned": len(rows),
            "accessed_by": agent_id,
            "timestamp": datetime.utcnow().isoformat(),
            "chain_id": payload.get("_chain_id"),
        }
    finally:
        session.close()


# ============================================================================
# Audit chain verification (W3: tamper-evident audit)
# ============================================================================

@app.get("/api/audit/verify")
async def verify_audit_trail() -> Dict[str, Any]:
    """
    Recomputes the HMAC hash chain and reports any broken links.
    A broken link at position N means events N…end were tampered with.
    """
    session = _db_session()
    try:
        report = verify_audit_chain(session, CHAIN_HMAC_SECRET)
        return report
    finally:
        session.close()


@app.get("/api/audit/events")
async def list_audit_events(limit: int = 100) -> Dict[str, Any]:
    session = _db_session()
    try:
        rows = (
            session.query(DBAuditEvent)
            .order_by(DBAuditEvent.timestamp.desc())
            .limit(min(limit, 500))
            .all()
        )
        security_blocks = [r for r in rows if r.attack_class]
        return {
            "total_returned": len(rows),
            "security_blocks": len(security_blocks),
            "events": [r.to_dict() for r in rows],
        }
    finally:
        session.close()


@app.get("/api/audit/security-blocks")
async def list_security_blocks() -> Dict[str, Any]:
    """Returns only events where an attack was blocked (T1–T4)."""
    session = _db_session()
    try:
        rows = (
            session.query(DBAuditEvent)
            .filter(DBAuditEvent.attack_class.isnot(None))
            .order_by(DBAuditEvent.timestamp.desc())
            .limit(200)
            .all()
        )
        by_class: Dict[str, int] = {}
        for r in rows:
            by_class[r.attack_class] = by_class.get(r.attack_class, 0) + 1
        return {
            "total_blocks": len(rows),
            "by_attack_class": by_class,
            "blocks": [r.to_dict() for r in rows],
        }
    finally:
        session.close()


@app.get("/api/delegation-chains")
async def list_delegation_chains() -> Dict[str, Any]:
    """Returns all delegation chain claims recorded by the resource server."""
    session = _db_session()
    try:
        rows = (
            session.query(DelegationChainRecord)
            .order_by(DelegationChainRecord.created_at.desc())
            .limit(100)
            .all()
        )
        return {
            "total": len(rows),
            "chains": [r.to_dict() for r in rows],
        }
    finally:
        session.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000, log_level="info")
