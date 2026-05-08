#!/usr/bin/env python3
"""
Keycloak Initialisation Script — UMA-Agent DORA Use Case

Creates test-realm, clients, and DORA-named agent users.
Configures scope-based authorization policies in Keycloak's Authorization Services.

Run from the project root after docker compose up:
    python3 keycloak/init-keycloak.py

Environment variables:
    KEYCLOAK_URL  — default http://localhost:8080
"""
import os
import sys
import time

import requests
from keycloak import KeycloakAdmin
from keycloak.exceptions import KeycloakGetError, KeycloakPostError

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")


def wait_for_keycloak(max_attempts: int = 30) -> bool:
    for i in range(max_attempts):
        try:
            r = requests.get(f"{KEYCLOAK_URL}/realms/master", timeout=5)
            if r.status_code < 500:
                print(f"Keycloak ready.")
                return True
        except Exception:
            pass
        print(f"Waiting for Keycloak… ({i + 1}/{max_attempts})")
        time.sleep(5)
    return False


def main() -> None:
    print("=" * 60)
    print("UMA-Agent Keycloak Initialisation")
    print(f"Keycloak URL: {KEYCLOAK_URL}")
    print("=" * 60)

    if not wait_for_keycloak():
        print("ERROR: Keycloak did not become ready")
        sys.exit(1)

    time.sleep(5)

    master_admin = KeycloakAdmin(
        server_url=KEYCLOAK_URL,
        username="admin",
        password="admin",
        realm_name="master",
        verify=False,
    )

    # ----------------------------------------------------------------
    # test-realm
    # ----------------------------------------------------------------
    print("\n[1/4] Checking test-realm…")
    try:
        master_admin.get_realm("test-realm")
        print("  test-realm exists")
    except KeycloakGetError:
        master_admin.create_realm(
            payload={
                "realm": "test-realm",
                "enabled": True,
                "displayName": "UMA-Agent DORA Compliance Realm",
            }
        )
        print("  test-realm created")

    # Separate admin instance targeting test-realm
    admin = KeycloakAdmin(
        server_url=KEYCLOAK_URL,
        username="admin",
        password="admin",
        realm_name="test-realm",
        user_realm_name="master",
        verify=False,
    )

    # ----------------------------------------------------------------
    # Clients
    # ----------------------------------------------------------------
    print("\n[2/4] Creating clients…")
    existing = {c["clientId"]: c["id"] for c in admin.get_clients()}

    if "test-app" not in existing:
        admin.create_client(
            payload={
                "clientId": "test-app",
                "name": "Test Application",
                "enabled": True,
                "publicClient": True,
                "directAccessGrantsEnabled": True,
                "standardFlowEnabled": True,
                "redirectUris": ["http://localhost:*"],
                "webOrigins": ["http://localhost:*"],
            }
        )
        print("  test-app created")
    else:
        print("  test-app exists")

    if "resource-server" not in existing:
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
        print("  resource-server created")
    else:
        print("  resource-server exists")

    # ----------------------------------------------------------------
    # DORA agent users (W6: real-world role mapping)
    # ----------------------------------------------------------------
    print("\n[3/4] Creating DORA agent users…")
    agents = [
        # DORA roles
        ("compliance-manager", "compliance-pass123", "compliance.manager@dora.local",
         "DORA compliance manager — root of delegation chain; all scopes"),
        ("risk-analyst", "risk-pass123", "risk.analyst@dora.local",
         "DORA ICT risk analyst — depth 2; documents:read, database:read"),
        ("data-extractor", "extractor-pass123", "data.extractor@dora.local",
         "DORA data extractor — depth 3; database:read, database:write"),
        ("report-validator", "validator-pass123", "report.validator@dora.local",
         "DORA report validator — depth 4; documents:read, database:audit"),
        # Legacy names (backward compatible with existing tests)
        ("coordinator-agent", "coordinator-pass123", "coordinator@uma-agent.local", "Coordinator"),
        ("researcher-agent", "researcher-pass123", "researcher@uma-agent.local", "Researcher"),
        ("executor-agent", "executor-pass123", "executor@uma-agent.local", "Executor"),
        ("validator-agent", "validator-pass123", "validator@uma-agent.local", "Validator"),
        # OAuth flow test users
        ("alice", "alice123", "alice@test.local", "OAuth test user"),
        ("bob", "bob123", "bob@test.local", "OAuth test user"),
    ]

    existing_users = {u["username"] for u in admin.get_users()}
    for username, password, email, description in agents:
        if username not in existing_users:
            admin.create_user(
                payload={
                    "username": username,
                    "email": email,
                    "enabled": True,
                    "emailVerified": True,
                    "credentials": [
                        {"type": "password", "value": password, "temporary": False}
                    ],
                    "attributes": {"description": [description]},
                }
            )
            print(f"  created: {username}")
        else:
            print(f"  exists:  {username}")

    # ----------------------------------------------------------------
    # Verify
    # ----------------------------------------------------------------
    print("\n[4/4] Verifying…")
    clients = [c["clientId"] for c in admin.get_clients()]
    users = [u["username"] for u in admin.get_users()]
    dora_count = sum(1 for u in users if any(k in u for k in ["compliance", "risk", "extractor", "validator", "agent"]))

    print(f"  Clients: {[c for c in clients if c in ('resource-server', 'test-app')]}")
    print(f"  Agent users created: {dora_count}")

    print("\n" + "=" * 60)
    print("Initialisation complete.")
    print("=" * 60)
    print("\nDORA agent credentials:")
    for username, password, email, _ in agents[:4]:
        print(f"  {username}: {password}")
    print("\nResource server client:")
    print("  CLIENT_ID:     resource-server")
    print("  CLIENT_SECRET: uma-resource-server-secret")
    print("=" * 60)


if __name__ == "__main__":
    main()
