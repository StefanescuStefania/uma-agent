#!/usr/bin/env python3
"""
Initialize Keycloak with test-realm, clients, and users
This script should be run after Keycloak is ready
"""
import time
import sys
from keycloak import KeycloakAdmin
from keycloak.exceptions import KeycloakGetError, KeycloakPostError

def wait_for_keycloak(max_attempts=30):
    """Wait for Keycloak to be ready"""
    import requests
    for i in range(max_attempts):
        try:
            # Try to access the Keycloak root endpoint
            response = requests.get("http://localhost:8080/", timeout=5)
            if response.status_code in [200, 404]:  # 404 is OK, means server is responding
                print(f"✓ Keycloak is ready!")
                return True
        except Exception as e:
            print(f"Waiting for Keycloak... ({i+1}/{max_attempts})")
            time.sleep(2)
    return False

def main():
    print("="*60)
    print("Keycloak Initialization Script")
    print("="*60)

    # Wait for Keycloak
    if not wait_for_keycloak():
        print("ERROR: Keycloak did not become ready in time")
        sys.exit(1)

    time.sleep(5)  # Extra wait for full startup

    try:
        # Connect as admin
        print("\n[1/5] Connecting to Keycloak admin...")
        admin = KeycloakAdmin(
            server_url="http://localhost:8080",
            username="admin",
            password="admin",
            realm_name="master",
            verify=False
        )
        print("✓ Connected")

        # Check if test-realm exists
        print("\n[2/5] Checking test-realm...")
        try:
            realm_info = admin.get_realm("test-realm")
            print(f"✓ test-realm exists (ID: {realm_info['id']})")
        except KeycloakGetError:
            print("Creating test-realm...")
            admin.create_realm(payload={
                "realm": "test-realm",
                "enabled": True,
                "displayName": "UMA Test Realm"
            })
            print("✓ test-realm created")

        # Switch to test-realm
        admin.realm_name = "test-realm"

        # Create or update clients
        print("\n[3/5] Creating clients...")

        # Get existing clients
        existing_clients = {c['clientId']: c['id'] for c in admin.get_clients()}

        # Create test-app client
        if 'test-app' not in existing_clients:
            print("  Creating test-app client...")
            test_app_data = {
                "clientId": "test-app",
                "name": "Test Application",
                "enabled": True,
                "publicClient": True,
                "directAccessGrantsEnabled": True,
                "standardFlowEnabled": True,
                "redirectUris": ["http://localhost:*"],
                "webOrigins": ["http://localhost:*"]
            }
            admin.create_client(payload=test_app_data)
            print("  ✓ test-app created")
        else:
            print("  ✓ test-app already exists")

        # Create resource-server client
        if 'resource-server' not in existing_clients:
            print("  Creating resource-server client...")
            resource_server_data = {
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
                "webOrigins": ["http://localhost:5000"]
            }
            admin.create_client(payload=resource_server_data)
            print("  ✓ resource-server created")
        else:
            print("  ✓ resource-server already exists")

        # Create users
        print("\n[4/5] Creating agent users...")
        agents = [
            ("coordinator-agent", "coordinator-pass123", "coordinator@uma-agent.local"),
            ("researcher-agent", "researcher-pass123", "researcher@uma-agent.local"),
            ("executor-agent", "executor-pass123", "executor@uma-agent.local"),
            ("validator-agent", "validator-pass123", "validator@uma-agent.local")
        ]

        existing_users = {u['username']: u['id'] for u in admin.get_users()}

        for username, password, email in agents:
            if username not in existing_users:
                print(f"  Creating {username}...")
                user_data = {
                    "username": username,
                    "email": email,
                    "enabled": True,
                    "emailVerified": True,
                    "credentials": [{
                        "type": "password",
                        "value": password,
                        "temporary": False
                    }]
                }
                admin.create_user(payload=user_data)
                print(f"  ✓ {username} created")
            else:
                print(f"  ✓ {username} already exists")

        # Verify setup
        print("\n[5/5] Verifying setup...")
        clients = admin.get_clients()
        client_ids = [c['clientId'] for c in clients]

        if 'resource-server' in client_ids and 'test-app' in client_ids:
            print("✓ All clients created")
        else:
            print("⚠ Some clients missing")

        users = admin.get_users()
        usernames = [u['username'] for u in users]

        agent_count = sum(1 for u in usernames if 'agent' in u)
        print(f"✓ {agent_count} agent users created")

        print("\n" + "="*60)
        print("Keycloak initialization complete!")
        print("="*60)
        print("\nClient credentials:")
        print("  CLIENT_ID: resource-server")
        print("  CLIENT_SECRET: uma-resource-server-secret")
        print("\nAgent credentials:")
        for username, password, _ in agents:
            print(f"  {username}: {password}")
        print("\n" + "="*60)

    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
