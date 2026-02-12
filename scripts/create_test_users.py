#!/usr/bin/env python3
"""
Create test users for OAuth flow tests

This creates:
- alice (alice123)
- bob (bob123)
- test-app public client

These are needed for tests/test_oauth_flow.py
"""

import requests
import sys

KEYCLOAK_URL = "http://localhost:8080"
REALM = "test-realm"

def get_admin_token():
    """Get admin access token"""
    response = requests.post(
        f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": "admin"
        }
    )
    response.raise_for_status()
    return response.json()["access_token"]

def create_user(token, username, password, email):
    """Create a user in the realm"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    user_data = {
        "username": username,
        "email": email,
        "enabled": True,
        "emailVerified": True,
        "requiredActions": [],
        "credentials": [{
            "type": "password",
            "value": password,
            "temporary": False
        }]
    }

    response = requests.post(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users",
        json=user_data,
        headers=headers
    )

    if response.status_code == 201:
        print(f"✓ Created user: {username}")
        return True
    elif response.status_code == 409:
        print(f"⚠ User already exists: {username}")
        return True
    else:
        print(f"✗ Failed to create user {username}: {response.status_code}")
        print(f"  {response.text}")
        return False

def create_public_client(token):
    """Create public client for password grant"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    client_data = {
        "clientId": "test-app",
        "enabled": True,
        "publicClient": True,
        "directAccessGrantsEnabled": True,
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "serviceAccountsEnabled": False,
        "redirectUris": ["*"],
        "webOrigins": ["*"]
    }

    response = requests.post(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients",
        json=client_data,
        headers=headers
    )

    if response.status_code == 201:
        print(f"✓ Created public client: test-app")
        return True
    elif response.status_code == 409:
        print(f"⚠ Client already exists: test-app")
        return True
    else:
        print(f"✗ Failed to create client: {response.status_code}")
        print(f"  {response.text}")
        return False

def main():
    print("\n" + "="*70)
    print("  Creating Test Users for OAuth Flow Tests")
    print("="*70 + "\n")

    try:
        # Get admin token
        print("Authenticating as admin...")
        token = get_admin_token()
        print("✓ Authenticated\n")

        # Create public client
        print("Creating public client...")
        create_public_client(token)
        print()

        # Create test users
        print("Creating test users...")
        create_user(token, "alice", "alice123", "alice@test.local")
        create_user(token, "bob", "bob123", "bob@test.local")
        create_user(token, "testuser", "testpass", "testuser@test.local")

        print("\n" + "="*70)
        print("  ✓ Test users created successfully!")
        print("="*70 + "\n")

        print("You can now run tests with:")
        print("  python3 -m pytest tests/test_oauth_flow.py -v")
        print()

        return 0

    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
