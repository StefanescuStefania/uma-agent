#!/usr/bin/env python3
"""Delete and recreate test users"""

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

def delete_user(token, username):
    """Delete a user"""
    headers = {"Authorization": f"Bearer {token}"}

    # Get user ID
    response = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users",
        params={"username": username},
        headers=headers
    )

    if response.status_code == 200 and response.json():
        user_id = response.json()[0]["id"]
        response = requests.delete(
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}",
            headers=headers
        )
        if response.status_code in [200, 204]:
            print(f"  Deleted: {username}")
            return True

    return False

def create_user(token, username, password, email):
    """Create user with full setup"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    user_data = {
        "username": username,
        "email": email,
        "firstName": username.capitalize(),
        "lastName": "Test",
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
        print(f"  Created: {username}")
        return True
    else:
        print(f"  Failed to create {username}: {response.status_code} - {response.text}")
        return False

def main():
    print("\nResetting test users...")

    try:
        token = get_admin_token()

        users = [
            ("alice", "alice123", "alice@test.local"),
            ("bob", "bob123", "bob@test.local"),
            ("testuser", "testpass", "testuser@test.local")
        ]

        # Delete existing users
        print("\n1. Deleting existing users...")
        for username, _, _ in users:
            delete_user(token, username)

        # Create new users
        print("\n2. Creating fresh users...")
        for username, password, email in users:
            create_user(token, username, password, email)

        # Test authentication
        print("\n3. Testing authentication...")
        response = requests.post(
            f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "test-app",
                "username": "alice",
                "password": "alice123"
            }
        )

        if response.status_code == 200:
            print("  ✓ Alice can authenticate!")
            print("\n✅ Test users are ready!")
            return 0
        else:
            print(f"  ✗ Authentication failed: {response.status_code}")
            print(f"    {response.json()}")
            return 1

    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
