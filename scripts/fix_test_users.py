#!/usr/bin/env python3
"""Fix existing test users to be fully set up"""

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

def update_user(token, username):
    """Update user to be fully set up"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # Get user ID
    response = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users",
        params={"username": username},
        headers=headers
    )

    if response.status_code != 200 or not response.json():
        print(f"✗ User not found: {username}")
        return False

    user_id = response.json()[0]["id"]

    # Update user
    update_data = {
        "emailVerified": True,
        "requiredActions": []
    }

    response = requests.put(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}",
        json=update_data,
        headers=headers
    )

    if response.status_code in [200, 204]:
        print(f"✓ Updated user: {username}")
        return True
    else:
        print(f"✗ Failed to update {username}: {response.status_code}")
        return False

def main():
    print("\nFixing test users...")

    try:
        token = get_admin_token()

        users = ["alice", "bob", "testuser"]
        for username in users:
            update_user(token, username)

        print("\n✓ Done! Testing authentication...")

        # Test alice authentication
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
            print("✓ Alice can authenticate successfully!")
            return 0
        else:
            print(f"✗ Alice authentication failed: {response.status_code}")
            print(f"  {response.json()}")
            return 1

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
