#!/usr/bin/env python3
"""
Setup Test Users in Keycloak

Creates real test users in Keycloak for testing the workflow.

Test Users Created:
1. coordinator-user (Coordinator Agent)
   - Scopes: read:data, write:data, execute:tasks, delegate:tasks
   - Password: coordinator-pass123

2. researcher-user (Researcher Agent)
   - Scopes: read:data, execute:tasks
   - Password: researcher-pass123

3. executor-user (Executor Agent)
   - Scopes: read:data, write:data, execute:tasks
   - Password: executor-pass123

4. validator-user (Validator Agent)
   - Scopes: read:data, validate:results
   - Password: validator-pass123

5. admin-user (Test Admin)
   - Scopes: admin:all
   - Password: admin-pass123

Usage:
    python3 tests/setup_keycloak_test_users.py

This creates the users needed for integration tests.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keycloak import KeycloakAdmin
from agents.workflow_logger import WorkflowLogger, WorkflowEventType, LogLevel


# Test user definitions
TEST_USERS = {
    "coordinator-user": {
        "password": "coordinator-pass123",
        "first_name": "Coordinator",
        "last_name": "Agent",
        "email": "coordinator@agents.local",
        "agent_type": "coordinator",
        "scopes": ["read:data", "write:data", "execute:tasks", "delegate:tasks"]
    },
    "researcher-user": {
        "password": "researcher-pass123",
        "first_name": "Researcher",
        "last_name": "Agent",
        "email": "researcher@agents.local",
        "agent_type": "researcher",
        "scopes": ["read:data", "execute:tasks", "delegate:tasks"]
    },
    "executor-user": {
        "password": "executor-pass123",
        "first_name": "Executor",
        "last_name": "Agent",
        "email": "executor@agents.local",
        "agent_type": "executor",
        "scopes": ["read:data", "write:data", "execute:tasks"]
    },
    "validator-user": {
        "password": "validator-pass123",
        "first_name": "Validator",
        "last_name": "Agent",
        "email": "validator@agents.local",
        "agent_type": "validator",
        "scopes": ["read:data", "validate:results"]
    },
    "admin-user": {
        "password": "admin-pass123",
        "first_name": "Admin",
        "last_name": "User",
        "email": "admin@agents.local",
        "agent_type": "admin",
        "scopes": ["admin:all"]
    },
    "test-user": {
        "password": "test-pass123",
        "first_name": "Test",
        "last_name": "User",
        "email": "test@agents.local",
        "agent_type": "user",
        "scopes": ["read:data"]
    }
}


def setup_test_users(
    server_url: str = "http://localhost:8080",
    realm_name: str = "uma-agent-realm",
    admin_user: str = "admin",
    admin_password: str = "admin",
    verbose: bool = True
) -> bool:
    """
    Setup test users in Keycloak.

    Args:
        server_url: Keycloak server URL
        realm_name: Realm name
        admin_user: Admin username
        admin_password: Admin password
        verbose: Print progress

    Returns:
        True if successful
    """
    # Initialize logger
    logger = WorkflowLogger(console_output=verbose)

    print("\n" + "=" * 80)
    print("KEYCLOAK TEST USER SETUP")
    print("=" * 80 + "\n")

    # Connect to Keycloak
    try:
        keycloak_admin = KeycloakAdmin(
            server_url=server_url,
            username=admin_user,
            password=admin_password,
            realm_name="master",
            user_realm_name="master",
            verify=False
        )
        print("✓ Connected to Keycloak")
    except Exception as e:
        print(f"✗ Failed to connect to Keycloak: {e}")
        print("  Make sure Keycloak is running: docker-compose up")
        logger.log_error(
            None,
            None,
            f"Failed to connect to Keycloak: {e}",
            "KeycloakConnectionError"
        )
        return False

    # Switch to target realm
    keycloak_admin.realm_name = realm_name

    print(f"✓ Using realm: {realm_name}\n")

    # Create test users
    print("Creating test users...")
    print("-" * 80 + "\n")

    created_users = []
    failed_users = []

    for username, user_data in TEST_USERS.items():
        try:
            # Check if user exists
            try:
                existing_user_id = keycloak_admin.get_user_id(username)
                if existing_user_id:
                    print(f"⚠ User already exists: {username}")
                    logger.log(
                        WorkflowEventType.AGENT_CREATED,
                        f"Test user already exists: {username}",
                        level=LogLevel.WARNING
                    )
                    continue
            except:
                pass  # User doesn't exist, continue creating

            # Prepare user data
            create_data = {
                "username": username,
                "firstName": user_data["first_name"],
                "lastName": user_data["last_name"],
                "email": user_data["email"],
                "enabled": True,
                "credentials": [
                    {
                        "type": "password",
                        "value": user_data["password"],
                        "temporary": False
                    }
                ],
                "attributes": {
                    "agent_type": user_data["agent_type"],
                    "scopes": user_data["scopes"],
                    "created_by": "setup_keycloak_test_users.py"
                }
            }

            # Create user
            response = keycloak_admin.create_user(create_data, exist_ok=False)

            print(f"✓ Created user: {username}")
            print(f"  - Agent type: {user_data['agent_type']}")
            print(f"  - Email: {user_data['email']}")
            print(f"  - Scopes: {', '.join(user_data['scopes'])}")
            print(f"  - Password: {user_data['password']}")
            print()

            logger.log_agent_created(
                username,
                f"{user_data['first_name']} {user_data['last_name']}",
                user_data["agent_type"]
            )

            created_users.append(username)

        except Exception as e:
            print(f"✗ Failed to create user: {username}")
            print(f"  Error: {e}\n")

            logger.log_error(
                username,
                user_data.get("first_name"),
                f"Failed to create test user: {e}",
                "UserCreationError"
            )

            failed_users.append(username)

    # Print summary
    print("=" * 80)
    print("SETUP SUMMARY")
    print("=" * 80 + "\n")

    print(f"Created users: {len(created_users)}")
    if created_users:
        for user in created_users:
            print(f"  ✓ {user}")

    if failed_users:
        print(f"\nFailed users: {len(failed_users)}")
        for user in failed_users:
            print(f"  ✗ {user}")

    # List created users
    print("\n" + "-" * 80)
    print("All users in realm:")
    print("-" * 80 + "\n")

    try:
        users = keycloak_admin.get_users()
        for user in users:
            scopes = user.get("attributes", {}).get("scopes", [])
            agent_type = user.get("attributes", {}).get("agent_type", "unknown")
            print(f"{user['username']}")
            print(f"  - Type: {agent_type}")
            print(f"  - Email: {user.get('email', 'N/A')}")
            print(f"  - Scopes: {', '.join(scopes) if scopes else 'None'}")
            print()
    except Exception as e:
        print(f"Failed to list users: {e}\n")

    # Export logs
    print("-" * 80)
    log_file = logger.export_logs()
    print(f"✓ Logs exported to: {log_file}\n")

    # Success message
    print("=" * 80)
    if failed_users:
        print("SETUP COMPLETED WITH WARNINGS")
        return len(created_users) > 0
    else:
        print("SETUP COMPLETED SUCCESSFULLY")
        return True

    print("=" * 80 + "\n")


def cleanup_test_users(
    server_url: str = "http://localhost:8080",
    realm_name: str = "uma-agent-realm",
    admin_user: str = "admin",
    admin_password: str = "admin",
    verbose: bool = True
) -> bool:
    """
    Delete test users from Keycloak.

    Args:
        server_url: Keycloak server URL
        realm_name: Realm name
        admin_user: Admin username
        admin_password: Admin password
        verbose: Print progress

    Returns:
        True if successful
    """
    print("\n" + "=" * 80)
    print("KEYCLOAK TEST USER CLEANUP")
    print("=" * 80 + "\n")

    try:
        keycloak_admin = KeycloakAdmin(
            server_url=server_url,
            username=admin_user,
            password=admin_password,
            realm_name="master",
            user_realm_name="master",
            verify=False
        )
        keycloak_admin.realm_name = realm_name
        print("✓ Connected to Keycloak\n")
    except Exception as e:
        print(f"✗ Failed to connect: {e}")
        return False

    deleted_count = 0
    for username in TEST_USERS.keys():
        try:
            user_id = keycloak_admin.get_user_id(username)
            if user_id:
                keycloak_admin.delete_user(user_id)
                print(f"✓ Deleted user: {username}")
                deleted_count += 1
            else:
                print(f"⚠ User not found: {username}")
        except Exception as e:
            print(f"✗ Failed to delete user {username}: {e}")

    print(f"\nDeleted {deleted_count} users")
    return True


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Setup test users in Keycloak"
    )
    parser.add_argument(
        "action",
        choices=["setup", "cleanup"],
        help="Action to perform"
    )
    parser.add_argument(
        "--server",
        default="http://localhost:8080",
        help="Keycloak server URL"
    )
    parser.add_argument(
        "--realm",
        default="test-realm",
        help="Realm name"
    )
    parser.add_argument(
        "--admin-user",
        default="admin",
        help="Admin username"
    )
    parser.add_argument(
        "--admin-password",
        default="admin",
        help="Admin password"
    )

    args = parser.parse_args()

    if args.action == "setup":
        success = setup_test_users(
            server_url=args.server,
            realm_name=args.realm,
            admin_user=args.admin_user,
            admin_password=args.admin_password
        )
    else:
        success = cleanup_test_users(
            server_url=args.server,
            realm_name=args.realm,
            admin_user=args.admin_user,
            admin_password=args.admin_password
        )

    sys.exit(0 if success else 1)
