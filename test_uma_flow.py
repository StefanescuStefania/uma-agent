#!/usr/bin/env python3
"""
Simple UMA 2.0 Flow Test

This script demonstrates the complete UMA 2.0 flow:
1. Try to access protected resource without token → get permission ticket
2. Exchange permission ticket for RPT using client credentials
3. Access protected resource with RPT → success!
"""

import requests
import re
import json
from typing import Optional

# Configuration
KEYCLOAK_URL = "http://localhost:8080"
REALM = "test-realm"
CLIENT_ID = "resource-server"
CLIENT_SECRET = "uma-resource-server-secret"
RESOURCE_SERVER_URL = "http://localhost:5000"

def print_step(step_num: int, title: str):
    """Print a step header"""
    print(f"\n{'='*70}")
    print(f"[Step {step_num}] {title}")
    print(f"{'='*70}")

def print_success(message: str):
    """Print success message"""
    print(f"✓ {message}")

def print_error(message: str):
    """Print error message"""
    print(f"✗ {message}")

def get_client_access_token() -> Optional[str]:
    """
    Get access token using client credentials grant
    This simulates an agent authenticating with Keycloak
    """
    try:
        response = requests.post(
            f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET
            }
        )
        response.raise_for_status()
        token_data = response.json()
        return token_data["access_token"]
    except Exception as e:
        print_error(f"Failed to get access token: {e}")
        return None

def access_protected_resource(resource_path: str, token: Optional[str] = None) -> dict:
    """
    Try to access a protected resource
    Returns: {"status": int, "data": dict, "permission_ticket": str or None}
    """
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        response = requests.get(
            f"{RESOURCE_SERVER_URL}{resource_path}",
            headers=headers
        )

        result = {
            "status": response.status_code,
            "data": None,
            "permission_ticket": None
        }

        if response.status_code == 200:
            result["data"] = response.json()
        elif response.status_code == 401:
            # Extract permission ticket from WWW-Authenticate header
            www_auth = response.headers.get("WWW-Authenticate", "")
            ticket_match = re.search(r'ticket="([^"]+)"', www_auth)
            if ticket_match:
                result["permission_ticket"] = ticket_match.group(1)

        return result

    except Exception as e:
        print_error(f"Request failed: {e}")
        return {"status": 0, "data": None, "permission_ticket": None}

def exchange_ticket_for_rpt(permission_ticket: str, agent_token: str) -> Optional[str]:
    """
    Exchange permission ticket for RPT (Requesting Party Token)
    """
    try:
        response = requests.post(
            f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
                "ticket": permission_ticket
            },
            headers={
                "Authorization": f"Bearer {agent_token}"
            }
        )

        if response.status_code == 200:
            token_data = response.json()
            return token_data["access_token"]
        else:
            print_error(f"RPT exchange failed: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        print_error(f"RPT exchange failed: {e}")
        return None

def main():
    """Run the complete UMA flow demonstration"""

    print("""
╔══════════════════════════════════════════════════════════════════╗
║                  UMA 2.0 FLOW DEMONSTRATION                      ║
╚══════════════════════════════════════════════════════════════════╝

This demonstrates:
  1. Accessing protected resource without authorization
  2. Receiving permission ticket from resource server
  3. Exchanging ticket for RPT using agent credentials
  4. Successfully accessing protected resource with RPT
""")

    # Step 1: Get client access token (simulates agent authentication)
    print_step(1, "Agent Authentication")
    print("Getting access token for resource-server client...")

    agent_token = get_client_access_token()
    if not agent_token:
        print_error("Failed to authenticate agent")
        return 1

    print_success("Agent authenticated successfully")
    print(f"  Token: {agent_token[:50]}...")

    # Step 2: Try to access protected resource without RPT
    print_step(2, "Access Protected Resource (Unauthorized)")
    print("Attempting to access /api/documents without RPT...")

    result = access_protected_resource("/api/documents")

    if result["status"] == 401 and result["permission_ticket"]:
        print_success("Received permission ticket from resource server!")
        print(f"  Permission Ticket: {result['permission_ticket'][:50]}...")
        permission_ticket = result["permission_ticket"]
    else:
        print_error(f"Expected 401 with permission ticket, got {result['status']}")
        return 1

    # Step 3: Exchange permission ticket for RPT
    print_step(3, "Exchange Permission Ticket for RPT")
    print("Exchanging ticket for RPT...")

    rpt = exchange_ticket_for_rpt(permission_ticket, agent_token)
    if not rpt:
        print_error("Failed to get RPT")
        return 1

    print_success("RPT obtained successfully!")
    print(f"  RPT: {rpt[:50]}...")

    # Step 4: Access protected resource with RPT
    print_step(4, "Access Protected Resource (Authorized)")
    print("Accessing /api/documents with RPT...")

    result = access_protected_resource("/api/documents", rpt)

    if result["status"] == 200:
        print_success("ACCESS GRANTED!")
        print("\nResource data:")
        print(json.dumps(result["data"], indent=2))
    else:
        print_error(f"Access denied: {result['status']}")
        return 1

    # Success!
    print(f"\n{'='*70}")
    print("✓ UMA 2.0 FLOW DEMONSTRATION COMPLETE")
    print(f"{'='*70}\n")

    print("Summary:")
    print("  1. ✓ Agent authenticated with Keycloak")
    print("  2. ✓ Resource server issued permission ticket")
    print("  3. ✓ Permission ticket exchanged for RPT")
    print("  4. ✓ Protected resource accessed with RPT")
    print("\n✓ All steps completed successfully!")
    print()

    return 0

if __name__ == "__main__":
    exit(main())
