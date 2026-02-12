#!/usr/bin/env python3
"""
Initialize UMA-Agent Database

Creates all necessary tables in PostgreSQL and verifies connectivity.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.database import init_database, get_db_session, AuditEvent, Delegation, AgentState, UMAToken
import uuid
from datetime import datetime

def main():
    """Initialize database and create tables"""

    print("="*60)
    print("UMA-Agent Database Initialization")
    print("="*60)
    print()

    # Step 1: Initialize database
    print("[1/3] Initializing database connection...")

    try:
        init_database(create_tables=True)
        print("✓ Database initialized")
        print("  - Tables created:")
        print("    - audit_events")
        print("    - delegations")
        print("    - agent_states")
        print("    - uma_tokens")
    except Exception as e:
        print(f"✗ Failed to initialize database: {e}")
        print("\nMake sure PostgreSQL is running:")
        print("  docker compose ps")
        return 1

    # Step 2: Test database connectivity
    print("\n[2/3] Testing database connectivity...")

    try:
        session = get_db_session()

        # Insert test audit event
        test_event = AuditEvent(
            id=f"test-{uuid.uuid4().hex[:8]}",
            event_type="test",
            agent_id="test-agent",
            action="database_init",
            result="success",
            extra_data={"message": "Database initialization test"}
        )
        session.add(test_event)
        session.commit()

        # Query it back
        events = session.query(AuditEvent).filter_by(event_type="test").all()
        session.close()

        print(f"✓ Database connectivity verified")
        print(f"  - Test event created and queried successfully")
        print(f"  - Found {len(events)} test event(s)")

    except Exception as e:
        print(f"✗ Database test failed: {e}")
        return 1

    # Step 3: Show database info
    print("\n[3/3] Database information...")

    session = get_db_session()

    audit_count = session.query(AuditEvent).count()
    delegation_count = session.query(Delegation).count()
    agent_count = session.query(AgentState).count()
    token_count = session.query(UMAToken).count()

    session.close()

    print(f"  Audit Events:  {audit_count}")
    print(f"  Delegations:   {delegation_count}")
    print(f"  Agent States:  {agent_count}")
    print(f"  UMA Tokens:    {token_count}")

    print()
    print("="*60)
    print("✓ Database initialization complete!")
    print("="*60)
    print()

    print("Next steps:")
    print("  - Run agents and they will automatically persist data")
    print("  - View audit logs: SELECT * FROM audit_events;")
    print("  - View delegations: SELECT * FROM delegations;")
    print()

    return 0

if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
