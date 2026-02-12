#!/usr/bin/env python3
"""
View complete audit trail from database

Shows all agents, delegations, audit events, and UMA tokens
with detailed information about what happened and why operations failed.
"""

import sys
from datetime import datetime
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from tabulate import tabulate

# Database connection
DATABASE_URL = "postgresql://keycloak:keycloak@localhost:5432/keycloak"

def get_session():
    """Create database session"""
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    return Session()

def view_agents(session):
    """View all agents created"""
    print("\n" + "="*100)
    print("AGENTS")
    print("="*100)

    result = session.execute("""
        SELECT
            id,
            agent_name,
            agent_type,
            scopes,
            delegation_depth,
            created_at
        FROM agent_states
        ORDER BY created_at DESC
    """)

    rows = result.fetchall()
    if not rows:
        print("No agents found")
        return

    headers = ["ID", "Name", "Type", "Scopes", "Depth", "Created At"]
    table_data = []
    for row in rows:
        table_data.append([
            row[0][:12] + "...",
            row[1],
            row[2],
            ", ".join(row[3]) if row[3] else "[]",
            row[4],
            row[5].strftime("%Y-%m-%d %H:%M:%S")
        ])

    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    print(f"\nTotal agents: {len(rows)}")

def view_delegations(session):
    """View all delegations (successful and failed)"""
    print("\n" + "="*100)
    print("DELEGATIONS")
    print("="*100)

    result = session.execute("""
        SELECT
            id,
            source_agent_id,
            target_agent_id,
            task_description,
            delegated_scopes,
            status,
            created_at
        FROM delegations
        ORDER BY created_at DESC
    """)

    rows = result.fetchall()
    if not rows:
        print("No delegations found")
        return

    headers = ["ID", "From Agent", "To Agent", "Task", "Scopes", "Status", "Created At"]
    table_data = []
    for row in rows:
        table_data.append([
            row[0][:12] + "...",
            row[1][:12] + "...",
            row[2][:12] + "...",
            (row[3][:40] + "...") if len(row[3]) > 40 else row[3],
            ", ".join(row[4]) if row[4] else "[]",
            row[5],
            row[6].strftime("%Y-%m-%d %H:%M:%S")
        ])

    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    print(f"\nTotal delegations: {len(rows)}")

def view_audit_events(session, limit=50):
    """View audit events with failure reasons"""
    print("\n" + "="*100)
    print(f"AUDIT EVENTS (last {limit})")
    print("="*100)

    result = session.execute(f"""
        SELECT
            event_type,
            agent_id,
            action,
            result,
            resource,
            extra_data,
            timestamp
        FROM audit_events
        ORDER BY timestamp DESC
        LIMIT {limit}
    """)

    rows = result.fetchall()
    if not rows:
        print("No audit events found")
        return

    # Group by result
    successful = [r for r in rows if r[3] == 'success']
    failed = [r for r in rows if r[3] == 'failure']

    print(f"\nSummary: {len(successful)} successful, {len(failed)} failed")

    if failed:
        print("\n" + "-"*100)
        print("FAILED OPERATIONS")
        print("-"*100)
        headers = ["Timestamp", "Event Type", "Agent", "Action", "Resource", "Reason"]
        table_data = []
        for row in failed:
            reason = ""
            if row[5]:  # extra_data
                reason = row[5].get('error', row[5].get('reason', ''))

            table_data.append([
                row[6].strftime("%Y-%m-%d %H:%M:%S"),
                row[0],
                row[1][:12] + "...",
                row[2],
                row[4] or "-",
                reason[:50] if reason else "No reason recorded"
            ])

        print(tabulate(table_data, headers=headers, tablefmt="grid"))

    print("\n" + "-"*100)
    print("ALL EVENTS")
    print("-"*100)
    headers = ["Timestamp", "Event Type", "Agent", "Action", "Result", "Resource"]
    table_data = []
    for row in rows:
        table_data.append([
            row[6].strftime("%Y-%m-%d %H:%M:%S"),
            row[0],
            row[1][:12] + "...",
            row[2],
            row[3],
            row[4] or "-"
        ])

    print(tabulate(table_data, headers=headers, tablefmt="grid"))

def view_uma_tokens(session):
    """View UMA tokens issued"""
    print("\n" + "="*100)
    print("UMA TOKENS (RPTs)")
    print("="*100)

    result = session.execute("""
        SELECT
            id,
            agent_id,
            token_type,
            resource,
            scopes,
            issued_at,
            expires_at,
            is_active
        FROM uma_tokens
        ORDER BY issued_at DESC
    """)

    rows = result.fetchall()
    if not rows:
        print("No UMA tokens found")
        return

    headers = ["ID", "Agent", "Type", "Resource", "Scopes", "Issued", "Expires", "Active"]
    table_data = []
    for row in rows:
        table_data.append([
            row[0][:12] + "...",
            row[1][:12] + "...",
            row[2],
            row[3],
            ", ".join(row[4]) if row[4] else "[]",
            row[5].strftime("%Y-%m-%d %H:%M:%S"),
            row[6].strftime("%Y-%m-%d %H:%M:%S"),
            "Yes" if row[7] else "No"
        ])

    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    print(f"\nTotal tokens: {len(rows)}")

def view_delegation_chain(session, agent_id=None):
    """View delegation chain for a specific agent"""
    if not agent_id:
        return

    print("\n" + "="*100)
    print(f"DELEGATION CHAIN FOR AGENT: {agent_id}")
    print("="*100)

    result = session.execute("""
        SELECT delegation_chain
        FROM agent_states
        WHERE id = :agent_id
    """, {"agent_id": agent_id})

    row = result.fetchone()
    if not row or not row[0]:
        print("No delegation chain found")
        return

    chain = row[0]
    for i, agent in enumerate(chain):
        print(f"Level {i+1}: {agent}")

def statistics(session):
    """Show statistics"""
    print("\n" + "="*100)
    print("STATISTICS")
    print("="*100)

    stats = {}

    # Count agents
    result = session.execute("SELECT COUNT(*) FROM agent_states")
    stats['Total Agents'] = result.fetchone()[0]

    # Count delegations
    result = session.execute("SELECT COUNT(*) FROM delegations")
    stats['Total Delegations'] = result.fetchone()[0]

    # Count successful delegations
    result = session.execute("SELECT COUNT(*) FROM delegations WHERE status = 'approved'")
    stats['Successful Delegations'] = result.fetchone()[0]

    # Count failed delegations
    result = session.execute("SELECT COUNT(*) FROM delegations WHERE status = 'denied'")
    stats['Failed Delegations'] = result.fetchone()[0]

    # Count audit events
    result = session.execute("SELECT COUNT(*) FROM audit_events")
    stats['Total Audit Events'] = result.fetchone()[0]

    # Count successful events
    result = session.execute("SELECT COUNT(*) FROM audit_events WHERE result = 'success'")
    stats['Successful Events'] = result.fetchone()[0]

    # Count failed events
    result = session.execute("SELECT COUNT(*) FROM audit_events WHERE result = 'failure'")
    stats['Failed Events'] = result.fetchone()[0]

    # Count UMA tokens
    result = session.execute("SELECT COUNT(*) FROM uma_tokens")
    stats['UMA Tokens Issued'] = result.fetchone()[0]

    # Count active tokens
    result = session.execute("SELECT COUNT(*) FROM uma_tokens WHERE is_active = true")
    stats['Active Tokens'] = result.fetchone()[0]

    # Event types breakdown
    result = session.execute("""
        SELECT event_type, COUNT(*)
        FROM audit_events
        GROUP BY event_type
        ORDER BY COUNT(*) DESC
    """)

    print("\nOverall Statistics:")
    print("-" * 50)
    for key, value in stats.items():
        print(f"{key:.<40} {value}")

    print("\nEvent Types Breakdown:")
    print("-" * 50)
    for row in result.fetchall():
        print(f"{row[0]:.<40} {row[1]}")

def main():
    """Main function"""
    print("\n" + "="*100)
    print("UMA-AGENT AUDIT TRAIL VIEWER")
    print("="*100)

    try:
        session = get_session()

        # Show statistics first
        statistics(session)

        # Show agents
        view_agents(session)

        # Show delegations
        view_delegations(session)

        # Show UMA tokens
        view_uma_tokens(session)

        # Show audit events
        view_audit_events(session, limit=50)

        print("\n" + "="*100)
        print("END OF AUDIT TRAIL")
        print("="*100 + "\n")

        session.close()
        return 0

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
