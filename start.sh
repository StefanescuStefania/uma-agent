#!/bin/bash
set -e

echo "=========================================="
echo "UMA-Agent Startup Script"
echo "=========================================="

# Step 1: Check if Docker containers are running
echo ""
echo "[1/5] Checking Docker containers..."
if ! docker ps | grep -q uma-keycloak; then
    echo "Starting Docker containers..."
    docker compose up -d
    echo "Waiting for Keycloak to start (40 seconds)..."
    sleep 40
else
    echo "✓ Docker containers already running"
fi

# Step 2: Initialize Keycloak
echo ""
echo "[2/5] Initializing Keycloak..."
source venv/bin/activate
python3 << 'EOF'
from keycloak import KeycloakAdmin
from keycloak.exceptions import KeycloakGetError
import time

time.sleep(2)

admin = KeycloakAdmin(
    server_url='http://localhost:8080',
    username='admin',
    password='admin',
    realm_name='master',
    verify=False
)

# Check test-realm exists
try:
    admin.get_realm('test-realm')
    print('✓ test-realm exists')
except:
    print('Creating test-realm...')
    admin.create_realm(payload={'realm': 'test-realm', 'enabled': True})
    print('✓ test-realm created')

admin.realm_name = 'test-realm'

# Create clients if they don't exist
existing_clients = {c['clientId']: c['id'] for c in admin.get_clients()}

if 'test-app' not in existing_clients:
    admin.create_client(payload={
        'clientId': 'test-app',
        'enabled': True,
        'publicClient': True,
        'directAccessGrantsEnabled': True,
        'redirectUris': ['http://localhost:*'],
        'webOrigins': ['http://localhost:*']
    })
    print('✓ test-app created')
else:
    print('✓ test-app exists')

if 'resource-server' not in existing_clients:
    admin.create_client(payload={
        'clientId': 'resource-server',
        'enabled': True,
        'clientAuthenticatorType': 'client-secret',
        'secret': 'uma-resource-server-secret',
        'publicClient': False,
        'serviceAccountsEnabled': True,
        'authorizationServicesEnabled': True,
        'redirectUris': ['http://localhost:5000/*'],
        'webOrigins': ['http://localhost:5000']
    })
    print('✓ resource-server created')
else:
    print('✓ resource-server exists')

print('\n✓ Keycloak initialized')
EOF

# Step 3: Update .env
echo ""
echo "[3/5] Configuring environment..."
cat > .env << 'ENVEOF'
CLIENT_SECRET=uma-resource-server-secret
CLIENT_ID=resource-server
KEYCLOAK_URL=http://localhost:8080
KEYCLOAK_REALM=test-realm
ENVEOF
echo "✓ .env configured"

# Step 4: Test authentication
echo ""
echo "[4/5] Testing authentication..."
source .env
python3 << 'EOF'
import requests
response = requests.post(
    'http://localhost:8080/realms/test-realm/protocol/openid-connect/token',
    data={
        'grant_type': 'client_credentials',
        'client_id': 'resource-server',
        'client_secret': 'uma-resource-server-secret'
    }
)
if response.status_code == 200:
    print('✓ Authentication working!')
else:
    print(f'✗ Authentication failed: {response.text}')
    exit(1)
EOF

# Step 5: Start resource server
echo ""
echo "[5/5] Starting resource server..."

# Kill any existing resource server
pkill -f "python3 resource_server/app.py" 2>/dev/null || true

# Start new resource server in background
CLIENT_SECRET=uma-resource-server-secret \
CLIENT_ID=resource-server \
KEYCLOAK_URL=http://localhost:8080 \
KEYCLOAK_REALM=test-realm \
python3 resource_server/app.py > logs/resource_server.log 2>&1 &

RESOURCE_PID=$!
echo "Resource server started with PID: $RESOURCE_PID"
echo "$RESOURCE_PID" > /tmp/uma_resource_server.pid

sleep 5

if ps -p $RESOURCE_PID > /dev/null; then
    echo "✓ Resource server running"
else
    echo "✗ Resource server failed to start. Check logs/resource_server.log"
    exit 1
fi

echo ""
echo "=========================================="
echo "Startup Complete!"
echo "=========================================="
echo ""
echo "Services:"
echo "  Keycloak: http://localhost:8080"
echo "  Resource Server: http://localhost:5000"
echo ""
echo "Credentials:"
echo "  CLIENT_ID: resource-server"
echo "  CLIENT_SECRET: uma-resource-server-secret"
echo ""
echo "To stop resource server:"
echo "  kill \$(cat /tmp/uma_resource_server.pid)"
echo ""
echo "=========================================="
