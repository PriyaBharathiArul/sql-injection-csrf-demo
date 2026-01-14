#!/bin/bash

echo "=========================================================================="
echo "SQL Injection & CSRF Security Demo - Quick Start"
echo "=========================================================================="
echo ""

# Get EC2 public IP
echo "Detecting EC2 public IP..."
EC2_IP=$(curl -s ifconfig.me 2>/dev/null)

if [ -z "$EC2_IP" ]; then
    echo "⚠ Could not detect public IP. Using localhost."
    EC2_IP="localhost"
fi

echo "✓ Your public IP: $EC2_IP"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "✗ Error: Docker is not running"
    echo "  Please start Docker and try again"
    exit 1
fi

echo "✓ Docker is running"
echo ""

# Stop existing containers
echo "Stopping existing containers..."
docker-compose down > /dev/null 2>&1

# Build and start services
echo "Building and starting services..."
echo "  - Vulnerable Flask App (port 5000)"
echo "  - Patched Flask App (port 5001)"
echo "  - Attacker Website (port 8080)"
echo ""

docker-compose up --build -d

# Wait for services to start
echo "Waiting for services to initialize..."
sleep 5

# Check if services are running
echo ""
echo "Checking service status..."
if docker ps | grep -q vulnerable-app; then
    echo "  ✓ Vulnerable app is running"
else
    echo "  ✗ Vulnerable app failed to start"
fi

if docker ps | grep -q patched-app; then
    echo "  ✓ Patched app is running"
else
    echo "  ✗ Patched app failed to start"
fi

if docker ps | grep -q attacker-site; then
    echo "  ✓ Attacker site is running"
else
    echo "  ✗ Attacker site failed to start"
fi

echo ""
echo "=========================================================================="
echo "Demo is ready!"
echo "=========================================================================="
echo ""
echo "Access the applications:"
echo ""
echo "  Vulnerable App:  http://$EC2_IP:5000"
echo "  Patched App:     http://$EC2_IP:5001"
echo "  Attacker Site:   http://$EC2_IP:8080/attacker.html"
echo ""
echo "Test Accounts:"
echo "  alice / password123"
echo "  bob / secret456"
echo "  charlie / pass789"
echo "  admin / admin_secret"
echo ""
echo "=========================================================================="
echo ""
echo "Next Steps:"
echo "  1. Open the applications in your browser"
echo "  2. Follow the demos in README.md"
echo "  3. Run attack scripts from ./scripts/ directory"
echo ""
echo "To stop the demo:    docker-compose down"
echo "To view logs:        docker-compose logs -f"
echo "To reset databases:  docker-compose down -v && docker-compose up -d"
echo ""
echo "=========================================================================="
