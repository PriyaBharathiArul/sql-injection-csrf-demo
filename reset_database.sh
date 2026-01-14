#!/bin/bash
# Reset Database Script
# Removes all data volumes and restarts containers with fresh databases

echo "========================================================================="
echo "Database Reset Script - Chaze Bank Demo"
echo "========================================================================="
echo ""
echo "This will:"
echo "  1. Stop all running containers"
echo "  2. Remove database volumes (deletes all user data)"
echo "  3. Restart containers with fresh databases"
echo ""
read -p "Continue? (y/n): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Reset cancelled."
    exit 0
fi

echo ""
echo "⏳ Stopping containers..."
docker-compose down -v

if [ $? -ne 0 ]; then
    echo "❌ Error: Failed to stop containers"
    exit 1
fi

echo ""
echo "🔄 Starting containers with fresh databases..."
docker-compose up -d

if [ $? -ne 0 ]; then
    echo "❌ Error: Failed to start containers"
    exit 1
fi

echo ""
echo "⏳ Waiting for services to be ready..."
sleep 5

echo ""
echo "✅ Database reset complete!"
echo ""
echo "========================================================================="
echo "Services are now running with fresh data:"
echo "========================================================================="
echo "  • Chaze Bank (Vulnerable):  http://54.91.136.41:5000"
echo "  • Chaze Bank (Secure):      http://54.91.136.41:5001"
echo "  • ShopSmart (Attacker):     http://54.91.136.41:8080"
echo ""
echo "Test Accounts (all reset to defaults):"
echo "  • alice / password123"
echo "  • bob / secret456"
echo "  • admin / admin_secret"
echo "  • charlie / pass789"
echo ""
echo "All user profiles have been reset to default values."
echo "========================================================================="
