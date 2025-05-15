#!/bin/bash

# NetGuardian Startup Script
# This script starts all NetGuardian components in the correct order

echo "Starting NetGuardian Security System..."
echo "--------------------------------------"

# Define color codes for better visibility
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Navigate to the prometheus project directory
cd "$(dirname "$0")"
PROJECT_ROOT=$(pwd)

echo -e "${BLUE}Step 1/4: Starting database services...${NC}"

# Start database services first
docker-compose up -d event-store intelligence-db evidence-vault
if [ $? -ne 0 ]; then
    echo "Failed to start database services. Please check the error message above."
    exit 1
fi

echo -e "${GREEN}✓ Database services started${NC}"
echo -e "${YELLOW}Waiting 30 seconds for databases to initialize...${NC}"
sleep 30

echo -e "${BLUE}Step 2/4: Starting API services...${NC}"

# Start API services
docker-compose up -d data-layer-api api-gateway
if [ $? -ne 0 ]; then
    echo "Failed to start API services. Please check the error message above."
    exit 1
fi

echo -e "${GREEN}✓ API services started${NC}"
echo -e "${YELLOW}Waiting 15 seconds for API services to initialize...${NC}"
sleep 15

echo -e "${BLUE}Step 3/4: Starting dashboard...${NC}"

# Start dashboard service
docker-compose up -d dashboard
if [ $? -ne 0 ]; then
    echo "Failed to start dashboard service. Please check the error message above."
    exit 1
fi

echo -e "${GREEN}✓ Dashboard service started${NC}"
echo -e "${YELLOW}Waiting 5 seconds for dashboard to initialize...${NC}"
sleep 5

echo -e "${BLUE}Step 4/4: Verifying services...${NC}"

# Check if all required services are running
RUNNING_SERVICES=$(docker-compose ps --services --filter "status=running" | wc -l)
if [ $RUNNING_SERVICES -lt 6 ]; then
    echo "Some services failed to start. Please check the logs with 'docker-compose logs'."
    exit 1
fi

echo -e "${GREEN}✓ All services are running properly${NC}"
echo "--------------------------------------"
echo -e "${GREEN}NetGuardian Security System started successfully!${NC}"
echo ""
echo "You can access the dashboard at: http://localhost:8080"
echo "Default login credentials: admin / netguardian"
echo ""
echo "To view logs of a specific service:"
echo "  docker-compose logs -f [service-name]"
echo ""
echo "To stop all services:"
echo "  docker-compose down"
echo "--------------------------------------" 