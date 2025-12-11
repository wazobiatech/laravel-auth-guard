#!/bin/bash

# Laravel Auth Guard - Development Environment Setup
# This script sets up the development environment using Docker Compose

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Laravel Auth Guard Development Environment Setup${NC}"
echo "=================================================="

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running. Please start Docker and try again.${NC}"
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker-compose >/dev/null 2>&1 && ! docker compose version >/dev/null 2>&1; then
    echo -e "${RED}❌ Docker Compose is not available. Please install Docker Compose and try again.${NC}"
    exit 1
fi

# Use docker compose if available, otherwise use docker-compose
DOCKER_COMPOSE="docker compose"
if ! docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker-compose"
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo -e "${YELLOW}📝 Creating .env file from .env.example...${NC}"
    cp .env.example .env
    echo -e "${GREEN}✅ .env file created${NC}"
else
    echo -e "${GREEN}✅ .env file already exists${NC}"
fi

# Create logs directory if it doesn't exist
if [ ! -d logs ]; then
    echo -e "${YELLOW}📁 Creating logs directory...${NC}"
    mkdir -p logs
    chmod 777 logs
    echo -e "${GREEN}✅ Logs directory created${NC}"
fi

# Create docs directory if it doesn't exist (for nginx)
if [ ! -d docs ]; then
    echo -e "${YELLOW}📁 Creating docs directory...${NC}"
    mkdir -p docs
    echo "<h1>Laravel Auth Guard Package</h1><p>Development environment is running!</p>" > docs/index.html
    echo -e "${GREEN}✅ Docs directory created${NC}"
fi

# Function to handle different commands
case "${1:-up}" in
    "up"|"start")
        echo -e "${BLUE}🔥 Starting development environment...${NC}"
        $DOCKER_COMPOSE up -d
        echo -e "${GREEN}✅ Development environment is running!${NC}"
        echo ""
        echo "Available services:"
        echo -e "  ${BLUE}Main container:${NC} laravel-auth-guard-dev"
        echo -e "  ${BLUE}Redis:${NC} redis-dev (localhost:6381)"
        echo -e "  ${BLUE}Redis Commander:${NC} http://localhost:8081"
        echo ""
        echo "Development commands:"
        echo -e "  ${YELLOW}Enter main container:${NC} $0 shell"
        echo -e "  ${YELLOW}Run tests:${NC} $0 test"
        echo -e "  ${YELLOW}View logs:${NC} $0 logs"
        echo -e "  ${YELLOW}Stop environment:${NC} $0 down"
        ;;
    
    "down"|"stop")
        echo -e "${BLUE}🛑 Stopping development environment...${NC}"
        $DOCKER_COMPOSE down
        echo -e "${GREEN}✅ Development environment stopped${NC}"
        ;;
    
    "restart")
        echo -e "${BLUE}🔄 Restarting development environment...${NC}"
        $DOCKER_COMPOSE restart
        echo -e "${GREEN}✅ Development environment restarted${NC}"
        ;;
    
    "build")
        echo -e "${BLUE}🔨 Building development containers...${NC}"
        $DOCKER_COMPOSE build --no-cache
        echo -e "${GREEN}✅ Containers built successfully${NC}"
        ;;
    
    "shell"|"bash")
        echo -e "${BLUE}🐚 Entering main development container...${NC}"
        docker exec -it laravel-auth-guard-dev bash
        ;;
    
    "test")
        echo -e "${BLUE}🧪 Running tests...${NC}"
        $DOCKER_COMPOSE --profile testing run --rm phpunit
        ;;
    
    "test-unit")
        echo -e "${BLUE}🧪 Running unit tests...${NC}"
        docker exec -it laravel-auth-guard-dev ./vendor/bin/phpunit --testsuite Unit
        ;;
    
    "test-feature")
        echo -e "${BLUE}🧪 Running feature tests...${NC}"
        docker exec -it laravel-auth-guard-dev ./vendor/bin/phpunit --testsuite Feature
        ;;
    
    "logs")
        container=${2:-laravel-auth-guard-dev}
        echo -e "${BLUE}📋 Showing logs for: $container${NC}"
        docker logs -f $container
        ;;
    
    "composer")
        shift
        echo -e "${BLUE}📦 Running composer: $@${NC}"
        docker exec -it laravel-auth-guard-dev composer "$@"
        ;;
    
    "php")
        shift
        echo -e "${BLUE}🐘 Running PHP: $@${NC}"
        docker exec -it laravel-auth-guard-dev php "$@"
        ;;
    
    "redis-cli")
        echo -e "${BLUE}🔴 Connecting to Redis CLI...${NC}"
        docker exec -it laravel-auth-guard-redis-dev redis-cli
        ;;
    
    "clean")
        echo -e "${YELLOW}🧹 Cleaning up Docker resources...${NC}"
        $DOCKER_COMPOSE down -v --remove-orphans
        docker system prune -f
        echo -e "${GREEN}✅ Cleanup completed${NC}"
        ;;
    
    "status")
        echo -e "${BLUE}📊 Container Status:${NC}"
        $DOCKER_COMPOSE ps
        ;;
    
    "docs")
        echo -e "${BLUE}📚 Starting documentation server...${NC}"
        $DOCKER_COMPOSE --profile docs up -d nginx
        echo -e "${GREEN}✅ Documentation available at: http://localhost:8080${NC}"
        ;;
    
    "help"|"-h"|"--help")
        echo ""
        echo "Laravel Auth Guard Development Environment"
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  up, start       Start the development environment"
        echo "  down, stop      Stop the development environment"
        echo "  restart         Restart all services"
        echo "  build           Rebuild all containers"
        echo "  shell, bash     Enter the main development container"
        echo "  test            Run all tests"
        echo "  test-unit       Run unit tests only"
        echo "  test-feature    Run feature tests only"
        echo "  logs [container] Show logs (default: main container)"
        echo "  composer [args] Run composer commands"
        echo "  php [args]      Run PHP commands"
        echo "  redis-cli       Connect to Redis CLI"
        echo "  clean           Clean up Docker resources"
        echo "  status          Show container status"
        echo "  docs            Start documentation server"
        echo "  help            Show this help message"
        echo ""
        ;;
    
    *)
        echo -e "${RED}❌ Unknown command: $1${NC}"
        echo -e "Run ${YELLOW}$0 help${NC} for available commands"
        exit 1
        ;;
esac