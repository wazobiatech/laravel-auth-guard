#!/bin/bash

# JWT Package Test Environment Setup Script

set -e

echo "🚀 Setting up JWT Package test environment..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "composer.json" ]; then
    echo "❌ Please run this script from the JWT package root directory"
    exit 1
fi

echo "📦 Building test environment..."

# Build and start the test environment
docker-compose -f docker-compose.test.yml up -d --build

echo "⏳ Waiting for containers to be ready..."
sleep 5

echo "🔧 Installing dependencies..."
docker-compose -f docker-compose.test.yml exec jwt-test composer install

echo "🧪 Running JWT package tests..."
docker-compose -f docker-compose.test.yml exec jwt-test php test-standalone.php

echo ""
echo "📊 Test Results:"
echo "==============="

# Check test results
if [ $? -eq 0 ]; then
    echo "✅ All tests passed!"
    echo ""
    echo "🛠  Available commands:"
    echo "  - Run tests again: docker-compose -f docker-compose.test.yml exec jwt-test php test-standalone.php"
    echo "  - Interactive shell: docker-compose -f docker-compose.test.yml exec jwt-test bash"
    echo "  - View logs: docker-compose -f docker-compose.test.yml logs jwt-test"
    echo "  - Stop environment: docker-compose -f docker-compose.test.yml down"
else
    echo "❌ Some tests failed. Check the output above for details."
    echo ""
    echo "🔍 Debug commands:"
    echo "  - Interactive shell: docker-compose -f docker-compose.test.yml exec jwt-test bash"
    echo "  - View container logs: docker-compose -f docker-compose.test.yml logs jwt-test"
fi

echo ""
echo "Environment is ready! Containers will keep running for further testing."