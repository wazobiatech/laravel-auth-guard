# Laravel Auth Guard - Development Environment

This document describes how to set up and use the Docker-based development environment for the Laravel Auth Guard package.

## Quick Start

1. **Clone the repository and navigate to the project directory**
   ```bash
   git clone <repository-url>
   cd laravel-auth-guard
   ```

2. **Start the development environment**
   ```bash
   ./dev.sh up
   ```

3. **Enter the development container**
   ```bash
   ./dev.sh shell
   ```

4. **Run tests**
   ```bash
   ./dev.sh test
   ```

## Development Environment Components

### Services

- **laravel-auth-guard-dev**: Main PHP development container with Xdebug
- **redis-dev**: Redis server for caching and testing
- **redis-commander**: Web-based Redis GUI (http://localhost:8081)
- **nginx**: Documentation server (http://localhost:8080) - optional
- **phpunit**: Dedicated test runner container

### Ports

- `6381`: Redis server (to avoid conflicts with local Redis)
- `8081`: Redis Commander web interface
- `8080`: Documentation server (when enabled)
- `9003`: Xdebug remote debugging port

## Development Commands

The `dev.sh` script provides convenient commands for development:

### Environment Management
```bash
./dev.sh up          # Start all services
./dev.sh down        # Stop all services
./dev.sh restart     # Restart all services
./dev.sh build       # Rebuild containers
./dev.sh clean       # Clean up Docker resources
./dev.sh status      # Show container status
```

### Development
```bash
./dev.sh shell       # Enter main container shell
./dev.sh logs        # Show container logs
./dev.sh logs redis  # Show Redis logs
```

### Testing
```bash
./dev.sh test        # Run all tests
./dev.sh test-unit   # Run unit tests only
./dev.sh test-feature # Run feature tests only
```

### Package Management
```bash
./dev.sh composer install    # Install dependencies
./dev.sh composer update     # Update dependencies
./dev.sh composer require package/name
```

### PHP Commands
```bash
./dev.sh php -v              # Check PHP version
./dev.sh php test-jwt.php    # Run test script
```

### Redis Management
```bash
./dev.sh redis-cli           # Connect to Redis CLI
```

### Documentation
```bash
./dev.sh docs               # Start documentation server
```

## File Structure

```
├── docker/                 # Docker configuration files
│   ├── nginx/             # Nginx configuration
│   └── redis/             # Redis configuration
├── logs/                  # Application logs
├── docs/                  # Documentation files
├── Dockerfile.dev         # Development Dockerfile
├── docker-compose.yml     # Development services
├── .env.example          # Environment variables template
├── .dockerignore         # Docker ignore file
└── dev.sh               # Development helper script
```

## Environment Variables

Copy `.env.example` to `.env` and customize as needed:

```env
# Mercury/JWT Configuration
MERCURY_BASE_URL=https://mercury.tiadara.com
SIGNATURE_SHARED_SECRET=your-signature-secret
SERVICE_ID=your-service-id

# JWT Settings
JWT_ALGORITHM=RS512

# Auth Settings
AUTH_CACHE_TTL=3600
AUTH_LOGGING_ENABLED=true
AUTH_JWT_HEADER=Authorization
AUTH_PROJECT_TOKEN_HEADER=X-Project-Token

# Redis Configuration
REDIS_HOST=redis-dev
REDIS_PORT=6379
REDIS_AUTH_DB=0

# Development Settings
APP_DEBUG=true
LOG_LEVEL=debug
```

## Debugging with Xdebug

The development environment includes Xdebug configured for remote debugging:

1. **VS Code Setup**: Install the PHP Debug extension
2. **Configuration**: Add this to your `.vscode/launch.json`:
   ```json
   {
     "version": "0.2.0",
     "configurations": [
       {
         "name": "Listen for Xdebug",
         "type": "php",
         "request": "launch",
         "port": 9003,
         "pathMappings": {
           "/app": "${workspaceFolder}"
         }
       }
     ]
   }
   ```
3. **Usage**: Set breakpoints and start debugging session in VS Code

## Testing

The environment provides multiple ways to run tests:

### Using the dedicated test container:
```bash
./dev.sh test
```

### Inside the main container:
```bash
./dev.sh shell
./vendor/bin/phpunit
```

### Specific test suites:
```bash
./dev.sh test-unit      # Unit tests only
./dev.sh test-feature   # Feature tests only
```

## Redis Management

### Using Redis CLI:
```bash
./dev.sh redis-cli
```

### Using Redis Commander:
Open http://localhost:8081 in your browser for a web-based Redis interface.

### Redis Configuration:
- Development data: DB 0
- Test data: DB 1 (automatically used during testing)

## Troubleshooting

### Container Issues
```bash
# Check container status
./dev.sh status

# View container logs
./dev.sh logs
./dev.sh logs redis

# Rebuild containers
./dev.sh build

# Clean up and restart
./dev.sh clean
./dev.sh up
```

### Permission Issues
```bash
# Fix log directory permissions
chmod 777 logs/

# Reset container permissions
./dev.sh down
./dev.sh build
./dev.sh up
```

### Port Conflicts
If ports are already in use, modify the port mappings in `docker-compose.yml`:
- Redis: Change `6381:6379` to another port
- Redis Commander: Change `8081:8081`
- Documentation: Change `8080:80`

## Performance Optimization

### Composer Cache
The environment uses a Docker volume for Composer cache to speed up dependency installation across container rebuilds.

### Development vs Production
- Development containers include Xdebug and development tools
- Use `Dockerfile.test` for testing/CI environments
- Production deployments should use optimized images without development tools

## Contributing

1. Fork the repository
2. Set up the development environment: `./dev.sh up`
3. Make your changes
4. Run tests: `./dev.sh test`
5. Submit a pull request

## Support

For issues with the development environment, please:
1. Check this documentation
2. Review container logs: `./dev.sh logs`
3. Try rebuilding: `./dev.sh build`
4. Open an issue with relevant log output