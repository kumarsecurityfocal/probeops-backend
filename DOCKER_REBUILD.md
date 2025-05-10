# ProbeOps Docker Rebuild & Database Migration Guide

This document explains how to rebuild the Docker containers and manage database migrations for ProbeOps API.

## Prerequisites

- Docker and Docker Compose installed
- PostgreSQL database service running (either local or remote)
- Environment variables properly configured in `.env` or environment

## Automated Scripts

Three helper scripts are provided to simplify container management:

1. **`update-backend.sh`** - Rebuilds and restarts the backend containers with migrations
2. **`test-migrations.sh`** - Tests migration process without rebuilding
3. **`verify_model_compatibility.py`** - Verifies model compatibility across environments

## Database Compatibility Notes

The system supports two different database schemas to maintain compatibility:

- Modern environments use `role` and `hashed_password` columns
- Legacy environments use `is_admin` and `password_hash` columns
- The migration system keeps both in sync automatically

## Manual Rebuild Process

If you need to manually rebuild and update the containers:

1. **Stop existing containers**:
   ```
   docker compose -f docker-compose.backend.yml down
   ```

2. **Rebuild containers**:
   ```
   docker compose -f docker-compose.backend.yml build --no-cache
   ```

3. **Start containers**:
   ```
   docker compose -f docker-compose.backend.yml up -d
   ```

4. **Apply migrations**:
   ```
   docker compose -f docker-compose.backend.yml exec api flask db upgrade
   ```

5. **Verify health**:
   ```
   curl http://localhost:5000/api/health
   ```

## Migration Process

The system uses Flask-Migrate to handle database migrations:

1. **Set Flask application**:
   ```
   export FLASK_APP=probeops.app
   ```

2. **Create a new migration**:
   ```
   flask db migrate -m "Description of changes"
   ```

3. **Review migration file**:
   The migration file will be created in `migrations/versions/`.
   Review and modify it if necessary.

4. **Apply migration**:
   ```
   flask db upgrade
   ```

5. **Revert migration (if needed)**:
   ```
   flask db downgrade
   ```

## Container Initialization

When containers start, the following sequence happens automatically:

1. Wait for the database to be available
2. Set Flask application environment variables
3. Mark current database state with `flask db stamp head`
4. Generate migrations for schema changes with `flask db migrate`
5. Apply migrations with `flask db upgrade`
6. Verify compatibility columns exist
7. Start the application server

## Troubleshooting

- **Container fails to start**: Check logs with `docker compose -f docker-compose.backend.yml logs api`
- **Migration errors**: Run `test-migrations.sh` to debug migration issues
- **Database connection issues**: Verify database host, username, and password in environment
- **Missing tables**: Ensure `flask db upgrade` completes successfully
- **Missing columns**: Verify the compatibility migration has been applied

## Key Column Compatibility

The User model supports multiple column naming schemes:

| Modern Column     | Legacy Column    | Purpose                   |
|-------------------|------------------|---------------------------|
| `hashed_password` | `password_hash`  | Store secure password     |
| `role`            | `is_admin`       | Track administrative role |

Both are kept synchronized through property methods in the User model.

## Testing Integration

For CI/CD pipelines, use the `verify_model_compatibility.py` script:

```
python verify_model_compatibility.py
```

This script will exit with code 0 on success or 1 on failure.

## Running Flask CLI Commands

### Using the Helper Script

We've provided a convenient helper script for running Flask CLI commands in the Docker container:

```
./flask-cli.sh [flask-command]
```

Examples:
```
./flask-cli.sh routes                   # Show all application routes
./flask-cli.sh db upgrade               # Run database migrations
./flask-cli.sh db migrate -m "message"  # Create a new migration
./flask-cli.sh shell                    # Start interactive Python shell
```

### Manual Execution

If you prefer to run commands manually:

```
docker compose -f docker-compose.backend.yml exec api flask --app main:app [command]
```

For example:
```
docker compose -f docker-compose.backend.yml exec api flask --app main:app routes
```

### Important Note

The Flask application is configured using `main:app`. This path should be used consistently for all Flask CLI commands.