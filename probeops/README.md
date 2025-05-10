# ProbeOps API

ProbeOps is a secure and modular API for network diagnostics, offering comprehensive monitoring capabilities with advanced Role-Based Access Control (RBAC).

## Project Structure

The project is organized as a Python package:

```
probeops/
├── __init__.py        # Package initialization
├── app.py             # Flask application factory
├── models.py          # Database models
├── routes.py          # API routes
└── services/          # Service modules
    ├── __init__.py
    ├── auth.py        # Authentication services
    └── probe.py       # Network probe services
```

## Database Management

The project uses SQLAlchemy for ORM and Flask-Migrate for database migrations.

### Migration Commands

To work with database migrations, use the following commands:

1. Initialize migrations (first time only):
   ```
   export FLASK_APP=main.py
   flask db init
   ```

2. Create a new migration after model changes:
   ```
   export FLASK_APP=main.py
   flask db migrate -m "Description of changes"
   ```

3. Apply pending migrations:
   ```
   export FLASK_APP=main.py
   flask db upgrade
   ```

4. Revert the last migration:
   ```
   export FLASK_APP=main.py
   flask db downgrade
   ```

### Database Management Commands

The application provides custom CLI commands for database management:

1. Initialize the database:
   ```
   export FLASK_APP=main.py
   flask init-db
   ```

2. Reset the database (caution: deletes all data):
   ```
   export FLASK_APP=main.py
   flask reset-db
   ```

3. Create an admin user:
   ```
   export FLASK_APP=main.py
   flask create-admin --username admin --email admin@example.com
   ```

4. List all users:
   ```
   export FLASK_APP=main.py
   flask list-users
   ```

## API Endpoints

The API is organized into the following endpoint groups:

- `/api` - API root and health check
- `/api/users` - User authentication and management
- `/api/admin` - Administrative functions
- `/api/probe` - Network diagnostic tools
- `/api/apikeys` - API key management

## Authentication

The API supports two authentication methods:

1. JWT token authentication:
   - Obtain a token via `/api/users/login`
   - Include token in Authorization header: `Authorization: Bearer <token>`

2. API key authentication:
   - Create an API key via `/api/apikeys`
   - Include key in header: `X-API-Key: <api_key>`

## Role-Based Access Control

The API implements RBAC with the following roles:

- `user`: Standard access with tier-based limits
- `admin`: Full access including administrative endpoints

## Subscription Tiers

The API supports different subscription tiers with varying rate limits:

- `Free`: Basic access with limited requests
- `Standard`: Increased limits for regular users
- `Enterprise`: Maximum access and priority

## Environment Variables

The application uses the following environment variables:

- `DATABASE_URL`: PostgreSQL connection string
- `FLASK_SECRET_KEY`: Secret key for session management
- `JWT_SECRET_KEY`: Secret key for JWT token generation
- `ADMIN_EMAIL`: Default admin email (for initialization)
- `ADMIN_PASSWORD`: Default admin password (for initialization)