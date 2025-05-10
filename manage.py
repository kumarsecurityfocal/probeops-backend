#!/usr/bin/env python3
"""
Flask application manager for ProbeOps API.
This script provides commands for database migrations and other management tasks.
"""
import os
import click
from flask.cli import FlaskGroup
from flask_migrate import Migrate

from probeops.app import create_app, db

# Create the Flask application
app = create_app()
migrate = Migrate(app, db)


@app.cli.command("init-db")
def init_db():
    """Initialize the database."""
    click.echo("Creating database tables...")
    db.create_all()
    click.echo("Database tables created!")


@app.cli.command("reset-db")
def reset_db():
    """Reset the database."""
    if click.confirm("This will delete all data. Are you sure?"):
        click.echo("Dropping database tables...")
        db.drop_all()
        click.echo("Creating database tables...")
        db.create_all()
        click.echo("Database has been reset!")


@app.cli.command("create-admin")
@click.option("--username", default="admin", help="Admin username")
@click.option("--email", default="admin@example.com", help="Admin email")
@click.option("--password", help="Admin password")
def create_admin(username, email, password):
    """Create an admin user."""
    from probeops.models import User
    
    if not password:
        password = click.prompt("Enter admin password", hide_input=True, confirmation_prompt=True)
    
    admin = User(
        username=username,
        email=email,
        role=User.ROLE_ADMIN,
        subscription_tier=User.TIER_ENTERPRISE,
        is_active=True
    )
    admin.password = password
    
    db.session.add(admin)
    db.session.commit()
    
    click.echo(f"Admin user '{username}' created successfully!")


@app.cli.command("list-users")
def list_users():
    """List all users."""
    from probeops.models import User
    
    users = User.query.all()
    if not users:
        click.echo("No users found.")
        return
    
    click.echo("Users:")
    for user in users:
        click.echo(f"ID: {user.id}, Username: {user.username}, "
                   f"Email: {user.email}, Role: {user.role}, "
                   f"Tier: {user.subscription_tier}, Active: {user.is_active}")


# Create CLI group for custom commands
cli = FlaskGroup(create_app=lambda: app)

if __name__ == "__main__":
    cli()