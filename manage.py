#!/usr/bin/env python3
"""
Flask application manager for ProbeOps API.
This script provides commands for database migrations and other management tasks.
"""
import os
from flask_migrate import Migrate, MigrateCommand
from flask.cli import FlaskGroup

from probeops.app import create_app, db

app = create_app()
migrate = Migrate(app, db)

cli = FlaskGroup(create_app=lambda: app)

if __name__ == "__main__":
    cli()