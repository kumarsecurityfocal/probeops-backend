"""
UI routes for the ProbeOps API
These routes serve the web interface for testing the API.
"""
from flask import Blueprint, render_template

ui_blueprint = Blueprint('ui', __name__)


@ui_blueprint.route('/')
def index():
    """Serve the main UI for testing the API"""
    return render_template('index.html')


@ui_blueprint.route('/docs')
def docs():
    """Serve the API documentation"""
    return render_template('docs.html')