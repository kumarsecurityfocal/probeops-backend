"""
API routes for ProbeOps API
"""
import logging
from flask import Blueprint, jsonify

# Configure logging
logger = logging.getLogger(__name__)

def register_routes(app):
    """Register all API routes with the Flask app"""
    # Create blueprints for different route modules
    api_bp = Blueprint('api', __name__, url_prefix='/api')
    auth_bp = Blueprint('auth', __name__, url_prefix='/api/users')
    admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')
    probe_bp = Blueprint('probe', __name__, url_prefix='/api/probe')
    apikey_bp = Blueprint('apikey', __name__, url_prefix='/api/apikeys')
    
    # Register routes in each blueprint
    register_auth_routes(auth_bp)
    register_admin_routes(admin_bp)
    register_probe_routes(probe_bp)
    register_apikey_routes(apikey_bp)
    
    # Register API root routes
    @api_bp.route('/')
    def api_root():
        """API root endpoint"""
        return jsonify({
            "name": "ProbeOps API",
            "version": "1.0.0",
            "documentation": "/api/docs",
            "endpoints": [
                "/api/users",
                "/api/admin",
                "/api/probe",
                "/api/apikeys"
            ]
        })
    
    @api_bp.route('/health')
    def health_check():
        """Health check endpoint"""
        return jsonify({"status": "ok"})
    
    # Root route redirects to API root
    @app.route('/')
    def root():
        """Redirect root to API documentation"""
        return jsonify({
            "name": "ProbeOps API",
            "version": "1.0.0",
            "message": "Welcome to ProbeOps API",
            "api_root": "/api"
        })
    
    # Register all blueprints with the app
    app.register_blueprint(api_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(probe_bp)
    app.register_blueprint(apikey_bp)


def register_auth_routes(bp):
    """Register authentication routes"""
    # Import at function level to avoid circular imports
    from probeops.services.auth import login_required, create_jwt_token
    from probeops.models import User
    from probeops.app import db
    
    from flask import request
    
    @bp.route('/register', methods=['POST'])
    def register():
        """Register a new user"""
        # To be implemented
        return jsonify({"message": "Registration endpoint"}), 501
    
    @bp.route('/login', methods=['POST'])
    def login():
        """Login and get JWT token"""
        # To be implemented
        return jsonify({"message": "Login endpoint"}), 501
    
    @bp.route('/me', methods=['GET'])
    @login_required
    def get_current_user_info():
        """Get current user information"""
        # To be implemented
        return jsonify({"message": "Current user endpoint"}), 501


def register_admin_routes(bp):
    """Register admin routes"""
    # Import at function level to avoid circular imports
    from probeops.services.auth import admin_required
    
    @bp.route('/status', methods=['GET'])
    @admin_required
    def server_status():
        """Admin endpoint to check the server status"""
        # To be implemented
        return jsonify({"message": "Server status endpoint"}), 501


def register_probe_routes(bp):
    """Register probe routes"""
    # Import at function level to avoid circular imports
    from probeops.services.auth import login_required
    
    @bp.route('/ping', methods=['POST'])
    @login_required
    def ping_probe():
        """Run ping on a target host"""
        # To be implemented
        return jsonify({"message": "Ping probe endpoint"}), 501
    
    @bp.route('/traceroute', methods=['POST'])
    @login_required
    def traceroute_probe():
        """Run traceroute on a target host"""
        # To be implemented
        return jsonify({"message": "Traceroute probe endpoint"}), 501
    
    @bp.route('/dns', methods=['POST'])
    @login_required
    def dns_probe():
        """Run DNS lookup on a domain"""
        # To be implemented
        return jsonify({"message": "DNS lookup endpoint"}), 501
    
    @bp.route('/whois', methods=['POST'])
    @login_required
    def whois_probe():
        """Run WHOIS lookup on a domain"""
        # To be implemented
        return jsonify({"message": "WHOIS lookup endpoint"}), 501
    
    @bp.route('/history', methods=['GET'])
    @login_required
    def probe_history():
        """Get probe job history for the current user"""
        # To be implemented
        return jsonify({"message": "Probe history endpoint"}), 501


def register_apikey_routes(bp):
    """Register API key routes"""
    # Import at function level to avoid circular imports
    from probeops.services.auth import login_required
    
    @bp.route('/', methods=['GET'])
    @login_required
    def list_apikeys():
        """List API keys for the current user"""
        # To be implemented
        return jsonify({"message": "List API keys endpoint"}), 501
    
    @bp.route('/', methods=['POST'])
    @login_required
    def create_apikey():
        """Create a new API key for the current user"""
        # To be implemented
        return jsonify({"message": "Create API key endpoint"}), 501