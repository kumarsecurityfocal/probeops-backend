"""
A simple Flask application to test server functionality.
"""
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/')
def root():
    return jsonify({
        "message": "Welcome to ProbeOps API", 
        "status": "online",
        "framework": "Flask"
    })