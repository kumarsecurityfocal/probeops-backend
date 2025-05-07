"""
Main application entry point for Flask.
This is a simple Flask application that will be used with gunicorn.
"""
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/')
def root():
    return jsonify({
        "message": "Welcome to ProbeOps API", 
        "status": "online",
        "note": "This is a Flask wrapper. For the full FastAPI application, run: uvicorn simple_app:app --host 0.0.0.0 --port 5000"
    })

@app.route('/health')
def health_check():
    return jsonify({
        "status": "OK",
        "message": "Service is running"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)