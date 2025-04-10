from flask import Flask, render_template, request, jsonify
from modules.data_ingestion import DataIngestionManager
from modules.anomaly_detection import AnomalyDetector
from modules.incident_response import IncidentResponder
import logging
import threading
import time
import os

app = Flask(__name__)

# Ensure logs directory exists
os.makedirs('logs', exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/app.log"),
        logging.StreamHandler()
    ]
)

# Initialize components
data_manager = DataIngestionManager()
anomaly_detector = AnomalyDetector()
incident_responder = IncidentResponder()

# Background worker thread
def background_monitoring():
    while True:
        try:
            # Collect data
            logs_data = data_manager.collect_logs()
            network_data = data_manager.collect_network_traffic()
            endpoint_data = data_manager.collect_endpoint_activity()
            
            # Detect anomalies
            log_anomalies = anomaly_detector.analyze_logs(logs_data)
            network_anomalies = anomaly_detector.analyze_network(network_data)
            endpoint_anomalies = anomaly_detector.analyze_endpoints(endpoint_data)
            
            # Respond to threats
            if log_anomalies or network_anomalies or endpoint_anomalies:
                all_anomalies = log_anomalies + network_anomalies + endpoint_anomalies
                incident_responder.handle_incidents(all_anomalies)
                
            time.sleep(60)  # Run every minute
        except Exception as e:
            logging.error(f"Error in monitoring thread: {str(e)}")
            time.sleep(60)  # Wait before retry

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/alerts')
def get_alerts():
    return jsonify(anomaly_detector.get_recent_alerts())

@app.route('/api/stats')
def get_stats():
    return jsonify({
        'logs_processed': data_manager.get_log_stats(),
        'network_events': data_manager.get_network_stats(),
        'endpoint_events': data_manager.get_endpoint_stats(),
        'threats_detected': anomaly_detector.get_detection_stats(),
        'incidents_resolved': incident_responder.get_resolution_stats()
    })

@app.route('/api/respond', methods=['POST'])
def manual_respond():
    incident_id = request.json.get('incident_id')
    action = request.json.get('action')
    return jsonify(incident_responder.manual_action(incident_id, action))

if __name__ == '__main__':
    # Start the monitoring thread
    monitor_thread = threading.Thread(target=background_monitoring, daemon=True)
    monitor_thread.start()
    
    # Start the Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)
