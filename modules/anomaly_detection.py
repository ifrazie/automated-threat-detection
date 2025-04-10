import logging
import json
import numpy as np
import time
import uuid
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class AnomalyDetector:
    def __init__(self):
        self.logger = logging.getLogger("AnomalyDetection")
        self.log_model = self._initialize_model()
        self.network_model = self._initialize_model()
        self.endpoint_model = self._initialize_model()
        
        # Load rules for rule-based detection
        self.rules = self._load_rules('config/detection_rules.json')
        
        # Keep track of alerts
        self.alerts = []
        self.stats = {
            'log_anomalies': 0,
            'network_anomalies': 0,
            'endpoint_anomalies': 0,
            'total_detections': 0
        }
    
    def _initialize_model(self):
        """Initialize the machine learning model for anomaly detection"""
        # Using Isolation Forest as an example algorithm
        return {
            'model': IsolationForest(contamination=0.05, random_state=42),
            'scaler': StandardScaler(),
            'is_trained': False,
            'training_data': []
        }
    
    def _load_rules(self, rules_path):
        """Load detection rules from a JSON file"""
        try:
            with open(rules_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading rules from {rules_path}: {str(e)}")
            # Return some default rules if the file can't be loaded
            return {
                "log_rules": [
                    {"pattern": "failed login", "severity": "medium"},
                    {"pattern": "unauthorized access", "severity": "high"}
                ],
                "network_rules": [
                    {"source_ip": "any", "dest_port": 22, "count_threshold": 10, "time_window": 60, "severity": "medium"}
                ],
                "endpoint_rules": [
                    {"process": "powershell.exe", "args_pattern": "-enc", "severity": "high"}
                ]
            }
    
    def analyze_logs(self, logs_data):
        """Analyze logs for anomalies using both ML and rule-based approaches"""
        self.logger.info(f"Analyzing {len(logs_data)} log entries")
        anomalies = []
        
        # Rule-based detection
        for log in logs_data:
            for rule in self.rules.get('log_rules', []):
                if rule.get('pattern', '') in str(log.get('message', '')):
                    anomaly = {
                        'id': str(uuid.uuid4()),
                        'timestamp': datetime.now().isoformat(),
                        'source': 'log',
                        'detection_type': 'rule_based',
                        'rule_name': rule.get('pattern', 'unknown'),
                        'severity': rule.get('severity', 'medium'),
                        'details': log,
                        'status': 'new'
                    }
                    anomalies.append(anomaly)
                    self.alerts.append(anomaly)
        
        # ML-based detection (if we have enough data)
        if len(logs_data) > 10:
            # Extract features (simplified)
            features = np.array([[
                len(str(log.get('message', ''))),
                hash(str(log.get('source', ''))) % 100  # Simple numeric feature
            ] for log in logs_data])
            
            # Train or update model if needed
            if not self.log_model['is_trained'] or len(self.log_model['training_data']) < 1000:
                self.log_model['training_data'].extend(features.tolist())
                if len(self.log_model['training_data']) >= 100:  # Train after collecting enough data
                    train_data = np.array(self.log_model['training_data'][-1000:])  # Use last 1000 samples
                    scaled_data = self.log_model['scaler'].fit_transform(train_data)
                    self.log_model['model'].fit(scaled_data)
                    self.log_model['is_trained'] = True
                    self.logger.info("Log anomaly detection model updated")
            
            # Detect anomalies if model is trained
            if self.log_model['is_trained']:
                scaled_features = self.log_model['scaler'].transform(features)
                predictions = self.log_model['model'].predict(scaled_features)
                
                for i, pred in enumerate(predictions):
                    if pred == -1:  # Anomaly
                        anomaly = {
                            'id': str(uuid.uuid4()),
                            'timestamp': datetime.now().isoformat(),
                            'source': 'log',
                            'detection_type': 'ml_based',
                            'severity': 'medium',
                            'details': logs_data[i],
                            'status': 'new'
                        }
                        anomalies.append(anomaly)
                        self.alerts.append(anomaly)
        
        self.stats['log_anomalies'] += len(anomalies)
        self.stats['total_detections'] += len(anomalies)
        return anomalies
    
    def analyze_network(self, network_data):
        """Analyze network traffic for anomalies"""
        self.logger.info(f"Analyzing {len(network_data)} network events")
        anomalies = []
        
        # Rule-based detection
        for event in network_data:
            for rule in self.rules.get('network_rules', []):
                # Simplified rule matching
                if (rule.get('dest_port', 0) == event.get('dest_port', 0) or 
                    rule.get('dest_port', 0) == 0):
                    anomaly = {
                        'id': str(uuid.uuid4()),
                        'timestamp': datetime.now().isoformat(),
                        'source': 'network',
                        'detection_type': 'rule_based',
                        'rule_name': f"Traffic to port {rule.get('dest_port', 'any')}",
                        'severity': rule.get('severity', 'medium'),
                        'details': event,
                        'status': 'new'
                    }
                    anomalies.append(anomaly)
                    self.alerts.append(anomaly)
        
        # ML detection would be implemented similarly to log analysis
        # Skipping the detailed implementation for brevity
        
        self.stats['network_anomalies'] += len(anomalies)
        self.stats['total_detections'] += len(anomalies)
        return anomalies
    
    def analyze_endpoints(self, endpoint_data):
        """Analyze endpoint activity for anomalies"""
        self.logger.info(f"Analyzing {len(endpoint_data)} endpoint events")
        anomalies = []
        
        # Rule-based detection
        for event in endpoint_data:
            for rule in self.rules.get('endpoint_rules', []):
                # Simplified rule matching
                if rule.get('process', '') in str(event.get('process', '')):
                    anomaly = {
                        'id': str(uuid.uuid4()),
                        'timestamp': datetime.now().isoformat(),
                        'source': 'endpoint',
                        'detection_type': 'rule_based',
                        'rule_name': f"Suspicious process: {rule.get('process', 'unknown')}",
                        'severity': rule.get('severity', 'medium'),
                        'details': event,
                        'status': 'new'
                    }
                    anomalies.append(anomaly)
                    self.alerts.append(anomaly)
        
        # ML detection would be implemented similarly to log analysis
        # Skipping the detailed implementation for brevity
        
        self.stats['endpoint_anomalies'] += len(anomalies)
        self.stats['total_detections'] += len(anomalies)
        return anomalies
    
    def get_recent_alerts(self, limit=100):
        """Return the most recent alerts"""
        return sorted(self.alerts, key=lambda x: x['timestamp'], reverse=True)[:limit]
    
    def get_detection_stats(self):
        """Return detection statistics"""
        return self.stats
