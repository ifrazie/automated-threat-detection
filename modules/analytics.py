import logging
import json
import os
import time
from datetime import datetime, timedelta
import pandas as pd
import numpy as np

class ThreatAnalytics:
    def __init__(self, data_path="logs/analytics"):
        self.logger = logging.getLogger("Analytics")
        self.data_path = data_path
        
        # Create analytics directory if it doesn't exist
        os.makedirs(self.data_path, exist_ok=True)
        
        # Initialize data stores
        self.alerts_store = os.path.join(self.data_path, "alerts_data.json")
        self.stats_store = os.path.join(self.data_path, "stats_data.json")
        
        # Load existing data
        self.alerts_data = self._load_data(self.alerts_store, default=[])
        self.stats_data = self._load_data(self.stats_store, default=[])
    
    def _load_data(self, file_path, default=None):
        """Load data from JSON file, return default if file doesn't exist"""
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    return json.load(f)
            return default
        except Exception as e:
            self.logger.error(f"Error loading data from {file_path}: {str(e)}")
            return default
    
    def _save_data(self, data, file_path):
        """Save data to JSON file"""
        try:
            with open(file_path, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            self.logger.error(f"Error saving data to {file_path}: {str(e)}")
    
    def record_alert(self, alert):
        """Record an alert for analytics"""
        # Add timestamp if not present
        if 'timestamp' not in alert:
            alert['timestamp'] = datetime.now().isoformat()
        
        # Add to alerts data
        self.alerts_data.append(alert)
        
        # Save to file
        self._save_data(self.alerts_data, self.alerts_store)
    
    def record_stats(self, stats):
        """Record system statistics for analytics"""
        # Add timestamp if not present
        if 'timestamp' not in stats:
            stats['timestamp'] = datetime.now().isoformat()
        
        # Add to stats data
        self.stats_data.append(stats)
        
        # Save to file
        self._save_data(self.stats_data, self.stats_store)
    
    def get_alert_trends(self, days=7):
        """Get alert trends for the specified number of days"""
        if not self.alerts_data:
            return {
                'daily_counts': [],
                'severity_distribution': {},
                'source_distribution': {}
            }
        
        # Convert to pandas DataFrame for easier analysis
        df = pd.DataFrame(self.alerts_data)
        
        # Ensure timestamp is datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Filter for the specified time range
        start_date = datetime.now() - timedelta(days=days)
        recent_df = df[df['timestamp'] >= start_date]
        
        if recent_df.empty:
            return {
                'daily_counts': [],
                'severity_distribution': {},
                'source_distribution': {}
            }
        
        # Get daily counts
        daily_counts = recent_df.groupby(recent_df['timestamp'].dt.date).size()
        
        # Get severity distribution
        severity_counts = recent_df['severity'].value_counts().to_dict()
        
        # Get source distribution
        source_counts = recent_df['source'].value_counts().to_dict()
        
        return {
            'daily_counts': [{
                'date': date.isoformat(),
                'count': int(count)
            } for date, count in daily_counts.items()],
            'severity_distribution': severity_counts,
            'source_distribution': source_counts
        }
    
    def get_stats_trends(self, days=7):
        """Get system statistics trends for the specified number of days"""
        if not self.stats_data:
            return {
                'logs_processed': [],
                'network_events': [],
                'endpoint_events': [],
                'threats_detected': [],
                'incidents_resolved': []
            }
        
        # Convert to pandas DataFrame for easier analysis
        df = pd.DataFrame(self.stats_data)
        
        # Ensure timestamp is datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Filter for the specified time range
        start_date = datetime.now() - timedelta(days=days)
        recent_df = df[df['timestamp'] >= start_date]
        
        if recent_df.empty:
            return {
                'logs_processed': [],
                'network_events': [],
                'endpoint_events': [],
                'threats_detected': [],
                'incidents_resolved': []
            }
        
        # Get trends for each metric
        metrics = ['logs_processed', 'network_events', 'endpoint_events', 
                  'threats_detected', 'incidents_resolved']
        
        result = {}
        for metric in metrics:
            if metric in recent_df.columns:
                daily_values = recent_df.groupby(recent_df['timestamp'].dt.date)[metric].max()
                result[metric] = [{
                    'date': date.isoformat(),
                    'value': int(value)
                } for date, value in daily_values.items()]
            else:
                result[metric] = []
        
        return result
    
    def get_top_threats(self, limit=5):
        """Get the top threats based on severity and frequency"""
        if not self.alerts_data:
            return []
        
        # Convert to pandas DataFrame
        df = pd.DataFrame(self.alerts_data)
        
        # Assign numeric values to severity levels
        severity_map = {'high': 3, 'medium': 2, 'low': 1}
        df['severity_score'] = df['severity'].map(severity_map)
        
        # Group by detection_type and calculate metrics
        grouped = df.groupby('detection_type').agg({
            'severity_score': 'mean',
            'id': 'count'
        }).reset_index()
        
        # Sort by severity score and count
        grouped['combined_score'] = grouped['severity_score'] * np.log1p(grouped['id'])
        top_threats = grouped.sort_values('combined_score', ascending=False).head(limit)
        
        return top_threats.to_dict(orient='records')
