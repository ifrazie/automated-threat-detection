import logging
import json
import time
import os
import requests
from datetime import datetime

class IncidentResponder:
    def __init__(self):
        self.logger = logging.getLogger("IncidentResponse")
        self.playbooks = self._load_playbooks('config/response_playbooks.json')
        self.incidents = []
        self.stats = {
            'incidents_handled': 0,
            'auto_resolved': 0,
            'manual_resolved': 0,
            'failed_responses': 0
        }
    
    def _load_playbooks(self, playbooks_path):
        """Load response playbooks from a JSON file"""
        try:
            if os.path.exists(playbooks_path):
                with open(playbooks_path, 'r') as f:
                    return json.load(f)
            else:
                self.logger.warning(f"Playbooks file {playbooks_path} not found, using defaults")
                return self._get_default_playbooks()
        except Exception as e:
            self.logger.error(f"Error loading playbooks from {playbooks_path}: {str(e)}")
            return self._get_default_playbooks()
    
    def _get_default_playbooks(self):
        """Return default playbooks if no configuration is found"""
        return {
            "log": [
                {
                    "severity": "high",
                    "actions": [
                        {"type": "alert", "channel": "email", "recipients": ["security@example.com"]},
                        {"type": "ticket", "system": "jira", "priority": "high"}
                    ]
                },
                {
                    "severity": "medium",
                    "actions": [
                        {"type": "alert", "channel": "slack", "channel_id": "security-alerts"}
                    ]
                }
            ],
            "network": [
                {
                    "severity": "high",
                    "actions": [
                        {"type": "block_ip", "duration": 3600},
                        {"type": "alert", "channel": "email", "recipients": ["security@example.com"]}
                    ]
                }
            ],
            "endpoint": [
                {
                    "severity": "high",
                    "actions": [
                        {"type": "isolate_host"},
                        {"type": "alert", "channel": "sms", "recipients": ["+1234567890"]}
                    ]
                }
            ]
        }
    
    def handle_incidents(self, anomalies):
        """Handle detected incidents using appropriate playbooks"""
        self.logger.info(f"Handling {len(anomalies)} incidents")
        
        for anomaly in anomalies:
            incident_id = anomaly['id']
            source = anomaly['source']
            severity = anomaly['severity']
            
            # Find matching playbook
            matching_playbooks = [p for p in self.playbooks.get(source, []) 
                                if p.get('severity') == severity]
            
            if matching_playbooks:
                playbook = matching_playbooks[0]
                response_actions = playbook.get('actions', [])
                
                # Record the incident
                incident = {
                    'id': incident_id,
                    'anomaly': anomaly,
                    'playbook': playbook,
                    'status': 'in_progress',
                    'start_time': datetime.now().isoformat(),
                    'actions_taken': [],
                    'end_time': None
                }
                
                # Execute actions
                for action in response_actions:
                    try:
                        result = self._execute_action(action, anomaly)
                        incident['actions_taken'].append({
                            'action': action,
                            'time': datetime.now().isoformat(),
                            'result': result,
                            'status': 'completed'
                        })
                    except Exception as e:
                        self.logger.error(f"Error executing action {action}: {str(e)}")
                        incident['actions_taken'].append({
                            'action': action,
                            'time': datetime.now().isoformat(),
                            'result': str(e),
                            'status': 'failed'
                        })
                
                # Update incident status
                if all(a['status'] == 'completed' for a in incident['actions_taken']):
                    incident['status'] = 'resolved'
                    incident['end_time'] = datetime.now().isoformat()
                    self.stats['auto_resolved'] += 1
                else:
                    incident['status'] = 'partially_resolved'
                
                self.incidents.append(incident)
                self.stats['incidents_handled'] += 1
            else:
                # No matching playbook found, create incident but take no action
                self.logger.warning(f"No matching playbook for {source} incident with severity {severity}")
                incident = {
                    'id': incident_id,
                    'anomaly': anomaly,
                    'playbook': None,
                    'status': 'new',
                    'start_time': datetime.now().isoformat(),
                    'actions_taken': [],
                    'end_time': None
                }
                self.incidents.append(incident)
                self.stats['incidents_handled'] += 1
    
    def _execute_action(self, action, anomaly):
        """Execute a specific response action"""
        action_type = action.get('type', '')
        
        if action_type == 'alert':
            return self._send_alert(action, anomaly)
        elif action_type == 'block_ip':
            return self._block_ip(action, anomaly)
        elif action_type == 'isolate_host':
            return self._isolate_host(action, anomaly)
        elif action_type == 'ticket':
            return self._create_ticket(action, anomaly)
        else:
            raise ValueError(f"Unknown action type: {action_type}")
    
    def _send_alert(self, action, anomaly):
        """Send an alert notification"""
        channel = action.get('channel', '')
        
        if channel == 'email':
            # Simulate sending email
            recipients = action.get('recipients', [])
            self.logger.info(f"Sending email alert to {recipients} for incident {anomaly['id']}")
            return {"status": "sent", "recipients": recipients}
        
        elif channel == 'slack':
            # Simulate sending to Slack
            slack_channel = action.get('channel_id', '')
            self.logger.info(f"Sending Slack alert to {slack_channel} for incident {anomaly['id']}")
            return {"status": "sent", "channel": slack_channel}
        
        elif channel == 'sms':
            # Simulate sending SMS
            phone_numbers = action.get('recipients', [])
            self.logger.info(f"Sending SMS alert to {phone_numbers} for incident {anomaly['id']}")
            return {"status": "sent", "recipients": phone_numbers}
        
        else:
            raise ValueError(f"Unknown alert channel: {channel}")
    
    def _block_ip(self, action, anomaly):
        """Block an IP address"""
        ip = anomaly.get('details', {}).get('source_ip', 'unknown')
        duration = action.get('duration', 3600)  # Default 1 hour
        
        self.logger.info(f"Blocking IP {ip} for {duration} seconds due to incident {anomaly['id']}")
        
        # In a real implementation, this would interface with firewalls or security systems
        return {"status": "blocked", "ip": ip, "duration": duration}
    
    def _isolate_host(self, action, anomaly):
        """Isolate a host from the network"""
        host = anomaly.get('details', {}).get('hostname', 'unknown')
        
        self.logger.info(f"Isolating host {host} due to incident {anomaly['id']}")
        
        # In a real implementation, this would interface with EDR or network controls
        return {"status": "isolated", "host": host}
    
    def _create_ticket(self, action, anomaly):
        """Create a ticket in a ticketing system"""
        system = action.get('system', 'default')
        priority = action.get('priority', 'medium')
        
        self.logger.info(f"Creating {priority} ticket in {system} for incident {anomaly['id']}")
        
        # In a real implementation, this would interface with ticketing systems like JIRA, ServiceNow, etc.
        ticket_id = f"INC-{int(time.time())}"
        return {"status": "created", "ticket_id": ticket_id, "system": system}
    
    def manual_action(self, incident_id, action):
        """Allow manual response actions for incidents"""
        matching_incidents = [i for i in self.incidents if i['id'] == incident_id]
        
        if not matching_incidents:
            return {"status": "error", "message": "Incident not found"}
        
        incident = matching_incidents[0]
        
        try:
            action_config = json.loads(action) if isinstance(action, str) else action
            result = self._execute_action(action_config, incident['anomaly'])
            
            incident['actions_taken'].append({
                'action': action_config,
                'time': datetime.now().isoformat(),
                'result': result,
                'status': 'completed',
                'manual': True
            })
            
            # Update incident status
            if incident['status'] != 'resolved':
                incident['status'] = 'manually_handled'
                incident['end_time'] = datetime.now().isoformat()
                self.stats['manual_resolved'] += 1
            
            return {"status": "success", "result": result}
        except Exception as e:
            self.logger.error(f"Error executing manual action on incident {incident_id}: {str(e)}")
            self.stats['failed_responses'] += 1
            return {"status": "error", "message": str(e)}
    
    def get_resolution_stats(self):
        """Return incident resolution statistics"""
        return self.stats
