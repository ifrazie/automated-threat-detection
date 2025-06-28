import os
import json
import logging

def initialize_directories_and_configs():
    """Create necessary directories and default configuration files 
    if they don't exist.
    """
    # Create necessary directories
    directories = ['logs', 'config']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✓ Created directory: {directory}")
    
    # Default configurations
    default_configs = {
        'config/log_sources.json': [
            {
                "type": "file",
                "path": "/var/log/auth.log",
                "format": "syslog"
            },
            {
                "type": "api",
                "url": "https://api.example.com/logs",
                "auth": {
                    "type": "bearer",
                    "token": "your-api-token"
                }
            }
        ],
        'config/network_sources.json': [
            {
                "type": "pcap",
                "interface": "eth0"
            },
            {
                "type": "netflow",
                "collector": "10.0.0.1",
                "port": 9995
            }
        ],
        'config/endpoint_sources.json': [
            {
                "type": "agent",
                "url": "https://endpoint-api.example.com/events",
                "auth": {
                    "type": "api_key",
                    "key": "your-api-key"
                }
            }
        ],
        'config/detection_rules.json': {
            "log_rules": [
                {
                    "pattern": "failed login",
                    "severity": "medium"
                },
                {
                    "pattern": "unauthorized access",
                    "severity": "high"
                }
            ],
            "network_rules": [
                {
                    "source_ip": "any",
                    "dest_port": 22,
                    "count_threshold": 10,
                    "time_window": 60,
                    "severity": "medium"
                }
            ],
            "endpoint_rules": [
                {
                    "process": "powershell.exe",
                    "args_pattern": "-enc",
                    "severity": "high"
                }
            ]
        },
        'config/response_playbooks.json': {
            "log": [
                {
                    "severity": "high",
                    "actions": [
                        {
                            "type": "alert",
                            "channel": "email",
                            "recipients": ["security@example.com"]
                        },
                        {
                            "type": "ticket",
                            "system": "jira",
                            "priority": "high"
                        }
                    ]
                },
                {
                    "severity": "medium",
                    "actions": [
                        {
                            "type": "alert",
                            "channel": "slack",
                            "channel_id": "security-alerts"
                        }
                    ]
                }
            ],
            "network": [
                {
                    "severity": "high",
                    "actions": [
                        {
                            "type": "block_ip",
                            "duration": 3600
                        },
                        {
                            "type": "alert",
                            "channel": "email",
                            "recipients": ["security@example.com"]
                        }
                    ]
                }
            ],
            "endpoint": [
                {
                    "severity": "high",
                    "actions": [
                        {
                            "type": "isolate_host"
                        },
                        {
                            "type": "alert",
                            "channel": "sms",
                            "recipients": ["+1234567890"]
                        }
                    ]
                }
            ]
        }
    }
    
    # Create default config files if they don't exist
    for file_path, config in default_configs.items():
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                json.dump(config, f, indent=2)
            print(f"✓ Created default configuration: {file_path}")
        else:
            print(f"✓ Configuration already exists: {file_path}")

if __name__ == "__main__":
    print("Initializing Threat Detection System...")
    initialize_directories_and_configs()
    print("\nSetup complete! You can now run 'python app.py' to start the application.")
