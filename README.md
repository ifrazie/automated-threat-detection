# AI-Powered Threat Detection & Incident Response

An automated security monitoring and incident response system that uses AI to detect anomalies in logs, network traffic, and endpoint activities.

## Features

- **Data Ingestion**: Collect security-relevant data from logs, network traffic, and endpoint activities
- **AI Anomaly Detection**: Identify unusual patterns using both rule-based and machine learning approaches
- **Automated Response**: Execute predefined playbooks to contain and mitigate threats
- **Security Dashboard**: Real-time monitoring and management interface

## Installation

1. Clone the repository:
   ```
   bash
   git clone https://github.com/yourusername/automated-threat-detection.git
   cd automated-threat-detection
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Create necessary directories:
   ```
   mkdir -p logs config
   ```

5. Create configuration files (examples will be generated on first run if not present):
   - `config/log_sources.json`
   - `config/network_sources.json`
   - `config/endpoint_sources.json`
   - `config/detection_rules.json`
   - `config/response_playbooks.json`

## Usage

1. Start the application:
   ```
   python app.py
   ```

2. Access the web interface:
   - Open a browser and navigate to `http://localhost:5000/`
   - The dashboard is available at `http://localhost:5000/dashboard`

## Configuration

### Data Sources

Configure your data sources in the respective JSON files:

```json
// config/log_sources.json example
[
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
]
```

### Detection Rules

Define detection rules in `config/detection_rules.json`:

```json
{
  "log_rules": [
    {
      "pattern": "failed login",
      "severity": "medium"
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
}
```

### Response Playbooks

Define automated response actions in `config/response_playbooks.json`:

```json
{
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
    }
  ]
}
```

## Architecture

The system is built on a modular architecture:

1. **Data Ingestion Module**: Collects and normalizes data from various sources
2. **Anomaly Detection Module**: Processes data to identify suspicious activities
3. **Incident Response Module**: Executes response actions based on detected threats
4. **Web Dashboard**: Provides visualization and management interface

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
