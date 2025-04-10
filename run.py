#!/usr/bin/env python3
import os
import sys
from init_config import initialize_directories_and_configs

def main():
    print("Starting Threat Detection System...")
    
    # Initialize directories and configuration
    initialize_directories_and_configs()
    
    # Import the Flask app only after ensuring directories exist
    from app import app
    
    print("\nStarting web server...")
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)
