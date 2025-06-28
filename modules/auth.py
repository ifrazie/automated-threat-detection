import functools
import hashlib
import time
import os
import json
import logging
from flask import request, jsonify

class APIKeyAuth:
    def __init__(self, config_path=None):
        self.logger = logging.getLogger("APIAuth")
        
        # Default path for API keys configuration
        if config_path is None:
            config_path = os.path.join("config", "api_keys.json")
        
        self.config_path = config_path
        self.api_keys = self._load_api_keys()
    
    def _load_api_keys(self):
        """Load API keys from configuration file"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                # Create default API key if config doesn't exist
                default_key = self._generate_api_key()
                api_keys = {
                    "keys": [
                        {
                            "key": default_key,
                            "name": "default",
                            "role": "admin",
                            "created": time.time(),
                            "expires": time.time() + (365 * 24 * 60 * 60)  # 1 year
                        }
                    ]
                }
                
                # Save the default key
                os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
                with open(self.config_path, 'w') as f:
                    json.dump(api_keys, f, indent=2)
                
                self.logger.info(f"Created default API key: {default_key}")
                return api_keys
        except Exception as e:
            self.logger.error(f"Error loading API keys: {str(e)}")
            return {"keys": []}
    
    def _generate_api_key(self):
        """Generate a random API key"""
        random_bytes = os.urandom(32)
        hash_obj = hashlib.sha256(random_bytes)
        return hash_obj.hexdigest()
    
    def require_api_key(self, f):
        """Decorator to require API key for routes"""
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            api_key = request.headers.get('X-API-Key')
            
            if not api_key:
                return jsonify({"error": "API key is required"}), 401
            
            valid_keys = [k.get("key") for k in self.api_keys.get("keys", [])]
            
            if api_key not in valid_keys:
                return jsonify({"error": "Invalid API key"}), 403
            
            # Check if key is expired
            for key_info in self.api_keys.get("keys", []):
                if key_info.get("key") == api_key:
                    if key_info.get("expires", 0) < time.time():
                        return jsonify({"error": "API key expired"}), 403
            
            return f(*args, **kwargs)
        return decorated
    
    def add_api_key(self, name, role="user", expires_days=365):
        """Add a new API key"""
        new_key = self._generate_api_key()
        
        key_info = {
            "key": new_key,
            "name": name,
            "role": role,
            "created": time.time(),
            "expires": time.time() + (expires_days * 24 * 60 * 60)
        }
        
        self.api_keys["keys"].append(key_info)
        
        with open(self.config_path, 'w') as f:
            json.dump(self.api_keys, f, indent=2)
        
        return new_key
    
    def revoke_api_key(self, key):
        """Revoke an API key"""
        self.api_keys["keys"] = [k for k in self.api_keys.get("keys", []) if k.get("key") != key]
        
        with open(self.config_path, 'w') as f:
            json.dump(self.api_keys, f, indent=2)
        
        return True
