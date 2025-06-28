import re
import ipaddress
import validators as val
import logging

class InputValidator:
    def __init__(self):
        self.logger = logging.getLogger("InputValidator")
    
    def validate_email(self, email):
        """Validate email format"""
        try:
            return val.email(email)
        except Exception as e:
            self.logger.error(f"Error validating email {email}: {str(e)}")
            return False
    
    def validate_ip(self, ip_address):
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    def validate_url(self, url):
        """Validate URL format"""
        try:
            return val.url(url)
        except Exception:
            return False
    
    def sanitize_input(self, input_string, max_length=1000):
        """Sanitize input by removing dangerous characters"""
        if not input_string:
            return ""
        
        # Truncate long inputs
        if len(input_string) > max_length:
            input_string = input_string[:max_length]
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>\'";]', '', input_string)
        return sanitized
    
    def validate_config(self, config, schema):
        """Validate configuration against a schema"""
        if not isinstance(config, dict) or not isinstance(schema, dict):
            return False, "Configuration or schema is not a dictionary"
        
        missing_fields = []
        invalid_fields = []
        
        for field, field_schema in schema.items():
            # Check required fields
            if field_schema.get('required', False) and field not in config:
                missing_fields.append(field)
                continue
            
            # Skip validation if field is not present and not required
            if field not in config:
                continue
            
            value = config[field]
            
            # Validate type
            expected_type = field_schema.get('type')
            if expected_type and not isinstance(value, self._get_type(expected_type)):
                invalid_fields.append(f"{field} (expected {expected_type})")
                continue
            
            # Validate format if specified
            format_type = field_schema.get('format')
            if format_type and not self._validate_format(value, format_type):
                invalid_fields.append(f"{field} (invalid {format_type} format)")
                continue
            
            # Validate nested objects
            if expected_type == 'object' and 'properties' in field_schema:
                if isinstance(value, dict):
                    valid, message = self.validate_config(value, field_schema['properties'])
                    if not valid:
                        invalid_fields.append(f"{field} ({message})")
            
            # Validate arrays
            if expected_type == 'array' and 'items' in field_schema:
                if isinstance(value, list):
                    for item in value:
                        if field_schema['items'].get('type') == 'object':
                            valid, message = self.validate_config(
                                item, field_schema['items'].get('properties', {})
                            )
                            if not valid:
                                invalid_fields.append(f"{field} item ({message})")
                        elif not isinstance(item, self._get_type(field_schema['items'].get('type'))):
                            invalid_fields.append(f"{field} item (wrong type)")
        
        if missing_fields or invalid_fields:
            message = ""
            if missing_fields:
                message += f"Missing required fields: {', '.join(missing_fields)}. "
            if invalid_fields:
                message += f"Invalid fields: {', '.join(invalid_fields)}."
            return False, message.strip()
        
        return True, "Configuration is valid"
    
    def _get_type(self, type_name):
        """Convert type name to Python type"""
        type_map = {
            'string': str,
            'integer': int,
            'number': (int, float),
            'boolean': bool,
            'object': dict,
            'array': list
        }
        return type_map.get(type_name, object)
    
    def _validate_format(self, value, format_type):
        """Validate specific formats"""
        if format_type == 'email':
            return self.validate_email(value)
        elif format_type == 'ip':
            return self.validate_ip(value)
        elif format_type == 'url':
            return self.validate_url(value)
        return True
