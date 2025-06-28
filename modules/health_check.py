import psutil
import logging
import os
import time
from datetime import datetime

class HealthChecker:
    def __init__(self):
        self.logger = logging.getLogger("HealthCheck")
        self.start_time = time.time()
        self.last_check = {}
    
    def check_system_health(self):
        """Perform system health checks and return status"""
        try:
            # Check CPU usage
            cpu_usage = psutil.cpu_percent(interval=1)
            
            # Check memory usage
            memory = psutil.virtual_memory()
            memory_usage = memory.percent
            
            # Check disk usage
            disk = psutil.disk_usage('/')
            disk_usage = disk.percent
            
            # Check logs directory
            logs_path = os.path.join(os.getcwd(), 'logs')
            logs_exist = os.path.exists(logs_path)
            
            # Check config directory
            config_path = os.path.join(os.getcwd(), 'config')
            config_exist = os.path.exists(config_path)
            
            # Calculate uptime
            uptime_seconds = time.time() - self.start_time
            uptime = self._format_uptime(uptime_seconds)
            
            # Determine status
            overall_status = "healthy"
            if cpu_usage > 90 or memory_usage > 90 or disk_usage > 90:
                overall_status = "warning"
            
            if not logs_exist or not config_exist:
                overall_status = "error"
            
            health_data = {
                "status": overall_status,
                "timestamp": datetime.now().isoformat(),
                "uptime": uptime,
                "system": {
                    "cpu_usage": cpu_usage,
                    "memory_usage": memory_usage,
                    "disk_usage": disk_usage
                },
                "components": {
                    "logs_directory": logs_exist,
                    "config_directory": config_exist
                }
            }
            
            self.last_check = health_data
            return health_data
            
        except Exception as e:
            self.logger.error(f"Error checking system health: {str(e)}")
            return {
                "status": "error",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            }
    
    def _format_uptime(self, seconds):
        """Format uptime in a human-readable way"""
        days, remainder = divmod(seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        parts = []
        if days > 0:
            parts.append(f"{int(days)} days")
        if hours > 0:
            parts.append(f"{int(hours)} hours")
        if minutes > 0:
            parts.append(f"{int(minutes)} minutes")
        if seconds > 0 or not parts:
            parts.append(f"{int(seconds)} seconds")
        
        return ", ".join(parts)
    
    def get_last_check(self):
        """Return the last health check result"""
        if not self.last_check:
            return self.check_system_health()
        return self.last_check
