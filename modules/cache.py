import time
import logging
import functools
import json
import os

class SimpleCache:
    def __init__(self, max_size=100, ttl=300):
        self.cache = {}
        self.max_size = max_size
        self.default_ttl = ttl  # Default TTL in seconds
        self.logger = logging.getLogger("Cache")
    
    def get(self, key):
        """Get a value from the cache"""
        cache_item = self.cache.get(key)
        
        if cache_item is None:
            return None
        
        # Check if the item has expired
        if time.time() > cache_item['expires']:
            self.cache.pop(key, None)
            return None
        
        # Update access time for LRU eviction
        cache_item['last_access'] = time.time()
        return cache_item['value']
    
    def set(self, key, value, ttl=None):
        """Set a value in the cache with a time-to-live"""
        if ttl is None:
            ttl = self.default_ttl
        
        # Evict items if the cache is full
        if len(self.cache) >= self.max_size:
            self._evict()
        
        self.cache[key] = {
            'value': value,
            'expires': time.time() + ttl,
            'last_access': time.time()
        }
    
    def _evict(self):
        """Evict least recently used items from the cache"""
        if not self.cache:
            return
        
        # Sort by last access time and remove the oldest item
        items = sorted(self.cache.items(), key=lambda x: x[1]['last_access'])
        if items:
            oldest_key = items[0][0]
            self.cache.pop(oldest_key)
    
    def clear(self):
        """Clear the entire cache"""
        self.cache = {}
    
    def cached(self, ttl=None):
        """Decorator to cache function results"""
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # Create a cache key based on function name and arguments
                key_parts = [func.__name__]
                key_parts.extend([str(arg) for arg in args])
                key_parts.extend([f"{k}={v}" for k, v in sorted(kwargs.items())])
                cache_key = ":".join(key_parts)
                
                # Try to get from cache
                cached_value = self.get(cache_key)
                if cached_value is not None:
                    self.logger.debug(f"Cache hit for {cache_key}")
                    return cached_value
                
                # If not in cache, call the function
                self.logger.debug(f"Cache miss for {cache_key}")
                result = func(*args, **kwargs)
                
                # Store in cache
                self.set(cache_key, result, ttl)
                return result
            return wrapper
        return decorator

# Initialize a global cache instance
cache = SimpleCache()
