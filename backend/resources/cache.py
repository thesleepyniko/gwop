import datetime
import json

class Cache:

    """Class to act as a cache
    
    Methods:
    Cache.get(key) -> dict

        returns the key if available
        
    Cache.set(key, value, ttl=60) -> None

        sets a key to a value. ttl expected in seconds.
        if ttl unset, defaults to 1 minute"""
    
    def __init__(self):
        self._store = {}
    
    def get(self, key):
        entry = self._store.get(key, None)
        if not entry:
            return None
        value, expire = entry
        if expire < datetime.datetime.now(datetime.timezone.utc):
            del self._store[key]
            return None
        return json.loads(value)
    
    def set(self, key, value, ttl=60):
        expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=ttl)
        self._store[key] = (json.dumps(value), expire)