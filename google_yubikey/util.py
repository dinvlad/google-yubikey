"""
Utility classes
"""

from datetime import datetime, timedelta
from typing import Any


class CachedItem():
    """ Holds a cached item """

    def __init__(self, key: Any = None, value: Any = None,
                 timeout=timedelta(seconds=10)):
        self.key = key
        self.value = value
        self._time = datetime.now()
        self._timeout = timeout

    def expired(self, key: Any = None):
        """ Determines if the token needs to be refreshed """
        return not self.value or (
            self.key == key and
            self._time < datetime.now() - self._timeout
        )
