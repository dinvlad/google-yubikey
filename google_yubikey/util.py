"""
Utility classes
"""

from datetime import datetime, timedelta
from typing import Any


class CachedItem():
    """ Holds a cached item """

    DEFAULT_LIFETIME_SEC = 10

    def __init__(self, key: Any = None, value: Any = None,
                 timeout_sec=DEFAULT_LIFETIME_SEC):
        self.key = key
        self.value = value
        self._time = datetime.now()
        self._timeout = timedelta(seconds=timeout_sec)

    def expired(self, key: Any = None):
        """ Determines if the token needs to be refreshed """
        return not self.value or (
            self.key == key and
            self._time < datetime.now() - self._timeout
        )
