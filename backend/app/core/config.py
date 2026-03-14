"""Shared configuration: rate limiter, timeouts, and environment settings."""

import logging
import os

from slowapi import Limiter
from slowapi.util import get_remote_address

logger = logging.getLogger(__name__)

# Match timeout in seconds (0 or empty = no timeout)
_timeout_env = os.environ.get("MATCH_TIMEOUT", "30")
MATCH_TIMEOUT: float | None = float(_timeout_env) if _timeout_env and float(_timeout_env) > 0 else None

# Rate limiter — keyed by client IP.
# Uses Redis when REDIS_URL is set (shared across workers/containers),
# falls back to in-memory storage for local development.
_redis_url = os.environ.get("REDIS_URL", "")
if _redis_url:
    limiter = Limiter(key_func=get_remote_address, storage_uri=_redis_url)
    logger.info("Rate limiter using Redis backend: %s", _redis_url)
else:
    limiter = Limiter(key_func=get_remote_address)
    logger.info("Rate limiter using in-memory backend (set REDIS_URL for shared rate limiting)")
