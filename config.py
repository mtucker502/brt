import os

REDIS_HOST = os.environ.get('REDIS_HOST') or '127.0.0.1'
REDIS_PORT = os.environ.get('REDIS_PORT') or None
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD') or None
CHUNK_SIZE = os.environ.get('CHUNK_SIZE') or 1000
