"""One non-blocking per-process slot shared by CPU-intensive lab jobs."""
from threading import Lock

slot = Lock()
