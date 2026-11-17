"""Process-local aggregate counters; no operation contents are retained."""

from datetime import datetime, timezone
from threading import Lock


class Metrics:
    def __init__(self) -> None:
        self.since = datetime.now(timezone.utc)
        self._counts = {name: 0 for name in (
            "aes_encrypt_success", "aes_decrypt_success", "aes_decrypt_failure",
            "experimental_success", "experimental_failure",
        )}
        self._lock = Lock()

    def increment(self, name: str) -> None:
        with self._lock:
            self._counts[name] += 1

    def summary(self) -> dict:
        with self._lock:
            return {"scope": "current_process", "since": self.since, "counts": self._counts.copy()}
