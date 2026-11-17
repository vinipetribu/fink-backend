"""Process-local queue for explicitly sanitized laboratory events."""
from app.crypto_lab.event_store.queue import EventQueue

events = EventQueue()
