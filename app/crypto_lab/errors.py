"""Deliberately content-free internal errors for the crypto lab."""


class CapacityError(Exception):
    """The local key store or concurrency limit is full."""


class DecryptionError(Exception):
    """An envelope cannot be authenticated or recovered."""
