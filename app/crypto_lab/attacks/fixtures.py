"""Public, deterministic synthetic input catalogue; never contains user data."""

CATALOG = "synthetic-v1"
BLOCKS = tuple(i.to_bytes(8, "big") for i in range(32))
REPEATED = (bytes(8),) * 4
DISTINCT = (bytes(8), bytes(range(8)), b"ABCDEFGH", b"12345678")
