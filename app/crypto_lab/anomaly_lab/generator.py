"""Bounded synthetic windows. Never reads application events or external data."""
import random
from datetime import datetime, timedelta, timezone
from .features import extract

PROFILE = 'synthetic-security-v1'
SEED = 20261116
FAMILIES = ('login_failures', 'access_denied', 'request_volume', 'admin_activity')
SPECS = (('train', 4200, 0), ('calibration', 600, 0), ('validation', 600, 60), ('test', 600, 60))
TYPES = {'LOGIN_SUCCESS': ('SUCCESS', 'POST', '/synthetic/login'),
         'LOGIN_FAILURE': ('FAILURE', 'POST', '/synthetic/login'),
         'ACCESS_DENIED': ('DENIED', 'GET', '/synthetic/restricted'),
         'ADMIN_ACCESS': ('ALLOWED', 'GET', '/synthetic/admin'),
         'SYNTHETIC_REQUEST_OBSERVED': ('SUCCESS', 'GET', '/synthetic/general')}


def windows():
    """Yield distinct streams and episodes with partition-separated UTC windows."""
    epoch = datetime(2020, 1, 1, tzinfo=timezone.utc)
    offset = 0
    for partition_index, (partition, total, anomalous) in enumerate(SPECS):
        rng = random.Random(SEED + partition_index * 100003)
        flags = [0] * (total - anomalous) + [1] * anomalous
        rng.shuffle(flags)
        families = list(FAMILIES) * (anomalous // len(FAMILIES))
        rng.shuffle(families)
        family_iter = iter(families)
        for i, label in enumerate(flags):
            family = next(family_iter) if label else None
            start = epoch + timedelta(minutes=5 * (offset + i))
            # Normal and anomalous distributions overlap; outcomes are synthetic labels.
            counts = [rng.randint(0, 4), rng.randint(0, 3), rng.randint(0, 3),
                      rng.randint(0, 3), rng.randint(1, 12)]
            if label:
                index = {'login_failures': 1, 'access_denied': 2, 'admin_activity': 3, 'request_volume': 4}[family]
                counts[index] += rng.randint(2, 8) if partition == 'validation' else rng.randint(3, 9)
            event_types = list(TYPES)
            events = []
            for kind, count in zip(event_types, counts):
                for _ in range(count):
                    result, method, route = TYPES[kind]
                    at = start + timedelta(seconds=rng.randrange(300))
                    events.append({'schema_version': 1, 'timestamp': at.isoformat(), 'event': kind,
                                   'result': result, 'method': method, 'route': route})
            rng.shuffle(events)
            events = events[:32]
            yield {'partition': partition, 'episode_id': f'{partition}-{i}',
                   'synthetic_stream_id': f'{partition}-{i}', 'window_start': start.isoformat(),
                   'label': label, 'family': family, 'features': extract(events, start.hour), 'event_count': len(events)}
        offset += total + 1


def generate():
    rows = list(windows())
    return {'profile': PROFILE, 'seed': SEED, 'rows': rows,
            'window_seconds': 300, 'window_count': len(rows),
            'event_count': sum(r['event_count'] for r in rows)}
