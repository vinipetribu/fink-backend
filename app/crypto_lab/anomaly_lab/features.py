"""Fixed window features; no identities, labels, or future observations."""
from collections import Counter

FEATURE_NAMES = ('events', 'requests', 'login_success', 'login_failure', 'access_denied',
                 'admin_access', 'failure_ratio', 'no_login_denominator', 'denied_ratio',
                 'no_event_denominator', 'route_categories', 'admin_off_hours')


def extract(events, hour):
    counts = Counter(event['event'] for event in events)
    n = len(events)
    attempts = counts['LOGIN_FAILURE'] + counts['LOGIN_SUCCESS']
    return [n, counts['SYNTHETIC_REQUEST_OBSERVED'], counts['LOGIN_SUCCESS'], counts['LOGIN_FAILURE'],
            counts['ACCESS_DENIED'], counts['ADMIN_ACCESS'],
            counts['LOGIN_FAILURE'] / attempts if attempts else 0.0, int(not attempts),
            counts['ACCESS_DENIED'] / n if n else 0.0, int(not n),
            len({event['route'] for event in events}),
            sum(event['event'] == 'ADMIN_ACCESS' for event in events) if hour < 8 or hour >= 18 else 0]
