"""Best-effort, bounded persistence of aggregate synthetic anomaly runs."""
import asyncio
import json
from uuid import UUID

from sqlalchemy import text

from app.core.settings import settings
from app.crypto_lab.anomaly_lab.generator import PROFILE
from app.shared.database import engine

PARTITIONS = ('train', 'calibration', 'validation', 'test')
METHODS = ('isolation_forest', 'robust_baseline')
FAMILIES = ('login_failures', 'access_denied', 'request_volume', 'admin_activity')
METRICS = ('matrix', 'matrix_axes', 'TN', 'FP', 'FN', 'TP', 'normal_support', 'anomaly_support',
           'alerts', 'prevalence', 'precision', 'recall', 'f1', 'false_positive_rate')
RATIO = ('value', 'numerator', 'denominator', 'undefined_reason')
PARAMETERS = ('n_estimators', 'max_samples', 'contamination', 'max_features', 'bootstrap', 'n_jobs', 'random_state')


def aggregate(payload):
    """Copy only documented aggregate fields, never dataset rows or arbitrary keys."""
    if not payload:
        return {}, {'schema_version': 1, 'event_count': None, 'window_count': None, 'methods': {}}
    versions = {k: payload.get('library_versions', {}).get(k) for k in ('scikit_learn', 'numpy')}
    versions['isolation_forest_parameters'] = {k: payload.get('model_parameters', {}).get(k) for k in PARAMETERS}
    baseline = payload.get('baseline', {})
    versions['baseline_parameters'] = {k: baseline.get(k) for k in ('center', 'scale')}
    sizes = {k: payload.get('partition_sizes', {}).get(k) for k in PARTITIONS}
    window_count = sum(sizes.values()) if all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in sizes.values()) else None
    methods = {}
    for method in METHODS:
        source = payload.get('methods', {}).get(method, {})
        out = {k: source.get(k) for k in ('threshold', 'quantile', 'quantile_method', 'comparison', 'calibration_ties', 'calibration_alert_fraction')}
        out['partitions'] = {}
        for part in PARTITIONS:
            item = source.get('partitions', {}).get(part, {})
            metrics = {k: item.get(k) for k in METRICS}
            for key in ('prevalence', 'precision', 'recall', 'f1', 'false_positive_rate'):
                metrics[key] = {k: (item.get(key) or {}).get(k) for k in RATIO}
            metrics['families'] = {}
            for family in FAMILIES:
                data = item.get('families', {}).get(family, {})
                metrics['families'][family] = {'support': data.get('support'), 'detected': data.get('detected'),
                                               'recall': {k: (data.get('recall') or {}).get(k) for k in RATIO}}
            out['partitions'][part] = metrics
        methods[method] = out
    return versions, {'schema_version': 1, 'event_count': payload.get('event_count'), 'window_count': window_count,
                      'partition_sizes': sizes, 'methods': methods}


def enabled():
    return (settings.crypto_lab_enabled and settings.crypto_lab_anomaly_enabled and settings.crypto_lab_event_store_enabled
            and not settings.debug and settings.environment.strip().lower() in {'development', 'test', 'testing', 'local'})


async def persist(job_id, state, started_at, finished_at, payload, *, db_engine=None):
    """Return false on failure; analysis results remain available in memory."""
    if not enabled():
        return False
    try:
        versions, metrics = aggregate(payload)
        params = {'id': UUID(job_id), 'origin': 'synthetic', 'catalog': PROFILE, 'state': state,
                  'started_at': started_at, 'finished_at': finished_at, 'processed_volume': metrics['window_count'],
                  'model_versions': json.dumps(versions, allow_nan=False), 'metrics': json.dumps(metrics, allow_nan=False)}
        async with asyncio.timeout(2):
            async with (db_engine or engine).begin() as connection:
                await connection.execute(text('''INSERT INTO lab_anomaly_runs
                    (id, origin, catalog, model_versions, state, started_at, finished_at, processed_volume, metrics_version, metrics)
                    VALUES (:id, :origin, :catalog, CAST(:model_versions AS jsonb), :state,
                            :started_at, :finished_at, :processed_volume, 1, CAST(:metrics AS jsonb))
                    ON CONFLICT (id) DO NOTHING'''), params)
        return True
    except Exception:
        return False
