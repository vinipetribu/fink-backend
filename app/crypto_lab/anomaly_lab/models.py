"""Normal-only Isolation Forest and robust statistical baseline."""
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from .evaluation import evaluate
from .features import FEATURE_NAMES

PARAMETERS = {'n_estimators': 100, 'max_samples': 256, 'contamination': 'auto',
              'max_features': 1.0, 'bootstrap': False, 'n_jobs': 1, 'random_state': 42}


def analyse(data):
    rows = data['rows']
    parts = {name: [r for r in rows if r['partition'] == name]
             for name in ('train', 'calibration', 'validation', 'test')}
    if len(rows) != 6000 or any(r['label'] != 0 for name in ('train', 'calibration') for r in parts[name]):
        raise ValueError('Invalid synthetic dataset')
    matrices = {name: np.asarray([r['features'] for r in subset], dtype=float) for name, subset in parts.items()}
    model = IsolationForest(**PARAMETERS)
    model.fit(matrices['train'])
    median = np.median(matrices['train'], axis=0)
    mad = np.median(np.abs(matrices['train'] - median), axis=0)
    scale = np.where(mad > 0, 1.4826 * mad, 1.0)
    scorers = {'isolation_forest': lambda x: -model.score_samples(x),
               'robust_baseline': lambda x: np.max(np.abs((x - median) / scale), axis=1)}
    methods = {}
    for name, score in scorers.items():
        calibration = score(matrices['calibration'])
        threshold = float(np.quantile(calibration, .99, method='linear'))
        partition_metrics = {}
        for part, x in matrices.items():
            scores = score(x)
            predictions = scores > threshold
            subset = parts[part]
            partition_metrics[part] = evaluate([r['label'] for r in subset], predictions.tolist(),
                                                [r['family'] for r in subset])
        methods[name] = {'threshold': threshold, 'quantile': .99, 'quantile_method': 'linear',
                         'comparison': 'score > threshold', 'calibration_ties': int(np.sum(calibration == threshold)),
                         'calibration_alert_fraction': float(np.mean(calibration > threshold)),
                         'partitions': partition_metrics}
    return {'schema_version': 1, 'scope': 'synthetic_only', 'profile': data['profile'], 'seed': data['seed'],
            'library_versions': {'scikit_learn': sklearn.__version__, 'numpy': np.__version__},
            'features': list(FEATURE_NAMES), 'model_parameters': PARAMETERS,
            'baseline': {'center': 'median', 'scale': '1.4826 * MAD; zero MAD replaced by 1'},
            'window_seconds': 300, 'event_count': data['event_count'],
            'partition_sizes': {name: len(value) for name, value in parts.items()}, 'methods': methods,
            'note': 'Synthetic labels only; anomaly scores are not attack probabilities.'}
