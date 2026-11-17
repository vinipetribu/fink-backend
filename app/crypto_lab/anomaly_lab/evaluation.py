"""Metrics with explicit denominators and undefined values."""


def ratio(numerator, denominator):
    return {'value': numerator / denominator if denominator else None, 'numerator': numerator,
            'denominator': denominator, 'undefined_reason': None if denominator else 'zero_denominator'}


def evaluate(labels, predicted, families):
    tp = sum(y == 1 and p for y, p in zip(labels, predicted))
    fn = sum(y == 1 and not p for y, p in zip(labels, predicted))
    fp = sum(y == 0 and p for y, p in zip(labels, predicted))
    tn = sum(y == 0 and not p for y, p in zip(labels, predicted))
    group = {}
    for family in ('login_failures', 'access_denied', 'request_volume', 'admin_activity'):
        support = sum(y == 1 and f == family for y, f in zip(labels, families))
        detected = sum(y == 1 and f == family and p for y, f, p in zip(labels, families, predicted))
        group[family] = {'support': support, 'detected': detected, 'recall': ratio(detected, support)}
    return {'matrix': [[tn, fp], [fn, tp]], 'matrix_axes': 'actual_rows_predicted_columns',
            'TN': tn, 'FP': fp, 'FN': fn, 'TP': tp, 'normal_support': tn + fp,
            'anomaly_support': tp + fn, 'alerts': tp + fp,
            'prevalence': ratio(tp + fn, len(labels)), 'precision': ratio(tp, tp + fp),
            'recall': ratio(tp, tp + fn), 'f1': ratio(2 * tp, 2 * tp + fp + fn),
            'false_positive_rate': ratio(fp, fp + tn), 'families': group}
