"""Synthetic anomaly lab: methodology, API and isolated workers."""
import asyncio
from collections import Counter
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from app.crypto_lab.anomaly_lab import generator
from app.crypto_lab.anomaly_lab.evaluation import evaluate
from app.crypto_lab.anomaly_lab.features import extract
from app.crypto_lab.anomaly_lab.runner import Coordinator, Busy, NotFound
from app.crypto_lab.attacks.runner import Coordinator as AttackCoordinator


class SyntheticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = generator.generate()

    def test_reproducible_and_separated(self):
        self.assertEqual(self.data, generator.generate())
        rows = self.data['rows']
        self.assertEqual(Counter(r['partition'] for r in rows), {'train': 4200, 'calibration': 600,
                                                                  'validation': 600, 'test': 600})
        self.assertEqual(len({r['episode_id'] for r in rows}), 6000)
        self.assertEqual(len({r['synthetic_stream_id'] for r in rows}), 6000)
        self.assertTrue(all(r['event_count'] <= 32 for r in rows))
        for part in ('train', 'calibration', 'validation', 'test'):
            labels = Counter(r['label'] for r in rows if r['partition'] == part)
            self.assertEqual(labels[1], 60 if part in ('validation', 'test') else 0)
        dates = [r['window_start'] for r in rows]
        self.assertEqual(dates, sorted(dates))
        self.assertEqual(len(set(dates)), 6000)
        self.assertLess(len(json.dumps(self.data).encode()), 5 * 1024 * 1024)

    def test_features_denominators(self):
        self.assertEqual(extract([], 2), [0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0])
        events = [{'event': 'LOGIN_FAILURE', 'route': '/synthetic/login'},
                  {'event': 'ADMIN_ACCESS', 'route': '/synthetic/admin'}]
        values = extract(events, 2)
        self.assertEqual(values[6], 1)
        self.assertEqual(values[8], 0)
        self.assertEqual(values[-1], 1)

    def test_worker_denies_socket_creation(self):
        script = ("from app.crypto_lab.anomaly_lab.worker import disable_network; "
                  "disable_network(); import socket; socket.socket()")
        result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('PermissionError', result.stderr)

    def test_confusion_and_undefined(self):
        result = evaluate([0, 0, 1, 1], [False, True, False, True],
                          [None, None, 'login_failures', 'access_denied'])
        self.assertEqual(result['matrix'], [[1, 1], [1, 1]])
        for metric in ('precision', 'recall', 'f1', 'false_positive_rate'):
            self.assertEqual(result[metric]['value'], .5)
        empty = evaluate([0], [False], [None])
        self.assertIsNone(empty['precision']['value'])
        self.assertEqual(empty['precision']['undefined_reason'], 'zero_denominator')

    def test_training_does_not_use_test_labels(self):
        from app.crypto_lab.anomaly_lab.models import analyse
        with patch('app.crypto_lab.anomaly_lab.models.evaluate', return_value={}):
            original = analyse(self.data)
            altered = dict(self.data, rows=[dict(r, label=1-r['label']) if r['partition'] == 'test' else r
                                            for r in self.data['rows']])
            modified = analyse(altered)
        for method in ('isolation_forest', 'robust_baseline'):
            self.assertEqual(original['methods'][method]['threshold'], modified['methods'][method]['threshold'])


class WorkerTests(unittest.IsolatedAsyncioTestCase):
    async def test_full_pipeline_and_shared_slot(self):
        a, b = Coordinator(), AttackCoordinator()
        started = a.start('owner', 'dataset', 120)
        with self.assertRaises(Exception):
            b.start('other', 'brute_force', 120)
        await a.task
        job = a.read('owner', a.jobs, started['job_id'])
        self.assertEqual(job['status'], 'completed')
        self.assertEqual(job['metadata']['window_count'], 6000)
        with self.assertRaises(NotFound): a.read('other', a.jobs, started['job_id'])
        # Shift only the synthetic test clock state; actual endpoints enforce the wait.
        a.user_starts.clear()
        run = a.start('owner', 'run', 120, job['dataset_id'])
        await a.task
        done = a.read('owner', a.jobs, run['job_id'])
        self.assertEqual(done['status'], 'completed')
        result = a.read('owner', a.results, done['result_id'])['result']
        self.assertEqual(result['scope'], 'synthetic_only')
        for model in ('isolation_forest', 'robust_baseline'):
            metrics = result['methods'][model]['partitions']['test']
            self.assertEqual(metrics['normal_support'], 540)
            self.assertEqual(metrics['anomaly_support'], 60)
        self.assertIsNone(a.process)
        self.assertFalse(a.has_slot)

    async def test_timeout_and_close(self):
        a = Coordinator()
        started = a.start('owner', 'dataset', .001)
        await a.task
        self.assertEqual(a.read('owner', a.jobs, started['job_id'])['status'], 'timed_out')
        self.assertFalse(a.has_slot)
        a.user_starts.clear()
        started = a.start('owner', 'dataset', 30)
        await asyncio.sleep(.05)
        await a.close()
        self.assertEqual(a.read('owner', a.jobs, started['job_id'])['status'], 'failed')
        self.assertIsNone(a.process)
        self.assertFalse(a.has_slot)
