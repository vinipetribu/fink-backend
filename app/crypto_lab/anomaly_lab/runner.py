"""Bounded jobs and synthetic-only ephemeral storage."""
import asyncio
from collections import deque
import json
import os
import sys
import time
from uuid import uuid4
from app.crypto_lab.heavy_capacity import slot


class Busy(Exception): pass
class RateLimited(Exception): pass
class NotFound(Exception): pass


class Coordinator:
    def __init__(self):
        self.jobs, self.datasets, self.results = {}, {}, {}
        self.starts, self.user_starts, self.reads = deque(), {}, {}
        self.active, self.task, self.process, self.has_slot = None, None, None, False

    def clean(self, now):
        for storage in (self.jobs, self.datasets, self.results):
            for key, value in list(storage.items()):
                if value.get('ended') is not None and now - value['ended'] >= 900:
                    del storage[key]
        while self.starts and now - self.starts[0] >= 3600:
            self.starts.popleft()
        self.user_starts = {k: v for k, v in self.user_starts.items() if now - v < 60}
        for owner, times in list(self.reads.items()):
            while times and now - times[0] >= 60: times.popleft()
            if not times: del self.reads[owner]

    def start(self, owner, kind, timeout, dataset_id=None):
        now = time.monotonic()
        self.clean(now)
        if sys.platform != 'linux' or not os.path.exists('/.dockerenv') or not 0 < timeout <= 120:
            raise Busy()
        if self.active is not None: raise Busy()
        if owner in self.user_starts or len(self.starts) >= 10: raise RateLimited()
        if kind == 'dataset' and self.datasets: raise Busy()
        data = None
        if kind == 'run':
            entry = self.datasets.get(dataset_id)
            if entry is None or entry['owner'] != owner: raise NotFound()
            data = entry['data']
        if not slot.acquire(blocking=False): raise Busy()
        self.has_slot = True
        while len(self.jobs) >= 10:
            del self.jobs[min(self.jobs, key=lambda k: self.jobs[k]['ended'])]
        job_id = str(uuid4())
        self.jobs[job_id] = {'owner': owner, 'job_id': job_id, 'kind': kind, 'status': 'running',
                             'schema_version': 1, 'scope': 'synthetic_only', 'started': now}
        self.active = job_id
        self.starts.append(now)
        self.user_starts[owner] = now
        self.task = asyncio.create_task(self._execute(job_id, timeout, data))
        return {'job_id': job_id, 'status': 'running'}

    def read(self, owner, storage, key):
        now = time.monotonic()
        self.clean(now)
        times = self.reads.setdefault(owner, deque())
        if len(times) >= 60: raise RateLimited()
        times.append(now)
        entry = storage.get(key)
        if not entry or entry['owner'] != owner: raise NotFound()
        return {k: v for k, v in entry.items() if k not in ('owner', 'started', 'ended', 'data')} | (
            {'duration_seconds': (entry.get('ended') or now) - entry['started']} if 'started' in entry else {})

    async def _execute(self, job_id, timeout, data):
        job = self.jobs[job_id]
        spawn = None
        try:
            async with asyncio.timeout_at(asyncio.get_running_loop().time() + max(0, timeout - (time.monotonic() - job['started']))):
                env = {'PATH': os.defpath, 'OPENBLAS_NUM_THREADS': '1', 'OMP_NUM_THREADS': '1',
                       'MKL_NUM_THREADS': '1', 'NUMEXPR_NUM_THREADS': '1'}
                spawn = asyncio.create_task(asyncio.create_subprocess_exec(
                    sys.executable, '-m', 'app.crypto_lab.anomaly_lab.worker', job['kind'], str(os.getpid()),
                    str(job['started'] + timeout), stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                    env=env, start_new_session=True))
                self.process = await asyncio.shield(spawn)
                output, _ = await self.process.communicate(data)
                limit = 5 * 1024 * 1024 if job['kind'] == 'dataset' else 65536
                if self.process.returncode or len(output) > limit: raise ValueError('Worker failed')
                payload = json.loads(output)
                if not isinstance(payload, dict): raise ValueError('Invalid result')
                now = time.monotonic()
                object_id = str(uuid4())
                if job['kind'] == 'dataset':
                    self.datasets[object_id] = {'owner': job['owner'], 'ended': now, 'data': output}
                    job['dataset_id'] = object_id
                    job['metadata'] = {'profile': payload['profile'], 'window_count': payload['window_count'],
                                       'event_count': payload['event_count'], 'window_seconds': payload['window_seconds'],
                                       'seed': payload['seed']}
                else:
                    while len(self.results) >= 10:
                        del self.results[min(self.results, key=lambda k: self.results[k]['ended'])]
                    self.results[object_id] = {'owner': job['owner'], 'ended': now, 'result_id': object_id,
                                               'result': payload}
                    job['result_id'] = object_id
                job['status'] = 'completed'
        except TimeoutError:
            job['status'] = 'timed_out'
        except asyncio.CancelledError:
            job['status'] = 'failed'
            raise
        except Exception:
            job['status'] = 'failed'
        finally:
            if spawn is not None and self.process is None:
                try:
                    self.process = await asyncio.wait_for(spawn, timeout=2)
                except (Exception, asyncio.CancelledError):
                    pass
            if self.process:
                if self.process.returncode is None:
                    try: self.process.kill()
                    except ProcessLookupError: pass
                await self.process.wait()
            self.process = None
            job['ended'] = time.monotonic()
            self.active = None
            self.release()

    def release(self):
        if self.has_slot:
            self.has_slot = False
            slot.release()

    async def close(self):
        if self.task and not self.task.done():
            self.task.cancel()
            try: await self.task
            except asyncio.CancelledError: pass
        if self.active:
            self.jobs[self.active]['status'] = 'failed'
            self.jobs[self.active]['ended'] = time.monotonic()
            self.active = None
        self.release()


coordinator = Coordinator()
