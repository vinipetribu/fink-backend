"""Bounded, per-process job coordinator. No experiment runs on the API loop."""
import asyncio
from collections import deque
import json
import os
import sys
import time
from uuid import uuid4
from app.crypto_lab.heavy_capacity import slot


class Busy(Exception):
    pass


class RateLimited(Exception):
    pass


class Coordinator:
    def __init__(self):
        self.jobs = {}
        self.active = None
        self.starts = deque()
        self.user_starts = {}
        self.reads = {}
        self.task = None
        self.process = None
        self.has_slot = False

    def clean(self, now):
        for job_id, item in list(self.jobs.items()):
            if item.get("ended") is not None and now - item["ended"] >= 900:
                del self.jobs[job_id]
        while self.starts and now - self.starts[0] >= 3600:
            self.starts.popleft()
        self.user_starts = {u: t for u, t in self.user_starts.items() if now - t < 60}
        for user, times in list(self.reads.items()):
            while times and now - times[0] >= 60:
                times.popleft()
            if not times:
                del self.reads[user]

    def start(self, owner, experiment, timeout):
        now = time.monotonic()
        self.clean(now)
        if sys.platform != "linux" or not 0 < timeout <= 120:
            raise Busy()
        if self.active is not None:
            raise Busy()
        if owner in self.user_starts or len(self.starts) >= 10:
            raise RateLimited()
        if not slot.acquire(blocking=False):
            raise Busy()
        self.has_slot = True
        while len(self.jobs) >= 10:
            oldest = min(self.jobs, key=lambda i: self.jobs[i]["ended"])
            del self.jobs[oldest]
        job_id = str(uuid4())
        self.jobs[job_id] = {"owner": owner, "run_id": job_id, "experiment": experiment,
                             "algorithm": "TOY-V1-INSECURE", "status": "running",
                             "schema_version": 1, "catalog_version": "synthetic-v1",
                             "parameters": {"timeout_seconds": timeout}, "started": now}
        self.active = job_id
        self.starts.append(now)
        self.user_starts[owner] = now
        self.task = asyncio.create_task(self._execute(job_id, timeout))
        from app.crypto_lab.event_store.emitter import emit
        emit('ATTACK_RUN', '/api/v1/crypto-lab/attacks/runs', 'ALLOWED', origin='synthetic')
        return {"run_id": job_id, "status": "running", "algorithm": "TOY-V1-INSECURE"}

    def get(self, owner, job_id):
        now = time.monotonic()
        self.clean(now)
        times = self.reads.setdefault(owner, deque())
        if len(times) >= 60:
            raise RateLimited()
        times.append(now)
        job = self.jobs.get(job_id)
        if job is None or job["owner"] != owner:
            return None
        return {k: v for k, v in job.items() if k not in {"owner", "started", "ended"}} | {
            "duration_seconds": (job.get("ended") or now) - job["started"]}

    async def _execute(self, job_id, timeout):
        job = self.jobs[job_id]
        try:
            async with asyncio.timeout_at(asyncio.get_running_loop().time() + max(0, timeout - (time.monotonic() - job["started"]))):
                self.process = await asyncio.create_subprocess_exec(
                    sys.executable, "-m", "app.crypto_lab.attacks.worker", job["experiment"], str(os.getpid()),
                    str(job["started"] + timeout),
                    stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL, env={"PATH": os.defpath}, start_new_session=True)
                output, _ = await self.process.communicate()
                if self.process.returncode != 0 or len(output) > 65536:
                    raise ValueError("Worker failed")
                metrics = json.loads(output)
                if not isinstance(metrics, dict):
                    raise ValueError("Invalid result")
                public = {k: v for k, v in job.items() if k not in {"owner", "started"}}
                public.update({"status": "completed", "metrics": metrics, "duration_seconds": timeout})
                if len(json.dumps(public, separators=(",", ":"), allow_nan=False).encode()) > 65536:
                    raise ValueError("Result too large")
                job["metrics"] = metrics
                job["status"] = "completed"
        except TimeoutError:
            job["status"] = "timed_out"
        except asyncio.CancelledError:
            job["status"] = "failed"
            raise
        except Exception:
            job["status"] = "failed"
        finally:
            if self.process is not None:
                if self.process.returncode is None:
                    try:
                        self.process.kill()
                    except ProcessLookupError:
                        pass
                await self.process.wait()
            self.process = None
            job["ended"] = time.monotonic()
            from app.crypto_lab.event_store.emitter import emit
            emit('ATTACK_RUN', '/api/v1/crypto-lab/attacks/runs',
                 {'completed': 'SUCCESS', 'timed_out': 'TIMEOUT'}.get(job['status'], 'FAILURE'), origin='synthetic')
            self.active = None
            self.release_slot()

    def release_slot(self):
        if self.has_slot:
            self.has_slot = False
            slot.release()

    async def close(self):
        if self.task and not self.task.done():
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        if self.active is not None:
            job = self.jobs[self.active]
            job["status"] = "failed"
            job["ended"] = time.monotonic()
            from app.crypto_lab.event_store.emitter import emit
            emit('ATTACK_RUN', '/api/v1/crypto-lab/attacks/runs', 'FAILURE', origin='synthetic')
            self.active = None
        self.release_slot()


coordinator = Coordinator()
