"""Fresh Linux process; no request data, credentials, stores or inherited memory."""
import ctypes
import json
import os
import resource
import signal
import sys
import time


def main():
    if sys.platform != "linux" or len(sys.argv) != 4:
        return 1
    # Independent fail-safe if the coordinator loses its handle during startup.
    deadline = float(sys.argv[3])
    remaining = deadline - time.monotonic()
    if not 0 < remaining <= 120:
        return 1
    signal.setitimer(signal.ITIMER_REAL, remaining)
    parent = int(sys.argv[2])
    # Atomically request a kernel-delivered SIGKILL if our parent dies. Check the
    # parent again to close the race between exec and prctl.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        return 1
    resource.setrlimit(resource.RLIMIT_CPU, (120, 121))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    from . import avalanche, brute_force, differential, statistics
    experiments = {"avalanche": avalanche.run, "brute_force": brute_force.run,
                   "differential": differential.run, "statistics": statistics.run}
    result = experiments[sys.argv[1]]()
    encoded = json.dumps(result, separators=(",", ":"), allow_nan=False).encode()
    if len(encoded) > 65536:
        return 1
    sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.exit(1)
