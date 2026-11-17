"""Disposable Docker Linux worker, with no access to application state."""
import ctypes
import errno
import json
import os
import resource
import signal
import sys
import time


def disable_network():
    """Deny socket syscalls; fail closed when the Docker image lacks libseccomp."""
    seccomp = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
    seccomp.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    context = seccomp.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    if not context:
        raise RuntimeError('seccomp unavailable')
    try:
        for name in ('socket', 'socketpair', 'connect', 'bind', 'listen', 'accept', 'accept4',
                     'sendto', 'recvfrom', 'sendmsg', 'recvmsg'):
            number = seccomp.seccomp_syscall_resolve_name(name.encode())
            if number < 0 or seccomp.seccomp_rule_add(context, 0x00050000 | errno.EPERM, number, 0) != 0:
                raise RuntimeError('seccomp rule unavailable')
        if seccomp.seccomp_load(context) != 0:
            raise RuntimeError('seccomp load failed')
    finally:
        seccomp.seccomp_release(context)


def main():
    if sys.platform != 'linux' or not os.path.exists('/.dockerenv') or len(sys.argv) != 4:
        return 1
    operation, parent, deadline = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
    remaining = deadline - time.monotonic()
    if not 0 < remaining <= 120:
        return 1
    signal.setitimer(signal.ITIMER_REAL, remaining)
    if ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        return 1
    resource.setrlimit(resource.RLIMIT_CPU, (120, 121))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    disable_network()
    if operation == 'dataset':
        from .generator import generate
        result = generate()
        limit = 5 * 1024 * 1024
    elif operation == 'run':
        from .models import analyse
        data = sys.stdin.buffer.read(5 * 1024 * 1024 + 1)
        if len(data) > 5 * 1024 * 1024:
            return 1
        result = analyse(json.loads(data))
        limit = 65536
    else:
        return 1
    encoded = json.dumps(result, separators=(',', ':'), allow_nan=False).encode()
    if len(encoded) > limit:
        return 1
    sys.stdout.buffer.write(encoded)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        sys.exit(1)
