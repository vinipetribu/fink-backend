"""Local-only ASGI boundary: configuration, streaming body cap and safe errors."""

import json
import os
import shlex
import sys

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse

PREFIX = "/api/v1/crypto-lab"
MAX_BODY = 16384
MAX_STEGO_BODY = 1420000
STEGO_PATHS = {PREFIX + "/steganography/embed", PREFIX + "/steganography/extract"}


def compatible_workers(settings) -> bool:
    """Reject explicitly declared multi-process setups; external topology is unknowable."""
    if settings.crypto_lab_workers != 1 or settings.crypto_lab_instances != 1:
        return False
    for name in ("WEB_CONCURRENCY", "UVICORN_WORKERS"):
        value = os.environ.get(name)
        if value is not None:
            try:
                if int(value) != 1:
                    return False
            except ValueError:
                return False
    try:
        args = shlex.split(os.environ.get("GUNICORN_CMD_ARGS", "")) + sys.argv[1:]
    except ValueError:
        return False
    for index, arg in enumerate(args):
        if arg in ("--workers", "-w"):
            if index + 1 >= len(args) or args[index + 1] != "1":
                return False
        elif arg.startswith("--workers=") and arg != "--workers=1":
            return False
        elif arg.startswith("-w") and arg != "-w1" and len(arg) > 2:
            return False
    return True


class CryptoLabMiddleware:
    def __init__(self, app, settings):
        self.app = app
        self.settings = settings

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "")
        if scope["type"] != "http" or not (path == PREFIX or path.startswith(PREFIX + "/")):
            await self.app(scope, receive, send)
            return

        async def reject(status: int, detail: str) -> None:
            await JSONResponse({"detail": detail}, status_code=status,
                               headers={"Cache-Control": "no-store"})(scope, receive, send)

        if self.settings.environment.strip().lower() == "production":
            await reject(404, "Não encontrado")
            return
        if (self.settings.environment.strip().lower() not in {"development", "test", "testing", "local"}
                or not self.settings.crypto_lab_enabled or self.settings.debug
                or not compatible_workers(self.settings)):
            await reject(503, "Laboratório indisponível")
            return

        # Drain only up to the limit, including bodies with no Content-Length.
        body = bytearray()
        max_body = (1024 if path.startswith((PREFIX + "/attacks/", PREFIX + "/anomalies/")) else
                    MAX_STEGO_BODY if path in STEGO_PATHS else MAX_BODY)
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > max_body:
                await reject(413, "Corpo da requisição excede o limite")
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        if scope["method"] in ("POST", "PUT", "PATCH") and body:
            try:
                json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, RecursionError):
                await reject(400, "JSON inválido")
                return

        sent_body = False
        async def replay():
            nonlocal sent_body
            if not sent_body:
                sent_body = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        started = False
        replacement = None
        sanitized_sent = False
        async def safe_send(message):
            nonlocal started, replacement, sanitized_sent
            if message["type"] == "http.response.start":
                started = True
                event_types = {
                    PREFIX + '/encrypt': 'AES_ENCRYPT',
                    PREFIX + '/decrypt': 'AES_DECRYPT',
                    PREFIX + '/steganography/embed': 'STEGO_EMBED',
                    PREFIX + '/steganography/extract': 'STEGO_EXTRACT',
                }
                if scope['method'] == 'POST' and path in event_types:
                    from app.crypto_lab.event_store.emitter import emit
                    emit(event_types[path], path, 'SUCCESS' if message['status'] < 400 else 'FAILURE')
                headers = MutableHeaders(scope=message)
                headers["cache-control"] = "no-store"
                if message["status"] == 422:
                    replacement = b'{"detail":"Entrada invalida"}'
                elif message["status"] == 401:
                    replacement = b'{"detail":"Autenticacao invalida"}'
                if replacement is not None:
                    headers["content-type"] = "application/json"
                    headers["content-length"] = str(len(replacement))
            elif message["type"] == "http.response.body" and replacement is not None:
                if sanitized_sent:
                    return
                sanitized_sent = True
                message = {"type": "http.response.body", "body": replacement, "more_body": False}
            await send(message)

        try:
            await self.app(scope, replay, safe_send)
        except Exception:
            # Never log exception objects, request bodies or tracebacks for this prefix.
            if not started:
                await reject(500, "Erro interno")
            else:
                try:
                    await send({"type": "http.response.body", "body": b"", "more_body": False})
                except Exception:
                    pass
