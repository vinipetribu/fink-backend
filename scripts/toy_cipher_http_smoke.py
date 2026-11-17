"""Smoke HTTP local da cifra didática usando a imagem Docker da FINK.

Cria duas contas fictícias persistentes no banco de desenvolvimento; uma recebe
ADMIN temporariamente e é rebaixada ao final. Não executa seed, migrações ou
remoção de volumes. Os contêineres efêmeros criados pelo script são parados.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import secrets
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "fink-backend-api"
ENDPOINT = "/api/v1/crypto-lab/experimental/run"
FILES = ("app/main.py", "app/core/settings.py", "app/crypto_lab/__init__.py", "app/crypto_lab/routes.py",
         "app/crypto_lab/schemas.py", "app/crypto_lab/toy_cipher.py", "app/crypto_lab/middleware.py",
         "app/crypto_lab/aes_service.py", "app/crypto_lab/envelope.py", "app/crypto_lab/key_store.py",
         "app/crypto_lab/metrics.py", "app/crypto_lab/errors.py")


def docker(*args, data=None, timeout=60):
    result = subprocess.run(["docker", *args], input=data, text=True, capture_output=True, cwd=ROOT, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Docker falhou ao executar {args[0]}; verifique Docker e a imagem local.")
    return result.stdout.strip()


def request(port, path, data=None, token=None, method="POST"):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    try:
        connection.request(method, path, json.dumps(data, ensure_ascii=False).encode("utf-8") if data is not None else None,
                           headers)
        response = connection.getresponse()
        raw = response.read()
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeError):
            body = {}
        return response.status, response.getheader("Cache-Control", ""), body
    finally:
        connection.close()


def check(label, condition, detail=""):
    print(f"{'PASS' if condition else 'FAIL'} | {label}" + (f" | {detail}" if detail else ""), flush=True)
    return bool(condition)


def image_and_network():
    image_id = docker("image", "inspect", "--format", "{{.Id}}", IMAGE)
    print("Imagem utilizada:", image_id, flush=True)
    hash_code = ("import hashlib,json,pathlib; names=" + repr(FILES) + "; "
                 "print(json.dumps({n:hashlib.sha256(pathlib.Path('/app',n).read_bytes()).hexdigest() for n in names}))")
    image_hashes = json.loads(docker("run", "--rm", "--entrypoint", "python", IMAGE, "-c", hash_code))
    for name in FILES:
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != image_hashes.get(name):
            raise RuntimeError("A imagem difere do código local; reconstrua a imagem antes do teste.")
    postgres = docker("compose", "ps", "-q", "postgres")
    if not postgres:
        raise RuntimeError("PostgreSQL do Compose não está em execução.")
    inspect = json.loads(docker("inspect", postgres))[0]
    if inspect.get("State", {}).get("Health", {}).get("Status") != "healthy":
        raise RuntimeError("PostgreSQL do Compose ainda não está saudável.")
    networks = inspect["NetworkSettings"]["Networks"]
    candidates = [name for name, data in networks.items() if "postgres" in (data.get("Aliases") or [])]
    if len(candidates) != 1:
        raise RuntimeError("Não foi possível identificar a rede Compose do PostgreSQL.")
    return candidates[0]


def start_instance(network, name, flags):
    args = ["run", "--detach", "--rm", "--name", name, "--network", network,
            "--publish", "127.0.0.1::8000", "--env", "ENVIRONMENT=development", "--env", "DEBUG=false",
            "--env", "CRYPTO_LAB_WORKERS=1", "--env", "CRYPTO_LAB_INSTANCES=1",
            "--env", "DATABASE_URL=postgresql+asyncpg://fink:fink@postgres:5432/fink",
            "--env", "REDIS_URL=redis://redis:6379/0"]
    for key, value in flags.items():
        args += ["--env", f"{key}={value}"]
    docker(*args, "--entrypoint", "python", IMAGE, "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0",
           "--port", "8000", "--workers", "1", "--lifespan", "off")
    port_str = docker("port", name, "8000/tcp").splitlines()[0].rsplit(":", 1)[-1]
    port = int(port_str)
    for _ in range(40):
        try:
            status, _, _ = request(port, "/health", method="GET")
            if status == 200:
                return port
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.25)
    raise RuntimeError("Instância de teste não respondeu ao health check.")


def create_user(port, email, password):
    person = {"email": email, "senha": password, "nome": "Teste Didatico Ficticio",
              "data_nascimento": "2000-01-01", "telefone": "81999999999", "genero": "nao_informado",
              "estado": "PE", "cidade": "Recife", "rua": "Rua de Teste", "numero": "1", "cep": "50000000"}
    status, _, response = request(port, "/api/v1/pessoas/", person)
    if status != 201:
        raise RuntimeError(f"Cadastro fictício falhou (HTTP {status}); confira o banco de desenvolvimento.")
    return str(uuid.UUID(response["id_pessoa"]))


def login(port, email, password):
    status, _, response = request(port, "/api/v1/sessoes/login", {"email": email, "senha": password})
    if status != 201 or not isinstance(response.get("token"), str):
        raise RuntimeError(f"Login fictício falhou (HTTP {status}).")
    return response["token"]


def set_admin(person_id, enabled):
    # ID criado nesta execução é validado como UUID antes de compor o comando SQL.
    person_id = str(uuid.UUID(person_id))
    value = "TRUE" if enabled else "FALSE"
    sql = f"UPDATE pessoa SET admin = {value} WHERE id_pessoa = '{person_id}' RETURNING id_pessoa;\n"
    output = docker("compose", "exec", "-T", "postgres", "psql", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1",
                    "-U", "fink", "-d", "fink", data=sql)
    if person_id not in output.splitlines():
        raise RuntimeError("Não foi possível ajustar o perfil da conta fictícia.")


def main():
    started = datetime.now(timezone.utc).isoformat()
    suffix = uuid.uuid4().hex[:12]
    containers = []
    admin_id = None
    results = []
    logs_values = {}
    cleanup_failed = False
    message = "Anotação financeira fictícia " + suffix
    password = "Ficticia-" + secrets.token_urlsafe(24)
    email_a = f"toy-admin-{suffix}@example.com"
    email_b = f"toy-user-{suffix}@example.com"
    logs_values.update(mensagem=message, senha_ficticia=password)
    flags = {
        "default": {},
        "geral_apenas": {"CRYPTO_LAB_ENABLED": "true", "CRYPTO_LAB_EXPERIMENTAL_ENABLED": "false"},
        "experimental_apenas": {"CRYPTO_LAB_ENABLED": "false", "CRYPTO_LAB_EXPERIMENTAL_ENABLED": "true"},
        "ambas": {"CRYPTO_LAB_ENABLED": "true", "CRYPTO_LAB_EXPERIMENTAL_ENABLED": "true"},
    }
    try:
        network = image_and_network()
        ports = {}
        for mode, flag_values in flags.items():
            name = f"fink-toy-smoke-{suffix}-{mode.replace('_', '-')}"
            # Register before start to clean up even if readiness fails.
            containers.append(name)
            ports[mode] = start_instance(network, name, flag_values)
            flag_code = ("import json; from app.core.settings import settings; "
                         "print(json.dumps([settings.crypto_lab_enabled, settings.crypto_lab_experimental_enabled]))")
            actual_flags = json.loads(docker("exec", name, "python", "-c", flag_code))
            expected_flags = {"default": [False, False], "geral_apenas": [True, False],
                              "experimental_apenas": [False, True], "ambas": [True, True]}[mode]
            if actual_flags != expected_flags:
                raise RuntimeError(f"Flags da instância {mode} diferem do cenário esperado.")
        print("Contêineres locais prontos. Criando contas fictícias...", flush=True)
        port = ports["ambas"]
        admin_id = create_user(port, email_a, password)
        create_user(port, email_b, password)
        set_admin(admin_id, True)
        admin = login(port, email_a, password)
        user = login(port, email_b, password)
        logs_values.update(token_admin=admin, token_user=user)
        code, cache, aes = request(port, "/api/v1/crypto-lab/encrypt", {"text": message}, user)
        aes_envelope = aes.get("envelope")
        aes_before = code == 200 and cache.lower() == "no-store" and isinstance(aes_envelope, dict)
        if aes_before:
            logs_values["ciphertext_aes"] = aes_envelope.get("ciphertext", "")
            code, cache, recovered = request(port, "/api/v1/crypto-lab/decrypt", {"envelope": aes_envelope}, user)
            aes_before = code == 200 and recovered.get("text") == message and cache.lower() == "no-store"
        results.append(check("AES: cifragem e recuperação antes da cifra didática", aes_before))
        body = {"action": "encrypt", "text": message}
        for mode, description in (("default", "Flags omitidas: desabilitado por padrão"),
                                  ("geral_apenas", "Somente flag geral habilitada"),
                                  ("experimental_apenas", "Somente flag experimental habilitada")):
            code, cache, _ = request(ports[mode], ENDPOINT, body, admin)
            results.append(check(description, code == 503 and cache.lower() == "no-store", f"HTTP {code}"))
        code, cache, _ = request(port, ENDPOINT, body)
        results.append(check("Anônimo rejeitado", code == 401 and cache.lower() == "no-store", f"HTTP {code}"))
        code, cache, _ = request(port, ENDPOINT, body, user)
        results.append(check("USER rejeitado", code == 403 and cache.lower() == "no-store", f"HTTP {code}"))
        code, cache, toy = request(port, ENDPOINT, body, admin)
        ok = (code == 200 and cache.lower() == "no-store" and toy.get("algorithm") == "TOY-V1-INSECURE"
              and isinstance(toy.get("key_id"), str) and isinstance(toy.get("ciphertext"), str)
              and "insegura" in toy.get("warning", "").lower() and "key" not in toy and "toy_key" not in toy)
        results.append(check("ADMIN cifra com ambas as flags", ok, f"HTTP {code}"))
        if not ok:
            raise RuntimeError("Cifragem didática não retornou o contrato esperado; testes dependentes não executados.")
        logs_values["ciphertext_didatico"] = toy["ciphertext"]
        code, cache, decoded = request(port, ENDPOINT,
                                       {"action": "decrypt", "key_id": toy["key_id"],
                                        "ciphertext": toy["ciphertext"]}, admin)
        results.append(check("Cifra reversível", code == 200 and decoded.get("text") == message
                             and cache.lower() == "no-store", f"HTTP {code}"))
        aes_ok = False
        if aes_before:
            code, cache, recovered = request(port, "/api/v1/crypto-lab/decrypt", {"envelope": aes_envelope}, user)
            aes_ok = code == 200 and recovered.get("text") == message and cache.lower() == "no-store"
        results.append(check("AES: mesmo envelope recuperado após cifra didática", aes_ok))
        # docker logs escreve stderr também; colete as duas saídas, sem exibí-las.
        all_logs = []
        for name in containers:
            proc = subprocess.run(["docker", "logs", "--since", started, name], capture_output=True, text=True, timeout=60)
            if proc.returncode:
                raise RuntimeError("Não foi possível inspecionar os logs de todos os contêineres.")
            all_logs.append(proc.stdout + proc.stderr)
        log_text = "\n".join(all_logs)
        found = [label for label, value in logs_values.items() if value and value in log_text]
        key_field = re.search(r'(?i)["\'](?:toy_key|secret_key|chave|key)["\']\s*:', log_text)
        results.append(check("Logs: plaintext, credenciais e ciphertext verificados", not found,
                             "valores encontrados: " + ", ".join(found) if found else "valores verificados ausentes"))
        results.append(check("Logs: ausência de campos explícitos de chave", key_field is None,
                             "o valor interno da chave não é acessível pelo cliente HTTP"))
        print("LIMITAÇÃO | A ausência do valor interno da chave nos logs não pode ser comprovada por esta inspeção HTTP.")
        if not all(results):
            raise RuntimeError("Um ou mais cenários falharam; confira os resultados acima.")
    finally:
        if admin_id:
            try:
                set_admin(admin_id, False)
                print("Conta ADMIN fictícia rebaixada para USER; contas e sessões permanecem no banco.")
            except (RuntimeError, OSError, subprocess.TimeoutExpired):
                cleanup_failed = True
                print(f"ATENÇÃO: não foi possível rebaixar {email_a}; inspecione o banco local.", file=sys.stderr)
        for name in reversed(containers):
            try:
                stopped = subprocess.run(["docker", "stop", name], stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL, timeout=20, check=False)
                if stopped.returncode:
                    state = subprocess.run(["docker", "inspect", "--format", "{{.State.Running}}", name],
                                           capture_output=True, text=True, timeout=20, check=False)
                    if state.returncode == 0 and state.stdout.strip() == "true":
                        cleanup_failed = True
                        print(f"Aviso: contêiner temporário {name} continua em execução.", file=sys.stderr)
            except (OSError, subprocess.TimeoutExpired):
                cleanup_failed = True
                print(f"Aviso: não foi possível parar o contêiner temporário {name}.", file=sys.stderr)
        if cleanup_failed:
            raise RuntimeError("Falha na finalização; confira os avisos acima.")
    print(f"Concluído: {len(results)} cenários PASS. Contas fictícias permanecem no banco.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.TimeoutExpired, KeyError, ValueError, http.client.HTTPException) as exc:
        print("Teste interrompido:", exc, file=sys.stderr)
        sys.exit(1)
