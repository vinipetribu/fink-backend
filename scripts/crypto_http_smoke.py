"""Teste HTTP local do Crypto Lab; cria duas contas fictícias no banco existente."""

import base64
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone

BASE = "http://127.0.0.1:18000"
CONTAINER = "fink-crypto-http-local"


def call(method, path, data, token=None):
    command = ["curl", "--silent", "--show-error", "--include", "--max-time", "15",
               "--request", method, BASE + path, "--header", "Content-Type: application/json"]
    if token:
        command += ["--header", "Authorization: Bearer " + token]
    command += ["--data-binary", json.dumps(data, ensure_ascii=False)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError("Não foi possível conectar à API na porta 18000.")
    headers, separator, body = result.stdout.partition("\r\n\r\n")
    if not separator:
        headers, separator, body = result.stdout.partition("\n\n")
    if not separator:
        raise RuntimeError("Resposta HTTP inválida.")
    lines = headers.splitlines()
    code = int(lines[0].split()[1])
    cache = next((line.split(":", 1)[1].strip().lower() for line in lines[1:]
                  if line.lower().startswith("cache-control:")), "ausente")
    try:
        response = json.loads(body)
    except json.JSONDecodeError:
        response = {}
    return code, cache, response


def create_user(email, password):
    person = {"email": email, "senha": password, "nome": "Teste Crypto Ficticio",
              "data_nascimento": "2000-01-01", "telefone": "81999999999",
              "genero": "nao_informado", "estado": "PE", "cidade": "Recife",
              "rua": "Rua de Teste", "numero": "1", "cep": "50000000"}
    code, _, _ = call("POST", "/api/v1/pessoas/", person)
    if code != 201:
        raise RuntimeError(f"Cadastro fictício retornou HTTP {code}. Confira os logs da API.")
    code, _, response = call("POST", "/api/v1/sessoes/login", {"email": email, "senha": password})
    if code != 201 or not isinstance(response.get("token"), str):
        raise RuntimeError(f"Login fictício retornou HTTP {code} ou não retornou token.")
    return response["token"]


def report(label, actual, expected, cache):
    ok = actual == expected and cache == "no-store"
    print(f"{label}: HTTP {actual} (esperado {expected}), Cache-Control: {cache} — {'OK' if ok else 'FALHOU'}")
    return ok


def main():
    started = datetime.now(timezone.utc).isoformat()
    suffix = uuid.uuid4().hex[:12]
    password = "Senha-Ficticia-" + suffix + "!"
    message = "Transação fictícia: café e pão R$ 25,00"
    print("Criando duas contas fictícias e autenticando...")
    token_a = create_user("crypto-a-" + suffix + "@example.com", password)
    token_b = create_user("crypto-b-" + suffix + "@example.com", password)
    checks = []
    code, cache, response = call("POST", "/api/v1/crypto-lab/encrypt", {"text": message}, token_a)
    checks.append(report("Cifragem", code, 200, cache))
    if code != 200 or not isinstance(response.get("envelope"), dict):
        raise RuntimeError("Não foi possível obter o envelope; testes seguintes não foram executados.")
    envelope = response["envelope"]
    code, cache, response = call("POST", "/api/v1/crypto-lab/decrypt", {"envelope": envelope}, token_a)
    checks.append(report("Descriptografia", code, 200, cache))
    identical = response.get("text") == message
    checks.append(identical)
    print("Texto recuperado: " + ("IDÊNTICO — OK" if identical else "DIFERENTE — FALHOU"))
    code, cache, _ = call("POST", "/api/v1/crypto-lab/encrypt", {"text": message})
    checks.append(report("Sem autenticação", code, 401, cache))
    tampered = dict(envelope)
    value = bytearray(base64.b64decode(tampered["ciphertext"], validate=True))
    value[-1] ^= 1
    tampered["ciphertext"] = base64.b64encode(value).decode()
    code, cache, _ = call("POST", "/api/v1/crypto-lab/decrypt", {"envelope": tampered}, token_a)
    checks.append(report("Envelope adulterado", code, 400, cache))
    code, cache, _ = call("POST", "/api/v1/crypto-lab/decrypt", {"envelope": envelope}, token_b)
    checks.append(report("Outro usuário", code, 400, cache))
    logs = subprocess.run(["docker", "logs", "--since", started, CONTAINER], capture_output=True, text=True)
    if logs.returncode:
        print("Logs: NÃO VERIFICADOS — não foi possível acessá-los.")
        checks.append(False)
    else:
        content = logs.stdout + logs.stderr
        values = {"mensagem": message, "senha fictícia": password, "token A": token_a, "token B": token_b,
                  "nonce": envelope["nonce"], "ciphertext": envelope["ciphertext"]}
        found = [name for name, value in values.items() if value in content]
        checks.append(not found)
        print("Logs: " + ("FALHOU — encontrados: " + ", ".join(found) if found else "valores verificados ausentes — OK"))
    if not all(checks):
        sys.exit(1)
    print("Teste HTTP concluído: todos os cenários acima passaram.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.TimeoutExpired, KeyError, ValueError) as exc:
        print("Teste interrompido:", exc, file=sys.stderr)
        sys.exit(1)
