import base64
import getpass
import http.client
import json
import sys
from pathlib import Path


HOST = "127.0.0.1"
PORTA = 18010
MENSAGEM = "Mensagem secreta de demonstracao FINK"

RAIZ = Path(__file__).resolve().parent.parent
ORIGINAL = RAIZ / "evidencias" / "etapa4" / "original.png"
MODIFICADA = RAIZ / "evidencias" / "etapa4" / "modificada.png"

ASSINATURA_PNG = b"\x89PNG\r\n\x1a\n"


def falhar(mensagem):
    print(f"FAIL | {mensagem}")
    raise SystemExit(1)


def post(nome, rota, dados, esperado, token=None):
    headers = {"Content-Type": "application/json"}

    if token:
        headers["Authorization"] = f"Bearer {token}"

    conexao = http.client.HTTPConnection(HOST, PORTA, timeout=30)

    try:
        corpo = json.dumps(dados, ensure_ascii=False).encode("utf-8")

        conexao.request(
            "POST",
            rota,
            body=corpo,
            headers=headers,
        )

        resposta = conexao.getresponse()
        status = resposta.status
        conteudo = resposta.read()

    except (OSError, http.client.HTTPException):
        falhar(f"{nome}: não foi possível conectar à API.")

    finally:
        conexao.close()

    if status != esperado:
        falhar(f"{nome}: HTTP {status}; esperado HTTP {esperado}.")

    try:
        resultado = json.loads(conteudo)
    except (ValueError, UnicodeDecodeError):
        falhar(f"{nome}: resposta JSON inválida. HTTP {status}.")

    if not isinstance(resultado, dict):
        falhar(f"{nome}: formato de resposta inválido. HTTP {status}.")

    print(f"PASS | {nome} | HTTP {status}")
    return resultado


def main():
    if not ORIGINAL.is_file():
        falhar("Imagem original não encontrada em evidencias/etapa4/original.png.")

    try:
        imagem_original = ORIGINAL.read_bytes()
    except OSError:
        falhar("Não foi possível ler a imagem original.")

    if not imagem_original.startswith(ASSINATURA_PNG):
        falhar("O arquivo original não possui assinatura PNG válida.")

    if len(imagem_original) > 1_048_576:
        falhar("A imagem original ultrapassa o limite de 1 MiB.")

    email = input("E-mail da conta fictícia: ").strip()
    senha = getpass.getpass("Senha: ")

    if not email or not senha:
        falhar("Informe o e-mail e a senha da conta fictícia.")

    login = post(
        "Login",
        "/api/v1/sessoes/login",
        {"email": email, "senha": senha},
        esperado=201,
    )

    token = login.get("token")

    if not isinstance(token, str) or not token:
        falhar("Login: a resposta não contém um token válido.")

    # A senha deixa de ser necessária após o login.
    del senha

    cifragem = post(
        "Criptografia AES-256-GCM",
        "/api/v1/crypto-lab/encrypt",
        {"text": MENSAGEM},
        esperado=200,
        token=token,
    )

    envelope = cifragem.get("envelope")

    if not isinstance(envelope, dict):
        falhar("Criptografia: envelope não encontrado na resposta.")

    insercao = post(
        "Inserção na imagem PNG",
        "/api/v1/crypto-lab/steganography/embed",
        {
            "image_png": base64.b64encode(imagem_original).decode("ascii"),
            "envelope": envelope,
        },
        esperado=200,
        token=token,
    )

    try:
        imagem_modificada = base64.b64decode(
            insercao["image_png"],
            validate=True,
        )
    except (KeyError, ValueError):
        falhar("Inserção: imagem retornada inválida.")

    if not imagem_modificada.startswith(ASSINATURA_PNG):
        falhar("Inserção: a resposta não é um PNG válido.")

    try:
        MODIFICADA.write_bytes(imagem_modificada)
    except OSError:
        falhar("Não foi possível salvar modificada.png.")

    print("PASS | Imagem salva em evidencias/etapa4/modificada.png")

    try:
        imagem_salva = MODIFICADA.read_bytes()
    except OSError:
        falhar("Não foi possível reler modificada.png.")

    extracao = post(
        "Extração do envelope",
        "/api/v1/crypto-lab/steganography/extract",
        {
            "image_png": base64.b64encode(imagem_salva).decode("ascii"),
        },
        esperado=200,
        token=token,
    )

    envelope_extraido = extracao.get("envelope")

    if not isinstance(envelope_extraido, dict):
        falhar("Extração: envelope não encontrado na resposta.")

    recuperacao = post(
        "Descriptografia",
        "/api/v1/crypto-lab/decrypt",
        {"envelope": envelope_extraido},
        esperado=200,
        token=token,
    )

    if recuperacao.get("text") != MENSAGEM:
        falhar("A mensagem recuperada é diferente da original.")

    print("PASS | Mensagem recuperada idêntica à original")
    print("Concluído: imagem de demonstração gerada.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperação cancelada.")
        sys.exit(1)