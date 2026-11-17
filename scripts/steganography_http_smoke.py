"""Validação HTTP local de LSB/AES; executa apenas com dados fictícios.

Cria duas contas fictícias persistentes no banco de desenvolvimento. Uma delas
é promovida temporariamente a ADMIN para exercitar a cifra didática e é rebaixada
em seguida. Sessões e contas permanecem. Não executa seed, migração ou exclusão
de volumes. Cria e encerra apenas seu próprio contêiner temporário de API.
"""

from __future__ import annotations

import base64
import http.client
import io
import json
import secrets
import struct
import subprocess
import sys
import uuid
import zlib
from datetime import datetime, timezone

import toy_cipher_http_smoke as common

BASE = '/api/v1/crypto-lab'
PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'


def chunk(kind, payload):
    return (struct.pack('>I', len(payload)) + kind + payload
            + struct.pack('>I', zlib.crc32(kind + payload) & 0xffffffff))


def png_encode(width, height, color, pixels):
    """Fixtures 8-bit e não entrelaçadas, com filtro 0 e CRC válido."""
    channels = 3 if color == 2 else 4
    if len(pixels) != width * height * channels:
        raise ValueError('Comprimento de pixels inválido')
    stride = width * channels
    raw = b''.join(b'\0' + pixels[y * stride:(y + 1) * stride] for y in range(height))
    ihdr = struct.pack('>IIBBBBB', width, height, 8, color, 0, 0, 0)
    return PNG_SIGNATURE + chunk(b'IHDR', ihdr) + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b'')


def make_fixture(width, height, color):
    channels = 3 if color == 2 else 4
    pixels = bytes((index * 73 + 29) % 256 for index in range(width * height * channels))
    return png_encode(width, height, color, pixels), pixels


def read_png_independent(png):
    """Leitor independente restrito às saídas esperadas (PNG 8-bit, filtro 0)."""
    if not png.startswith(PNG_SIGNATURE):
        raise ValueError('Assinatura PNG inválida')
    pos, info, compressed, ended = 8, None, [], False
    while pos < len(png):
        if pos + 12 > len(png):
            raise ValueError('PNG truncado')
        size = struct.unpack_from('>I', png, pos)[0]
        if pos + 12 + size > len(png):
            raise ValueError('Chunk truncado')
        kind = png[pos + 4:pos + 8]
        data = png[pos + 8:pos + 8 + size]
        crc = struct.unpack_from('>I', png, pos + 8 + size)[0]
        if zlib.crc32(kind + data) & 0xffffffff != crc:
            raise ValueError('CRC inválido')
        pos += 12 + size
        if kind == b'IHDR':
            if info is not None or size != 13:
                raise ValueError('IHDR inválido')
            info = struct.unpack('>IIBBBBB', data)
        elif kind == b'IDAT':
            compressed.append(data)
        elif kind == b'IEND':
            if data or pos != len(png):
                raise ValueError('IEND inválido')
            ended = True
            break
    if not info or not ended or not compressed:
        raise ValueError('PNG incompleto')
    width, height, depth, color, compression, filtering, interlace = info
    if (depth, color, compression, filtering, interlace) not in ((8, 2, 0, 0, 0), (8, 6, 0, 0, 0)):
        raise ValueError('Formato inesperado')
    stride = width * (3 if color == 2 else 4)
    raw = zlib.decompress(b''.join(compressed))
    if len(raw) != (stride + 1) * height:
        raise ValueError('Dados PNG inválidos')
    rows = []
    for y in range(height):
        start = y * (stride + 1)
        if raw[start] != 0:
            raise ValueError('Filtro PNG inesperado')
        rows.append(raw[start + 1:start + 1 + stride])
    return width, height, color, b''.join(rows)


def tamper_hidden_payload(png):
    width, height, color, pixels = read_png_independent(png)
    pixels = bytearray(pixels)
    # Altera um bit após o cabeçalho FSL1 (40 bytes), preservando CRC do PNG.
    channel_index = 40 * 8 + 5
    channels = 3 if color == 2 else 4
    index = (channel_index // 3) * channels + channel_index % 3
    pixels[index] ^= 1
    return png_encode(width, height, color, bytes(pixels))


def b64(data):
    return base64.b64encode(data).decode('ascii')


def required(label, status, expected, cache, response=None, condition=True):
    ok = status == expected and cache.lower() == 'no-store' and condition
    print(f"{'PASS' if ok else 'FAIL'} | {label} | HTTP {status} (esperado {expected}) | Cache-Control: {cache or 'ausente'}", flush=True)
    if not ok:
        raise RuntimeError(f'Cenário falhou: {label}; cenários seguintes não foram executados.')
    return response


def check(label, condition):
    print(f"{'PASS' if condition else 'FAIL'} | {label}", flush=True)
    if not condition:
        raise RuntimeError(f'Cenário falhou: {label}; cenários seguintes não foram executados.')


def main():
    # Inclui o codec da Etapa 4 na comparação de hashes da imagem reconstruída.
    common.FILES = tuple(dict.fromkeys(common.FILES + ('app/crypto_lab/steganography.py',)))
    suffix = uuid.uuid4().hex[:12]
    started = datetime.now(timezone.utc).isoformat()
    password = 'Ficticia-' + secrets.token_urlsafe(24)
    message = 'Mensagem fictícia de laboratório ' + suffix
    user_email = f'stego-user-{suffix}@example.com'
    admin_email = f'stego-admin-{suffix}@example.com'
    name = f'fink-stego-smoke-{suffix}'
    admin_id = None
    container_started = False
    cleanup_failed = False
    values = {'mensagem fictícia': message, 'senha fictícia': password}
    try:
        network = common.image_and_network()
        # Usar ambas as flags também permite comprovar a independência da cifra didática.
        container_started = True
        port = common.start_instance(network, name,
                                     {'CRYPTO_LAB_ENABLED': 'true', 'CRYPTO_LAB_EXPERIMENTAL_ENABLED': 'true'})
        print('Instância local pronta. Criando duas contas fictícias...', flush=True)
        common.create_user(port, user_email, password)
        admin_id = common.create_user(port, admin_email, password)
        common.set_admin(admin_id, True)
        user_token = common.login(port, user_email, password)
        admin_token = common.login(port, admin_email, password)
        values.update({'token USER': user_token, 'token ADMIN': admin_token})
        print('PASS | Contas fictícias criadas e autenticadas', flush=True)

        status, cache, body = common.request(port, BASE + '/encrypt', {'text': message}, user_token)
        required('AES-256-GCM', status, 200, cache, condition=isinstance(body.get('envelope'), dict))
        envelope = body['envelope']
        values['ciphertext AES'] = envelope.get('ciphertext', '')
        values['nonce AES'] = envelope.get('nonce', '')

        status, cache, toy = common.request(port, BASE + '/experimental/run',
                                            {'action': 'encrypt', 'text': message}, admin_token)
        required('Cifra didática antes da esteganografia', status, 200, cache,
                 condition=isinstance(toy.get('key_id'), str) and isinstance(toy.get('ciphertext'), str))
        values['ciphertext didático'] = toy['ciphertext']

        images = {}
        for color, label in ((2, 'RGB'), (6, 'RGBA')):
            source, original = make_fixture(128, 128, color)
            values[f'PNG {label} de entrada'] = b64(source)
            status, cache, response = common.request(port, BASE + '/steganography/embed',
                                                      {'image_png': b64(source), 'envelope': envelope}, user_token)
            required(f'Inserção {label}', status, 200, cache, condition=isinstance(response.get('image_png'), str))
            try:
                image = base64.b64decode(response['image_png'], validate=True)
                width, height, actual_color, pixels = read_png_independent(image)
                valid = (width, height, actual_color) == (128, 128, color)
            except (ValueError, zlib.error, struct.error):
                valid = False
            check(f'PNG {label} válido — leitor independente', valid)
            images[label] = image
            values[f'PNG {label} de saída'] = response['image_png']
            if color == 6:
                check('Canal alfa RGBA preservado', pixels[3::4] == original[3::4])
            status, cache, response = common.request(port, BASE + '/steganography/extract',
                                                      {'image_png': b64(image)}, user_token)
            required(f'Extração {label}', status, 200, cache, condition=response.get('envelope') == envelope)
            status, cache, response = common.request(port, BASE + '/decrypt', response, user_token)
            required(f'Descriptografia {label}: texto idêntico', status, 200, cache,
                     condition=response.get('text') == message)

        try:
            from PIL import Image
        except ImportError:
            print('SKIP | Pillow no Mac indisponível; o leitor independente restrito acima foi usado.', flush=True)
        else:
            valid = True
            for label, image in images.items():
                try:
                    with Image.open(io.BytesIO(image)) as decoded:
                        decoded.load()
                        valid = valid and decoded.format == 'PNG' and decoded.mode == label and decoded.size == (128, 128)
                except Exception:
                    valid = False
            check('Pillow abre as imagens RGB e RGBA resultantes', valid)

        invalid = {'image_png': b64(b'not a PNG'), 'envelope': envelope}
        status, cache, _ = common.request(port, BASE + '/steganography/embed', invalid, user_token)
        required('PNG inválido rejeitado', status, 400, cache)
        oversize, _ = make_fixture(257, 20, 2)
        status, cache, _ = common.request(port, BASE + '/steganography/embed',
                                          {'image_png': b64(oversize), 'envelope': envelope}, user_token)
        required('Dimensão acima do limite rejeitada', status, 400, cache)
        small, _ = make_fixture(2, 2, 2)
        status, cache, _ = common.request(port, BASE + '/steganography/embed',
                                          {'image_png': b64(small), 'envelope': envelope}, user_token)
        required('Capacidade insuficiente rejeitada', status, 400, cache)
        status, cache, _ = common.request(port, BASE + '/steganography/extract', {'image_png': b64(images['RGB'])})
        required('Anônimo rejeitado', status, 401, cache)
        status, cache, _ = common.request(port, BASE + '/steganography/extract',
                                          {'image_png': b64(images['RGB'])}, admin_token)
        required('Outro usuário não recupera envelope', status, 400, cache)
        tampered = tamper_hidden_payload(images['RGB'])
        status, cache, _ = common.request(port, BASE + '/steganography/extract', {'image_png': b64(tampered)}, user_token)
        required('Adulteração do conteúdo oculto detectada', status, 400, cache)
        status, cache, response = common.request(port, BASE + '/decrypt', {'envelope': envelope}, user_token)
        required('AES após esteganografia', status, 200, cache, condition=response.get('text') == message)
        status, cache, response = common.request(port, BASE + '/experimental/run',
                                                {'action': 'decrypt', 'key_id': toy['key_id'],
                                                 'ciphertext': toy['ciphertext']}, admin_token)
        required('Cifra didática após esteganografia', status, 200, cache, condition=response.get('text') == message)

        logs = subprocess.run(['docker', 'logs', '--since', started, name], capture_output=True, text=True, timeout=60)
        if logs.returncode:
            raise RuntimeError('Não foi possível inspecionar os logs da instância.')
        observed = logs.stdout + logs.stderr
        found = [key for key, value in values.items() if value and value in observed]
        check('Logs: valores sensíveis verificados ausentes', not found)
        print('LIMITAÇÃO | O valor interno das chaves não é retornado pela API e não pode ser procurado diretamente nos logs.')
    finally:
        if admin_id:
            try:
                common.set_admin(admin_id, False)
                print('Conta ADMIN fictícia rebaixada para USER; contas e sessões permanecem no banco.')
            except (RuntimeError, OSError, subprocess.TimeoutExpired):
                cleanup_failed = True
                print(f'ATENÇÃO: não foi possível rebaixar {admin_email}; inspecione o banco de desenvolvimento.', file=sys.stderr)
        if container_started:
            try:
                stopped = subprocess.run(['docker', 'stop', name], capture_output=True, text=True, timeout=30)
                if stopped.returncode:
                    state = subprocess.run(['docker', 'inspect', '--format', '{{.State.Running}}', name],
                                           capture_output=True, text=True, timeout=20)
                    if state.returncode == 0 and state.stdout.strip() == 'true':
                        cleanup_failed = True
                        print(f'ATENÇÃO: contêiner temporário {name} continua em execução.', file=sys.stderr)
            except (OSError, subprocess.TimeoutExpired):
                cleanup_failed = True
                print(f'ATENÇÃO: não foi possível parar o contêiner {name}.', file=sys.stderr)
        if cleanup_failed:
            raise RuntimeError('Falha na finalização; confira os avisos.')
    print('Validação HTTP concluída; confira os cenários PASS e eventuais SKIP acima.')


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as exc:
        print('Teste interrompido:', exc, file=sys.stderr)
        sys.exit(1)
    except (OSError, subprocess.TimeoutExpired, KeyError, ValueError, http.client.HTTPException,
            zlib.error, struct.error):
        # Não refletir respostas da API, imagens, segredos ou tokens em erros.
        print('Teste interrompido. Confira o último cenário FAIL ou a disponibilidade do Docker/banco/imagem.', file=sys.stderr)
        sys.exit(1)
