"""HTTP real da Etapa 5 em infraestrutura descartável.

Requer imagens locais fink-backend-api e postgres:16, Docker e Python 3 no host.
Cria rede dedicada, PostgreSQL em tmpfs e APIs em portas efêmeras de loopback;
não usa o banco, volumes ou API existentes. Não imprime respostas sensíveis.
A verificação de plataforma não Linux é simulada e a inspeção de logs é limitada
às instâncias criadas e aos valores conhecidos desta execução.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import math
import secrets
import subprocess
import sys
import time
import uuid
from pathlib import Path

import steganography_http_smoke as stego

ROOT = Path(__file__).resolve().parent.parent
IMAGE = 'fink-backend-api'
BASE = '/api/v1/crypto-lab'
RUNS = BASE + '/attacks/runs'
NAMES = ('app/main.py', 'app/core/settings.py', 'app/crypto_lab/middleware.py',
         'app/crypto_lab/routes.py', 'app/crypto_lab/toy_cipher.py', 'app/crypto_lab/steganography.py',
         *(f'app/crypto_lab/attacks/{x}.py' for x in
           ('__init__', 'routes', 'runner', 'worker', 'brute_force', 'statistics', 'differential',
            'avalanche', 'fixtures', 'results')))


def docker(*args, input_text=None, timeout=40, check=True):
    p = subprocess.run(['docker', *args], input=input_text, capture_output=True, text=True,
                       timeout=timeout, cwd=ROOT)
    if check and p.returncode:
        raise RuntimeError('Comando Docker falhou: ' + args[0])
    return p


def request(port, path, obj=None, token=None, method='POST', raw=None):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=20)
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    data = raw if raw is not None else (json.dumps(obj).encode() if obj is not None else None)
    try:
        conn.request(method, path, data, headers)
        response = conn.getresponse()
        payload = response.read()
        try:
            parsed = json.loads(payload)
        except (ValueError, UnicodeError):
            parsed = {}
        return response.status, response.getheader('Cache-Control', '').lower(), parsed
    finally:
        conn.close()


class Smoke:
    def __init__(self):
        self.tag = uuid.uuid4().hex[:12]
        self.network = 'fink-attacks-net-' + self.tag
        self.db = 'fink-attacks-db-' + self.tag
        self.containers = []
        self.failures = 0
        self.skips = 0
        self.values = {}
        self.network_created = False

    def report(self, label, ok, detail=''):
        print(('PASS' if ok else 'FAIL') + ' | ' + label + (' | ' + detail if detail else ''), flush=True)
        self.failures += not ok
        return ok

    def skip(self, label, reason):
        self.skips += 1
        print('SKIP | ' + label + ' | ' + reason, flush=True)

    def create_db(self):
        docker('network', 'create', self.network)
        self.network_created = True
        self.containers.append(self.db)
        docker('run', '-d', '--pull=never', '--name', self.db, '--network', self.network,
               '--network-alias', 'postgres', '--tmpfs', '/var/lib/postgresql/data:rw',
               '-e', 'POSTGRES_USER=fink', '-e', 'POSTGRES_PASSWORD=fink', '-e', 'POSTGRES_DB=fink', 'postgres:16')
        for _ in range(120):
            if docker('exec', self.db, 'pg_isready', '-U', 'fink', '-d', 'fink', check=False).returncode == 0:
                return
            time.sleep(.25)
        raise RuntimeError('PostgreSQL temporário não ficou pronto')

    def instance(self, label, flags=None, timeout=None, supervised=False):
        name = f'fink-attacks-{self.tag}-{label}'
        self.containers.append(name)
        env = {'ENVIRONMENT': 'development', 'DEBUG': 'false', 'CRYPTO_LAB_WORKERS': '1',
               'CRYPTO_LAB_INSTANCES': '1', 'CRYPTO_LAB_ENABLED': 'true',
               'CRYPTO_LAB_EXPERIMENTAL_ENABLED': 'true', 'CRYPTO_LAB_ATTACKS_ENABLED': 'true',
               'DATABASE_URL': 'postgresql+asyncpg://fink:fink@postgres:5432/fink'}
        env.update(flags or {})
        if timeout is not None:
            env['CRYPTO_LAB_ATTACKS_TIMEOUT_SECONDS'] = str(timeout)
        args = ['run', '-d', '--pull=never', '--name', name, '--network', self.network,
                '-p', '127.0.0.1::8000']
        for key, value in env.items():
            args.extend(['-e', f'{key}={value}'])
        uvicorn = ['-m', 'uvicorn', 'app.main:app', '--host', '0.0.0.0', '--port', '8000',
                   '--workers', '1', '--lifespan', 'off']
        if supervised:
            # Keep PID 1 alive after Uvicorn dies, so Docker cannot mask an orphan.
            wrapper = ('import subprocess,sys,time; p=subprocess.Popen([sys.executable]+'
                       + repr(uvicorn) + '); p.wait(); time.sleep(30)')
            docker(*args, '--entrypoint', 'python', IMAGE, '-c', wrapper)
        else:
            docker(*args, '--entrypoint', 'python', IMAGE, *uvicorn)
        inspect = json.loads(docker('inspect', name).stdout)[0]
        published = inspect['NetworkSettings']['Ports']
        bindings = published.get('8000/tcp') or []
        all_bindings = [binding for mappings in published.values() if mappings for binding in mappings]
        if not self.report(f'Publicação exclusiva em loopback ({label})',
                           len(bindings) == 1 and all(b['HostIp'] == '127.0.0.1' for b in all_bindings),
                           f'mapeamentos: {bindings}; ativa: {inspect["State"]["Running"]}'):
            raise RuntimeError('Porta não publicada exclusivamente em loopback')
        port = int(bindings[0]['HostPort'])
        for _ in range(80):
            try:
                if request(port, '/health', method='GET')[0] == 200:
                    return name, port
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(.25)
        raise RuntimeError('API temporária não ficou pronta')

    def user(self, port, label, password):
        email = f'{label}-{self.tag}@example.com'
        person = {'email': email, 'senha': password, 'nome': 'Teste Ficticio', 'data_nascimento': '2000-01-01',
                  'telefone': '81999999999', 'genero': 'nao_informado', 'estado': 'PE', 'cidade': 'Recife',
                  'rua': 'Rua de Teste', 'numero': '1', 'cep': '50000000'}
        status, _, body = request(port, '/api/v1/pessoas/', person)
        if status != 201:
            raise RuntimeError(f'Cadastro fictício falhou: HTTP {status}')
        return email, str(uuid.UUID(body['id_pessoa']))

    def login(self, port, email, password):
        status, _, body = request(port, '/api/v1/sessoes/login', {'email': email, 'senha': password})
        if status != 201 or not isinstance(body.get('token'), str):
            raise RuntimeError('Login de teste falhou')
        return body['token']

    def start(self, port, token, experiment):
        status, cache, body = request(port, RUNS, {'experiment': experiment}, token)
        if status != 202 or cache != 'no-store' or body.get('status') != 'running':
            raise RuntimeError(f'{experiment}: início falhou (HTTP {status})')
        return str(uuid.UUID(body['run_id']))

    def poll(self, port, token, run_id, seconds=130):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            status, cache, body = request(port, RUNS + '/' + run_id, token=token, method='GET')
            if status != 200 or cache != 'no-store':
                raise RuntimeError(f'Consulta falhou (HTTP {status})')
            if body.get('status') != 'running':
                return body
            time.sleep(2.1)  # abaixo de 60 consultas por minuto
        raise RuntimeError('Consulta excedeu prazo de espera')

    def logs(self):
        ok = True
        for name in self.containers:
            out = docker('logs', name, check=False)
            if out.returncode:
                ok = False
                continue
            text = out.stdout + out.stderr
            if any(value and value in text for value in self.values.values()):
                ok = False
        self.report('Logs dos contêineres: valores conhecidos ausentes', ok)
        self.skip('Verificação direta de chaves internas nos logs', 'valores não são expostos ao cliente')
        print('LIMITAÇÃO | A inspeção não cobre logs externos, dumps ou valores internos desconhecidos.', flush=True)

    def cleanup(self):
        ok = True
        for name in reversed(self.containers):
            result = docker('rm', '-f', name, timeout=30, check=False)
            if result.returncode and docker('inspect', name, check=False).returncode == 0:
                ok = False
        if self.network_created:
            ok &= docker('network', 'rm', self.network, check=False).returncode == 0
        self.report('Limpeza dos contêineres e rede temporários', ok)


def bit_metrics(m, expected):
    h = m['histogram_bits_changed']
    return (m['pairs'] == expected and m['bits_per_pair'] == 64 and len(h) == 65 and sum(h) == expected
            and m['output_bit_denominator'] == expected and len(m['output_bit_changed_counts']) == 64
            and all(0 <= n <= expected for n in m['output_bit_changed_counts'])
            and math.isclose(m['mean_percent'], sum(i * n for i, n in enumerate(h)) * 100 / (64 * expected))
            and 0 <= m['min_percent'] <= m['mean_percent'] <= m['max_percent'] <= 100
            and m['population_stddev_percent'] >= 0)


def metrics_ok(experiment, response):
    if not (response.get('status') == 'completed' and response.get('algorithm') == 'TOY-V1-INSECURE'
            and response.get('schema_version') == 1 and response.get('catalog_version') == 'synthetic-v1'
            and response.get('experiment') == experiment and response.get('duration_seconds', -1) >= 0):
        return False
    m = response['metrics']
    if experiment == 'brute_force':
        return (m['attempts'] == m['key_space'] == 65536 and m['target_found'] is True
                and m['duration_seconds'] > 0 and math.isclose(m['keys_per_second'], 65536 / m['duration_seconds'])
                and 1 <= m['second_pair_candidates'] <= m['first_pair_candidates'] <= 65536
                and m['second_pair_checks'] == m['first_pair_candidates'])
    if experiment == 'statistics':
        return (m['byte_denominator'] == 10240 and len(m['byte_counts']) == 256
                and sum(m['byte_counts']) == 10240
                and all(math.isclose(f, n / 10240) for n, f in zip(m['byte_counts'], m['byte_frequencies']))
                and len(m['byte_frequencies']) == 256 and len(m['groups']['repeated']['per_key']) == 32
                and all(v['repeated_excess'] == 3 and v['positions_equal_to_first'] == 4
                        for v in m['groups']['repeated']['per_key']))
    p = m['propagation']
    if not (bit_metrics(m['plaintext_bit_flips'], 65536) and p['padding_included'] is False
            and p['offsets'] == list(range(-3, 4)) and sum(p['comparisons']) == 32768
            and all(v == 0 for i, v in enumerate(p['changed_blocks']) if i != 3)):
        return False
    return experiment != 'avalanche' or bit_metrics(m['key_bit_flips'], 16384)

MONITOR = r'''
import json,os,signal,time
end=time.monotonic()+12
pid=None
while time.monotonic()<end and pid is None:
    for entry in os.listdir('/proc'):
        if not entry.isdigit(): continue
        try:
            args=open('/proc/'+entry+'/cmdline','rb').read().split(b'\0')
            if b'app.crypto_lab.attacks.worker' in args and b'-m' in args:
                pid=int(entry); os.kill(pid,signal.SIGSTOP); break
        except (OSError,ProcessLookupError): pass
    if pid is None: time.sleep(.02)
if pid is None:
    print(json.dumps({'seen':False,'terminated':False}),flush=True); raise SystemExit(0)
end=time.monotonic()+12
while time.monotonic()<end:
    try:
        state=open('/proc/%d/stat'%pid).read().split(') ',1)[1][0]
        if state=='Z': break
    except FileNotFoundError: break
    time.sleep(.05)
else:
    print(json.dumps({'seen':True,'terminated':False}),flush=True); raise SystemExit(0)
print(json.dumps({'seen':True,'terminated':True}),flush=True)
'''

# The container supervisor remains alive while the actual API parent is killed.
PARENT_DEATH = r'''
import json,os,signal,time
end=time.monotonic()+12
pid=None
while time.monotonic()<end and pid is None:
    for entry in os.listdir('/proc'):
        if not entry.isdigit(): continue
        try:
            args=open('/proc/'+entry+'/cmdline','rb').read().split(b'\0')
            if b'app.crypto_lab.attacks.worker' not in args or b'-m' not in args: continue
            candidate=int(entry)
            parent=int(open('/proc/%d/stat'%candidate).read().split(') ',1)[1].split()[1])
            parent_args=open('/proc/%d/cmdline'%parent,'rb').read().split(b'\0')
            if b'uvicorn' in parent_args and b'app.main:app' in parent_args:
                pid=candidate; break
        except (OSError,ProcessLookupError,IndexError): pass
    if pid is None: time.sleep(.02)
if pid is None:
    print(json.dumps({'seen':False,'terminated':False}),flush=True); raise SystemExit
# Verify the real worker is armed, then kill only its actual Uvicorn parent.
time.sleep(.2)
try:
    os.kill(parent,signal.SIGKILL)
except ProcessLookupError:
    print(json.dumps({'seen':False,'terminated':False}),flush=True); raise SystemExit
end=time.monotonic()+5
terminated=False
while time.monotonic()<end:
    try:
        state=open('/proc/%d/stat'%pid).read().split(') ',1)[1][0]
        if state=='Z': terminated=True; break
    except FileNotFoundError:
        terminated=True; break
    time.sleep(.05)
print(json.dumps({'seen':True,'terminated':terminated}),flush=True)
'''



def main():
    smoke = Smoke()
    password = 'Ficticio-' + secrets.token_urlsafe(22)
    message = 'Conteudo sintetico ' + smoke.tag
    smoke.values.update(password=password, message=message)
    try:
        docker('version', '--format', '{{.Server.Version}}')
        image = docker('image', 'inspect', '--format', '{{.Id}}', IMAGE).stdout.strip()
        docker('image', 'inspect', 'postgres:16')
        print('Imagem API:', image, flush=True)
        smoke.create_db()
        name, port = smoke.instance('principal')
        # Confirm that the image corresponds to the source being tested.
        probe = ('import hashlib,json,pathlib; n=' + repr(NAMES) + '; '
                 'print(json.dumps({x:hashlib.sha256(pathlib.Path("/app",x).read_bytes()).hexdigest() for x in n}))')
        image_hashes = json.loads(docker('exec', name, 'python', '-c', probe).stdout)
        if not smoke.report('Código da imagem corresponde aos arquivos locais',
                            all(hashlib.sha256((ROOT / n).read_bytes()).hexdigest() == image_hashes[n] for n in NAMES)):
            raise RuntimeError('Imagem desatualizada')
        docker('exec', name, 'python', '-c',
               'import asyncio; from app.shared.database import init_db; asyncio.run(init_db(create_all=True))')
        admin_email, admin_id = smoke.user(port, 'admin', password)
        user_email, _ = smoke.user(port, 'user', password)
        sql = f"UPDATE pessoa SET admin=TRUE WHERE id_pessoa='{admin_id}' RETURNING id_pessoa;"
        output = docker('exec', '-i', smoke.db, 'psql', '-X', '-q', '-t', '-A', '-v', 'ON_ERROR_STOP=1',
                        '-U', 'fink', '-d', 'fink', input_text=sql).stdout
        if admin_id not in output.split():
            raise RuntimeError('Não foi possível conceder ADMIN na base descartável')
        admin, user = smoke.login(port, admin_email, password), smoke.login(port, user_email, password)
        smoke.values.update(admin_token=admin, user_token=user)
        smoke.report('Banco e contas fictícias isolados', True)

        for label, token, expected in (('Anônimo', None, 401), ('USER', user, 403)):
            status, cache, _ = request(port, RUNS, {'experiment': 'statistics'}, token)
            smoke.report(label + ' rejeitado', status == expected and cache == 'no-store', f'HTTP {status}')
        status, cache, body = request(port, RUNS, {'experiment': 'statistics', 'plaintext': message}, admin)
        smoke.report('Campo extra rejeitado sem refletir conteúdo', status == 422 and cache == 'no-store'
                     and message not in json.dumps(body), f'HTTP {status}')
        status, cache, _ = request(port, RUNS, token=admin, raw=b' ' * 1025)
        smoke.report('Corpo acima de 1.024 bytes rejeitado', status == 413 and cache == 'no-store', f'HTTP {status}')
        for index, flag in enumerate(('CRYPTO_LAB_ENABLED', 'CRYPTO_LAB_EXPERIMENTAL_ENABLED',
                                      'CRYPTO_LAB_ATTACKS_ENABLED')):
            _, p = smoke.instance('flag' + str(index), {flag: 'false'})
            status, cache, _ = request(p, RUNS, {'experiment': 'statistics'}, admin)
            smoke.report(flag + ' desabilitada', status == 503 and cache == 'no-store', f'HTTP {status}')

        # Preserve both envelopes/keys only in memory, then recover after experiments.
        status, _, aes = request(port, BASE + '/encrypt', {'text': message}, user)
        if status != 200: raise RuntimeError('AES de teste não respondeu')
        envelope = aes['envelope']
        smoke.values.update(aes_ciphertext=envelope['ciphertext'], aes_nonce=envelope['nonce'])
        status, _, toy = request(port, BASE + '/experimental/run', {'action': 'encrypt', 'text': message}, admin)
        if status != 200: raise RuntimeError('Cifra didática de teste não respondeu')
        smoke.values['toy_ciphertext'] = toy['ciphertext']
        image_data, _ = stego.make_fixture(128, 128, 2)
        image64 = base64.b64encode(image_data).decode()
        smoke.values['input_png'] = image64
        status, _, hidden = request(port, BASE + '/steganography/embed',
                                    {'image_png': image64, 'envelope': envelope}, user)
        if status != 200: raise RuntimeError('Inserção esteganográfica não respondeu')
        smoke.values['output_png'] = hidden['image_png']
        smoke.report('AES, cifra didática e esteganografia antes dos experimentos', True)

        # The first run shares the instance with the preserved envelopes; further
        # instances avoid waiting 60 seconds between accepted runs.
        for experiment in ('brute_force', 'statistics', 'differential', 'avalanche'):
            if experiment == 'brute_force':
                experiment_port = port
            else:
                _, experiment_port = smoke.instance('exp-' + experiment.replace('_', '-'))
            run_id = smoke.start(experiment_port, admin, experiment)
            response = smoke.poll(experiment_port, admin, run_id)
            try:
                ok = metrics_ok(experiment, response)
            except (KeyError, TypeError, ValueError, ZeroDivisionError):
                ok = False
            smoke.report('Experimento HTTP ' + experiment + ' e métricas', ok,
                         'estado ' + str(response.get('status')))

        _, timeout_port = smoke.instance('timeout', timeout=3)
        timeout_name = smoke.containers[-1]
        watcher = subprocess.Popen(['docker', 'exec', timeout_name, 'python', '-c', MONITOR],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(.2)
        run_id = smoke.start(timeout_port, admin, 'avalanche')
        status, cache, _ = request(timeout_port, RUNS, {'experiment': 'brute_force'}, admin)
        smoke.report('Concorrência: segunda execução recusada', status == 503 and cache == 'no-store', f'HTTP {status}')
        result = smoke.poll(timeout_port, admin, run_id, seconds=20)
        out, _ = watcher.communicate(timeout=25)
        monitor = json.loads(out) if watcher.returncode == 0 else {}
        smoke.report('Timeout e encerramento do filho observado', result.get('status') == 'timed_out'
                     and 'metrics' not in result and monitor.get('seen') and monitor.get('terminated'),
                     'estado ' + str(result.get('status')))

        crash_name, crash_port = smoke.instance('crash', supervised=True)
        crash_watcher = subprocess.Popen(['docker', 'exec', crash_name, 'python', '-c', PARENT_DEATH],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(.2)
        smoke.start(crash_port, admin, 'avalanche')
        out, _ = crash_watcher.communicate(timeout=25)
        observed = json.loads(out) if crash_watcher.returncode == 0 else {}
        container_alive = json.loads(docker('inspect', crash_name).stdout)[0]['State']['Running']
        if observed.get('seen'):
            smoke.report('SIGKILL da API temporária encerra o filho com contêiner ainda ativo',
                         observed.get('terminated', False) and container_alive)
        else:
            smoke.skip('SIGKILL do pai', 'não foi possível observar o filho ativo antes do sinal')

        # Platform emulation covers the coordinator guard, not a real non-Linux OS.
        probe = """import asyncio
from unittest.mock import patch
from app.crypto_lab.attacks.runner import Coordinator, Busy
async def test():
    with patch('app.crypto_lab.attacks.runner.sys.platform', 'darwin'):
        try: Coordinator().start('test', 'statistics', 10)
        except Busy: print('rejected'); return
        print('accepted')
asyncio.run(test())
"""
        result = docker('exec', name, 'python', '-c', probe)
        smoke.report('Plataforma não Linux simulada: execução rejeitada', result.stdout.strip() == 'rejected')
        smoke.skip('Execução em sistema operacional não Linux real', 'Docker usa kernel Linux')

        status, _, recovered = request(port, BASE + '/decrypt', {'envelope': envelope}, user)
        smoke.report('AES após experimentos', status == 200 and recovered.get('text') == message)
        status, _, recovered = request(port, BASE + '/experimental/run',
                                       {'action': 'decrypt', 'key_id': toy['key_id'],
                                        'ciphertext': toy['ciphertext']}, admin)
        smoke.report('Cifra didática após experimentos', status == 200 and recovered.get('text') == message)
        status, _, recovered = request(port, BASE + '/steganography/extract',
                                       {'image_png': hidden['image_png']}, user)
        smoke.report('Esteganografia após experimentos', status == 200 and recovered.get('envelope') == envelope)
        smoke.logs()
    except (RuntimeError, OSError, subprocess.TimeoutExpired, http.client.HTTPException,
            KeyError, ValueError, TypeError) as exc:
        smoke.failures += 1
        print('FAIL | Execução interrompida | ' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__),
              file=sys.stderr, flush=True)
        print('SKIP | Cenários posteriores não executados', flush=True)
    finally:
        try:
            smoke.cleanup()
        except (OSError, subprocess.TimeoutExpired):
            smoke.failures += 1
            print('FAIL | Limpeza: verifique os contêineres temporários', file=sys.stderr, flush=True)
    print(f'Resultado: {smoke.failures} FAIL; {smoke.skips} SKIP.', flush=True)
    return 1 if smoke.failures else 0


if __name__ == '__main__':
    sys.exit(main())
