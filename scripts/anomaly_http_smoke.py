"""Validação HTTP da Etapa 6 em Docker descartável; não usa banco principal.

Requer imagens locais fink-backend-api e postgres:16 e Python 3. Não monta
código no contêiner. A rede dedicada não é uma barreira geral de saída; nenhum
serviço externo é usado. O HTTP não comprova por si só ausência de vazamento
entre treino e teste: o catálogo determinístico da imagem também é auditado.
Logs são inspecionados apenas para marcadores conhecidos desta execução.
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

import attacks_http_smoke as common
import steganography_http_smoke as stego

BASE = '/api/v1/crypto-lab'
ANOMALY = BASE + '/anomalies'
ATTACK = BASE + '/attacks/runs'
PROFILE = {'profile': 'synthetic-security-v1'}
FILES = tuple(dict.fromkeys(common.NAMES + (
    'app/crypto_lab/heavy_capacity.py', 'app/api/deps.py', 'app/core/security_logging.py',
    *(f'app/crypto_lab/anomaly_lab/{n}.py' for n in
      ('__init__', 'generator', 'features', 'models', 'evaluation', 'runner', 'worker', 'schemas', 'routes')))))

# Real worker, stopped before exceeding its timeout; docker exec runs only in a
# disposable test container. READY is emitted only after SIGSTOP succeeds.
MONITOR = r'''
import json,os,signal,time
end=time.monotonic()+15
pid=None
while time.monotonic()<end and pid is None:
    for item in os.listdir('/proc'):
        if not item.isdigit(): continue
        try:
            args=open('/proc/'+item+'/cmdline','rb').read().split(b'\0')
            if TARGET in args and b'-m' in args:
                pid=int(item); os.kill(pid,signal.SIGSTOP); break
        except (OSError,ProcessLookupError): pass
    if pid is None: time.sleep(.01)
if pid is None:
    print('NOT_SEEN',flush=True); raise SystemExit(0)
print('READY',flush=True)
end=time.monotonic()+15
while time.monotonic()<end:
    try:
        state=open('/proc/%d/stat'%pid).read().split(') ',1)[1][0]
        if state=='Z': break
    except FileNotFoundError: break
    time.sleep(.05)
else:
    print(json.dumps({'terminated':False}),flush=True); raise SystemExit(0)
print(json.dumps({'terminated':True}),flush=True)
'''

# Supervisor PID 1 remains alive; only the observed worker's actual Uvicorn
# parent receives SIGKILL. A zombie counts as terminated, not as reaped.
PARENT_DEATH = r'''
import json,os,signal,time
end=time.monotonic()+15
pid=None
while time.monotonic()<end and pid is None:
    for item in os.listdir('/proc'):
        if not item.isdigit(): continue
        try:
            args=open('/proc/'+item+'/cmdline','rb').read().split(b'\0')
            if b'app.crypto_lab.anomaly_lab.worker' not in args or b'-m' not in args: continue
            candidate=int(item)
            parent=int(open('/proc/%d/stat'%candidate).read().split(') ',1)[1].split()[1])
            pargs=open('/proc/%d/cmdline'%parent,'rb').read().split(b'\0')
            if b'uvicorn' in pargs and b'app.main:app' in pargs:
                pid=candidate; break
        except (OSError,IndexError): pass
    if pid is None: time.sleep(.01)
if pid is None:
    print(json.dumps({'seen':False,'terminated':False}),flush=True); raise SystemExit
# Permit worker initialization of its parent-death signal.
time.sleep(.15)
try:
    os.kill(pid,signal.SIGSTOP)
    os.kill(parent,signal.SIGKILL)
except ProcessLookupError:
    print(json.dumps({'seen':False,'terminated':False}),flush=True); raise SystemExit
end=time.monotonic()+5
while time.monotonic()<end:
    try:
        state=open('/proc/%d/stat'%pid).read().split(') ',1)[1][0]
        if state=='Z': break
    except FileNotFoundError: break
    time.sleep(.05)
else:
    print(json.dumps({'seen':True,'terminated':False}),flush=True); raise SystemExit
print(json.dumps({'seen':True,'terminated':True}),flush=True)
'''

DATA_AUDIT = r'''
import json
from collections import Counter
from app.crypto_lab.anomaly_lab.generator import generate
from app.crypto_lab.anomaly_lab.features import FEATURE_NAMES
r=generate()['rows']
names=('train','calibration','validation','test')
parts={p:[x for x in r if x['partition']==p] for p in names}
stream={p:{x['synthetic_stream_id'] for x in parts[p]} for p in names}
episode={p:{x['episode_id'] for x in parts[p]} for p in names}
times={p:[x['window_start'] for x in parts[p]] for p in names}
ok=(len(r)==6000 and all(not stream[a]&stream[b] and not episode[a]&episode[b]
   and max(times[a]) < min(times[b]) for i,a in enumerate(names) for b in names[i+1:])
   and all(x['label']==0 for p in names[:2] for x in parts[p])
   and all(Counter(x['label'] for x in parts[p])=={0:540,1:60} for p in names[2:])
   and not ({'label','family','episode_id','synthetic_stream_id','window_start','partition'} & set(FEATURE_NAMES)))
print(json.dumps({'separated':ok}))
'''


def ratio_ok(value, numerator, denominator):
    return (value['numerator'] == numerator and value['denominator'] == denominator
            and ((denominator == 0 and value['value'] is None and value['undefined_reason'] == 'zero_denominator')
                 or (denominator > 0 and value['undefined_reason'] is None
                     and math.isclose(value['value'], numerator / denominator, rel_tol=1e-9, abs_tol=1e-12))))


def metrics_ok(result, sklearn_version):
    if (result['scope'] != 'synthetic_only' or result['schema_version'] != 1
            or result['profile'] != PROFILE['profile'] or result['window_seconds'] != 300
            or result['library_versions']['scikit_learn'] != sklearn_version
            or result['partition_sizes'] != {'train': 4200, 'calibration': 600, 'validation': 600, 'test': 600}
            or set(result['methods']) != {'isolation_forest', 'robust_baseline'}):
        return False
    for m in result['methods'].values():
        if m['quantile'] != .99 or m['quantile_method'] != 'linear' or m['comparison'] != 'score > threshold':
            return False
        for name, expected in (('train', (4200, 0)), ('calibration', (600, 0)),
                               ('validation', (540, 60)), ('test', (540, 60))):
            s = m['partitions'][name]
            tn, fp, fn, tp = s['TN'], s['FP'], s['FN'], s['TP']
            if not (all(isinstance(n, int) and n >= 0 for n in (tn, fp, fn, tp))
                    and s['matrix'] == [[tn, fp], [fn, tp]]
                    and s['matrix_axes'] == 'actual_rows_predicted_columns'
                    and (tn + fp, fn + tp) == expected
                    and (s['normal_support'], s['anomaly_support']) == expected
                    and s['alerts'] == tp + fp
                    and ratio_ok(s['precision'], tp, tp + fp)
                    and ratio_ok(s['recall'], tp, tp + fn)
                    and ratio_ok(s['f1'], 2 * tp, 2 * tp + fp + fn)
                    and ratio_ok(s['false_positive_rate'], fp, fp + tn)
                    and ratio_ok(s['prevalence'], tp + fn, tn + fp + fn + tp)):
                return False
    return True


def start(port, token, path, body):
    status, cache, response = common.request(port, path, body, token)
    if status != 202 or cache != 'no-store' or response.get('status') != 'running':
        raise RuntimeError(f'Início de trabalho retornou HTTP {status}')
    return str(uuid.UUID(response['job_id']))


def poll(port, token, job_id, deadline=130):
    limit = time.monotonic() + deadline
    while time.monotonic() < limit:
        status, cache, body = common.request(port, ANOMALY + '/jobs/' + job_id, token=token, method='GET')
        if status != 200 or cache != 'no-store': raise RuntimeError(f'Consulta retornou HTTP {status}')
        if body.get('status') != 'running': return body
        time.sleep(2.1)
    raise RuntimeError('Consulta excedeu prazo')


def wait_cooldown(started):
    delay = 60.5 - (time.monotonic() - started)
    if delay > 0:
        print(f'INFO | Respeitando intervalo de 60 s entre trabalhos ({delay:.1f} s restantes)', flush=True)
        time.sleep(delay)


def monitor(name, target):
    code = 'TARGET = ' + repr(target.encode()) + '\n' + MONITOR
    return subprocess.Popen(['docker', 'exec', name, 'python', '-c', code], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)


def status_check(smoke, label, value, expected):
    code, cache, body = value
    smoke.report(label, code == expected and cache == 'no-store', f'HTTP {code}')
    return body


def main():
    smoke = common.Smoke()
    password = 'Ficticio-' + secrets.token_urlsafe(24)
    message = 'Somente texto ficticio ' + smoke.tag
    marker = 'MARCADOR-PRIVADO-' + secrets.token_hex(12)
    smoke.values.update(password=password, message=message, marker=marker)
    try:
        common.docker('version', '--format', '{{.Server.Version}}')
        image = common.docker('image', 'inspect', '--format', '{{.Id}}', common.IMAGE).stdout.strip()
        common.docker('image', 'inspect', 'postgres:16')
        print('Imagem API:', image, flush=True)
        smoke.create_db()
        flags = {'CRYPTO_LAB_ANOMALY_ENABLED': 'true'}
        name, port = smoke.instance('anomaly-main', flags)
        probe = ('import hashlib,json,pathlib; n=' + repr(FILES) + '; '
                 'print(json.dumps({x:hashlib.sha256(pathlib.Path("/app",x).read_bytes()).hexdigest() for x in n}))')
        actual = json.loads(common.docker('exec', name, 'python', '-c', probe).stdout)
        if not smoke.report('Imagem corresponde ao código local das Etapas 5 e 6',
                            all(hashlib.sha256((common.ROOT / n).read_bytes()).hexdigest() == actual[n] for n in FILES)):
            raise RuntimeError('Reconstrua a imagem da API; hashes divergentes')
        version = common.docker('exec', name, 'python', '-c', 'import sklearn; print(sklearn.__version__)').stdout.strip()
        common.docker('exec', name, 'python', '-c',
                      'import asyncio; from app.shared.database import init_db; asyncio.run(init_db(create_all=True))')
        email_a, id_a = smoke.user(port, 'admin-a', password)
        email_b, id_b = smoke.user(port, 'admin-b', password)
        email_user, _ = smoke.user(port, 'user', password)
        smoke.values.update(email_a=email_a, email_b=email_b, email_user=email_user)
        sql = "UPDATE pessoa SET admin=TRUE WHERE id_pessoa IN ('%s','%s') RETURNING id_pessoa;" % (id_a, id_b)
        updated = common.docker('exec', '-i', smoke.db, 'psql', '-X', '-q', '-t', '-A', '-v', 'ON_ERROR_STOP=1',
                                '-U', 'fink', '-d', 'fink', input_text=sql).stdout.split()
        if set(updated) != {id_a, id_b}: raise RuntimeError('Falha ao criar ADMIN no banco descartável')
        admin_a = smoke.login(port, email_a, password)
        admin_b = smoke.login(port, email_b, password)
        user = smoke.login(port, email_user, password)
        smoke.values.update(admin_a=admin_a, admin_b=admin_b, user=user)
        smoke.report('PostgreSQL e três contas fictícias isolados', True)

        status_check(smoke, 'Anônimo rejeitado', common.request(port, ANOMALY + '/datasets', PROFILE), 401)
        status_check(smoke, 'USER rejeitado', common.request(port, ANOMALY + '/datasets', PROFILE, user), 403)
        for label, data in (('Campo extra', {**PROFILE, 'plaintext': marker}),
                            ('Dados arbitrários', {'profile': marker}),
                            ('Entrada em vez de dataset', {'dataset_id': marker, 'events': [marker]})):
            path = '/runs' if 'dataset_id' in data else '/datasets'
            status, cache, body = common.request(port, ANOMALY + path, data, admin_a)
            smoke.report(label + ' rejeitado sem reflexão', status == 422 and cache == 'no-store'
                         and marker not in json.dumps(body), f'HTTP {status}')
        status, cache, body = common.request(port, ANOMALY + '/datasets', token=admin_a,
                                             raw=json.dumps({'data': marker, 'padding': 'x' * 1025}).encode())
        smoke.report('Corpo acima de 1.024 bytes rejeitado sem reflexão', status == 413
                     and cache == 'no-store' and marker not in json.dumps(body), f'HTTP {status}')
        for i, flag in enumerate(('CRYPTO_LAB_ENABLED', 'CRYPTO_LAB_ANOMALY_ENABLED')):
            options = dict(flags)
            options[flag] = 'false'
            _, p = smoke.instance('anomaly-flag' + str(i), options)
            status_check(smoke, flag + ' desabilitada', common.request(p, ANOMALY + '/datasets', PROFILE, admin_a), 503)

        status, _, aes = common.request(port, BASE + '/encrypt', {'text': message}, user)
        if status != 200: raise RuntimeError('AES de teste indisponível')
        envelope = aes['envelope']
        smoke.values.update(aes_ciphertext=envelope['ciphertext'], aes_nonce=envelope['nonce'])
        status, _, toy = common.request(port, BASE + '/experimental/run', {'action': 'encrypt', 'text': message}, admin_a)
        if status != 200: raise RuntimeError('Cifra didática de teste indisponível')
        smoke.values['toy_ciphertext'] = toy['ciphertext']
        png, _ = stego.make_fixture(128, 128, 2)
        encoded = base64.b64encode(png).decode()
        smoke.values['png_input'] = encoded
        status, _, hidden = common.request(port, BASE + '/steganography/embed',
                                           {'image_png': encoded, 'envelope': envelope}, user)
        if status != 200: raise RuntimeError('Esteganografia de teste indisponível')
        smoke.values['png_output'] = hidden['image_png']
        smoke.report('Fluxos criptográficos existentes antes da análise', True)

        dataset_started = time.monotonic()
        job_id = start(port, admin_a, ANOMALY + '/datasets', PROFILE)
        job = poll(port, admin_a, job_id)
        ok = (job.get('status') == 'completed' and job.get('scope') == 'synthetic_only'
              and job.get('metadata', {}).get('window_count') == 6000
              and job.get('metadata', {}).get('profile') == PROFILE['profile']
              and job.get('metadata', {}).get('window_seconds') == 300
              and 0 <= job.get('metadata', {}).get('event_count', -1) <= 192000)
        if not smoke.report('ADMIN gera dataset sintético HTTP', ok, 'estado ' + str(job.get('status'))):
            raise RuntimeError('Dataset não foi produzido')
        dataset_id = str(uuid.UUID(job['dataset_id']))
        status_check(smoke, 'Outro ADMIN não acessa job',
                     common.request(port, ANOMALY + '/jobs/' + job_id, token=admin_b, method='GET'), 404)
        status_check(smoke, 'Outro ADMIN não usa dataset alheio',
                     common.request(port, ANOMALY + '/runs', {'dataset_id': dataset_id}, admin_b), 404)
        audit = json.loads(common.docker('exec', name, 'python', '-c', DATA_AUDIT, timeout=40).stdout)
        smoke.report('Auditoria do catálogo da imagem: partições, episódios e fluxos separados', audit['separated'])
        smoke.skip('Comprovação independente da ausência de vazamento no treinamento HTTP',
                   'HTTP expõe somente agregados; auditoria do gerador não observa diretamente fit/calibração')

        # Stage 5 must remain operational after generation, in the same API instance.
        attack_id = smoke.start(port, admin_a, 'statistics')
        attack = smoke.poll(port, admin_a, attack_id)
        smoke.report('Ataque didático após geração', common.metrics_ok('statistics', attack))

        # Freeze a real anomaly child to make the cross-stage admission test deterministic.
        timeout_name, timeout_port = smoke.instance('anomaly-timeout',
            {**flags, 'CRYPTO_LAB_ANOMALY_TIMEOUT_SECONDS': '4'})
        watcher = monitor(timeout_name, 'app.crypto_lab.anomaly_lab.worker')
        time.sleep(.25)
        timeout_job = start(timeout_port, admin_a, ANOMALY + '/datasets', PROFILE)
        observed = watcher.stdout.readline().strip()
        if observed == 'READY':
            status_check(smoke, 'Etapa 5 recusada durante trabalho da Etapa 6',
                         common.request(timeout_port, ATTACK, {'experiment': 'statistics'}, admin_b), 503)
        else:
            smoke.skip('Concorrência Etapa 6 → Etapa 5', 'filho de anomalia não observado em execução')
        timeout_result = poll(timeout_port, admin_a, timeout_job, 25)
        tail, _ = watcher.communicate(timeout=25)
        watched = json.loads(tail) if observed == 'READY' and watcher.returncode == 0 else {}
        smoke.report('Timeout de anomalia e encerramento observado do filho',
                     timeout_result.get('status') == 'timed_out' and watched.get('terminated') is True)

        attack_name, attack_port = smoke.instance('anomaly-shared-reverse', flags, timeout=4)
        reverse = monitor(attack_name, 'app.crypto_lab.attacks.worker')
        time.sleep(.25)
        busy_attack_id = smoke.start(attack_port, admin_a, 'avalanche')
        observed = reverse.stdout.readline().strip()
        if observed == 'READY':
            status_check(smoke, 'Etapa 6 recusada durante trabalho da Etapa 5',
                         common.request(attack_port, ANOMALY + '/datasets', PROFILE, admin_b), 503)
        else:
            smoke.skip('Concorrência Etapa 5 → Etapa 6', 'filho de ataque não observado em execução')
        attack_done = smoke.poll(attack_port, admin_a, busy_attack_id, seconds=25)
        tail, _ = reverse.communicate(timeout=25)
        reverse_result = json.loads(tail) if observed == 'READY' and reverse.returncode == 0 else {}
        smoke.report('Limpeza do filho de ataque controlado', attack_done.get('status') == 'timed_out'
                     and reverse_result.get('terminated') is True)

        crash_name, crash_port = smoke.instance('anomaly-crash', flags, supervised=True)
        death = subprocess.Popen(['docker', 'exec', crash_name, 'python', '-c', PARENT_DEATH],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(.25)
        start(crash_port, admin_a, ANOMALY + '/datasets', PROFILE)
        output, _ = death.communicate(timeout=25)
        crash_result = json.loads(output) if death.returncode == 0 else {}
        alive = json.loads(common.docker('inspect', crash_name).stdout)[0]['State']['Running']
        if crash_result.get('seen'):
            smoke.report('SIGKILL da API de anomalias encerra o filho com contêiner ativo',
                         crash_result.get('terminated') is True and alive)
        else:
            smoke.skip('SIGKILL da API de anomalias', 'filho não observado ativo antes do sinal')

        wait_cooldown(dataset_started)
        training_job = start(port, admin_a, ANOMALY + '/runs', {'dataset_id': dataset_id})
        trained = poll(port, admin_a, training_job)
        if not smoke.report('Treinamento e avaliação por HTTP', trained.get('status') == 'completed',
                            'estado ' + str(trained.get('status'))):
            raise RuntimeError('Análise não foi concluída')
        result_id = str(uuid.UUID(trained['result_id']))
        status, cache, body = common.request(port, ANOMALY + '/results/' + result_id, token=admin_a, method='GET')
        try:
            valid = status == 200 and cache == 'no-store' and body['result_id'] == result_id and metrics_ok(body['result'], version)
        except (KeyError, TypeError, ValueError):
            valid = False
        smoke.report('Versões, partições, matrizes e métricas HTTP consistentes', valid)
        if valid:
            for model, metrics in body['result']['methods'].items():
                test = metrics['partitions']['test']
                print(f"INFO | {model} | matriz teste {test['matrix']} | precisão {test['precision']['value']}"
                      f" | recall {test['recall']['value']} | F1 {test['f1']['value']}", flush=True)
        status_check(smoke, 'Outro ADMIN não consulta resultado alheio',
                     common.request(port, ANOMALY + '/results/' + result_id, token=admin_b, method='GET'), 404)

        attack_after_id = smoke.start(port, admin_b, 'statistics')
        attack_after = smoke.poll(port, admin_b, attack_after_id)
        smoke.report('Ataque didático após treinamento e avaliação', common.metrics_ok('statistics', attack_after))
        status, _, recovered = common.request(port, BASE + '/decrypt', {'envelope': envelope}, user)
        smoke.report('AES após análise', status == 200 and recovered.get('text') == message)
        status, _, recovered = common.request(port, BASE + '/experimental/run',
            {'action': 'decrypt', 'key_id': toy['key_id'], 'ciphertext': toy['ciphertext']}, admin_a)
        smoke.report('Cifra didática após análise', status == 200 and recovered.get('text') == message)
        status, _, recovered = common.request(port, BASE + '/steganography/extract',
                                             {'image_png': hidden['image_png']}, user)
        smoke.report('Esteganografia após análise', status == 200 and recovered.get('envelope') == envelope)
        smoke.logs()
    except (RuntimeError, OSError, subprocess.TimeoutExpired, http.client.HTTPException,
            KeyError, ValueError, TypeError) as exc:
        smoke.failures += 1
        print('FAIL | Execução interrompida | ' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__),
              file=sys.stderr, flush=True)
        smoke.skip('Cenários posteriores', 'interrompidos por falha anterior')
    finally:
        try: smoke.cleanup()
        except (OSError, subprocess.TimeoutExpired):
            smoke.failures += 1
            print('FAIL | Limpeza: verifique recursos temporários', file=sys.stderr, flush=True)
    print(f'Resultado: {smoke.failures} FAIL; {smoke.skips} SKIP.', flush=True)
    return 1 if smoke.failures else 0


if __name__ == '__main__':
    sys.exit(main())
