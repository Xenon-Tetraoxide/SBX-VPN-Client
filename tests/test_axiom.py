import argparse
import io
import json
import sqlite3
import subprocess
import uuid
from contextlib import closing
from email.message import Message
from pathlib import Path

import pytest

import sbx


FRANCE = 'France (x) [hy2]'
GERMANY = 'Germany (x) [reality]'
NETHERLANDS = 'Netherlands (Arco) [ws]'
TCP = 'Netherlands (Arco) [tcp]'
NAIVE = 'Netherlands (Arco) [http]'


def outbound(tag):
    return {'tag': tag, 'type': 'socks', 'server': 'proxy.example', 'server_port': 1080, 'version': '5'}


def config(*tags):
    return {'outbounds': [outbound(tag) for tag in tags]}


def state():
    return json.loads(json.dumps(sbx.DEFAULT_STATE))


@pytest.fixture
def app_directory(monkeypatch, tmp_path):
    directory = tmp_path / 'AxiOm data'
    directory.mkdir()
    db = directory / 'db.sqlite'
    with closing(sqlite3.connect(db)) as connection:
        connection.executescript((Path(__file__).parent / 'fixtures/axiom-v5.sql').read_text())
        connection.execute('PRAGMA journal_mode = WAL')
        connection.commit()
    monkeypatch.setenv('SBX_AXIOM_HOME', str(directory))
    return directory


def response(document, **headers):
    stream = io.BytesIO(json.dumps(document).encode())
    stream.headers = Message()
    for key, value in headers.items():
        stream.headers[key.replace('_', '-')] = value
    return stream


def test_brand(monkeypatch):
    monkeypatch.delenv('SBX_BRAND', raising=False)
    assert all(sbx.axiom_mode(entry) for entry in ('axiom', '/usr/bin/axiom', r'C:\Program Files\AxIoM.ExE', 'axiom.py'))
    assert not sbx.axiom_mode('/usr/bin/sbx.py')
    monkeypatch.setenv('SBX_BRAND', 'axiom')
    assert sbx.axiom_mode('sbx.py')


@pytest.mark.parametrize('windows', [False, True])
def test_remote_db_roundtrip(monkeypatch, app_directory, windows):
    monkeypatch.setattr(sbx, 'IS_WIN', windows)
    calls = []

    def urlopen(request, **kwargs):
        calls.append(request.full_url)
        assert request.get_header('User-agent') == (
            f'HiddifyNext/4.6.1 ({"windows" if windows else "linux"}) like ClashMeta v2ray sing-box')
        assert not any(header.lower().startswith('x-') for header in request.headers)
        return response(config(*((NETHERLANDS, FRANCE) if len(calls) == 1 else (TCP,))),
                        subscription_userinfo=f'upload=10; download={len(calls) * 100}; total=1000; expire=1800000000',
                        profile_update_interval='6', profile_title='Title', support_url='https://example.test/help')

    monkeypatch.setattr(sbx.urllib.request, 'urlopen', urlopen)
    profile_path = app_directory / 'db.sqlite'
    original_id = str(uuid.uuid4())
    with closing(sqlite3.connect(profile_path)) as db, db:
        db.execute('INSERT INTO profile_entries (id,type,active,name,last_update) VALUES (?, ?, ?, ?, ?)',
                   (original_id, 'local', 1, 'Old', '2026-01-02T03:04:05.000Z'))
    prefs_path = app_directory / sbx.AXIOM_FILE
    prefs_path.write_text(json.dumps({'flutter.region': 'other', 'flutter.preferences_version': 7,
                                      'flutter.server_selector_country': 'France'}))
    app = sbx.load_axiom_context()
    url = 'https://example.test/sub'
    name = sbx.write_axiom_profile(app, name='Свой', url=url)
    assert name == 'app:Свой'
    active, previous = app['profiles']
    assert active['type'] == 'remote' and active['active'] == 1 and previous['active'] == 0
    assert uuid.UUID(active['id']).version == 4
    assert (active['upload'], active['download'], active['total'], active['update_interval']) == (10, 100, 1000, 21600)
    assert active['expire'] == '2027-01-15T08:00:00.000Z'
    assert active['support_url'] == 'https://example.test/help'
    assert json.loads(active['populated_headers'])['profile-title'] == 'Title'
    assert json.loads(active['user_override'])['name'] == 'Свой'
    path = app_directory / 'configs' / f'{active["id"]}.json'
    assert json.loads(path.read_text(encoding='utf-8')) == config(NETHERLANDS, FRANCE)
    st = state()
    st['_axiom'] = app
    servers = sbx.all_servers(st)
    assert {server['source'] for server in servers} == {'app:Свой'}
    assert sbx.selected_server(st, servers) == FRANCE
    assert sbx.effective_route(st) == 'global'
    sbx.axiom_write_selection(app, ('Netherlands', 'vless', 'ws'))
    assert sbx.selected_server(st, servers) == NETHERLANDS
    sbx.axiom_write_selection(app, None)
    prefs = json.loads(prefs_path.read_text())
    assert prefs['flutter.preferences_version'] == 7
    assert prefs['flutter.region'] == 'other'
    assert prefs['flutter.server_selector_country'] == '__auto__'
    assert sbx.update_app_profiles(app, app['profiles'], quiet=True)
    assert app['profiles'][0]['name'] == 'Свой' and app['profiles'][0]['download'] == 200
    assert json.loads(path.read_text(encoding='utf-8')) == config(TCP)
    assert calls == [url, url]


def test_read_only_gate_and_lock(monkeypatch, app_directory):
    app = sbx.load_axiom_context()
    db_path = app_directory / 'db.sqlite'
    source = app_directory / 'source.json'
    source.write_text(json.dumps(config(FRANCE)))
    with closing(sqlite3.connect(db_path)) as other, other:
        other.execute('PRAGMA user_version = 6')
    readonly = sbx.load_axiom_context()
    with pytest.raises(ValueError, match='только для чтения'):
        sbx.write_axiom_profile(readonly, local=source)
    with pytest.raises(ValueError, match='только чтение'):
        sbx.write_axiom_profile(app, local=source)
    with closing(sqlite3.connect(db_path)) as other, other:
        other.execute('PRAGMA user_version = 5')
        other.execute('BEGIN EXCLUSIVE')
        with pytest.raises(sqlite3.OperationalError, match='locked'):
            sbx.write_axiom_profile(app, local=source)
    assert not (app_directory / 'configs').exists()


def test_profile_parsing_and_picker(monkeypatch, capsys):
    tags = [NETHERLANDS, NAIVE, GERMANY, FRANCE, TCP, 'Netherlands (b) [ws]', 'Netherlands (b) [grpc]']
    servers = [{'tag': tag, 'source': 'fixture', 'outbound': outbound(tag)} for tag in tags]
    options = sbx.axiom_options(servers)
    assert sbx.axiom_classify(GERMANY) is None
    assert sbx.axiom_classify('§hide§France (x) [HY]') == ('§hide§France', 'hysteria2', 'hy2')
    assert sbx.axiom_classify(' France (x) [HY] ') == ('France', 'hysteria2', 'hy2')
    assert sbx.axiom_classify('Canada (x) [shadowtls]') == ('Canada', 'shadowtls', 'stls')
    assert sbx.axiom_flag('France') == '🇫🇷' and sbx.axiom_flag('Moon') == '🏳️'
    assert [tag for _, tag in sbx.axiom_sorted(options)] == [FRANCE, TCP, NETHERLANDS, NAIVE]
    assert sbx.axiom_fastest(options, {NETHERLANDS: 20, FRANCE: 65000, TCP: 0, NAIVE: 25}) == NETHERLANDS
    assert sbx.axiom_fastest(options, {FRANCE: -1}) is None
    choices = iter(['2', '1', '2'])
    monkeypatch.setattr('builtins.input', lambda prompt: next(choices))
    assert sbx.pick_axiom(options) == NETHERLANDS
    output = capsys.readouterr().out
    assert '🇫🇷 France' in output and 'VLESS' in output and 'Reality (TCP)' in output and 'WebSocket' in output
    st = state()
    st['_axiom'] = {'root': None}
    st['latency'] = {FRANCE: 55, NETHERLANDS: 22, GERMANY: 3}
    cfg = sbx.build_config(st, servers)
    assert cfg['outbounds'][1]['outbounds'][0] == NETHERLANDS
    assert GERMANY in cfg['outbounds'][1]['outbounds']   # свои серверы не прячутся
    monkeypatch.setattr(sbx, 'all_servers', lambda _: servers)
    monkeypatch.setattr(sbx, 'is_active', lambda _: False)
    sbx.cmd_ls(st, argparse.Namespace(filter=None))
    output = capsys.readouterr().out
    assert 'QUIC' in output and 'HTTP/2 TLS' in output
    assert output.index('Свои серверы') < output.index('Germany')
    assert sbx.resolve(st, '1') == FRANCE


def test_profile_largest_group_and_detour(monkeypatch, app_directory):
    source = app_directory / 'profile.json'
    document = config(FRANCE, NETHERLANDS, TCP, 'chain')
    document['outbounds'][1]['detour'] = 'chain'
    document['outbounds'].extend([{'type': 'selector', 'tag': 'short', 'outbounds': [TCP]},
                                  {'type': 'selector', 'tag': 'long', 'outbounds': [NETHERLANDS, FRANCE]}])
    source.write_text(json.dumps(document))
    app = sbx.load_axiom_context()
    sbx.write_axiom_profile(app, name='Тест', local=source)
    st = state()
    st['_axiom'] = app
    servers = sbx.all_servers(st)
    assert next(server['outbound'] for server in servers if server['tag'] == NETHERLANDS)['detour'] == 'chain'
    assert list(sbx.profile_group(json.dumps(document))) == [NETHERLANDS, FRANCE]
    assert json.loads(sbx.profile_file(app, app['profiles'][0]['id']).read_text())['outbounds'][1]['detour'] == 'chain'


def test_legacy_dispatch(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sbx, 'CONF_DIR', tmp_path)
    monkeypatch.setattr(sbx, 'STATE_FILE', tmp_path / 'state.json')
    monkeypatch.setattr(sbx, 'SUBS_DIR', tmp_path / 'subs')
    monkeypatch.setattr(sbx.sys, 'argv', ['axiom.exe'])
    monkeypatch.setattr(sbx, 'load_axiom_context', lambda: {'root': None, 'profiles': []})
    monkeypatch.setattr(sbx, 'interactive', lambda: False)
    monkeypatch.setattr(sbx, 'run', lambda cmd, check=True, **kw: subprocess.CompletedProcess(cmd, 0, 'inactive\n', ''))
    calls = []
    monkeypatch.setattr(sbx, 'cmd_sub', lambda st, args: calls.append((args.action, args.name, args.url)))
    monkeypatch.setattr(sbx, 'cmd_use', lambda st, args: calls.append(('use', args.server)))
    monkeypatch.setattr(sbx, 'cmd_up', lambda st, args: calls.append(('up', args.force)))
    monkeypatch.setattr(sbx, 'cmd_down', lambda st, args: calls.append(('down',)))
    monkeypatch.setattr(sbx, 'cmd_self_update', lambda st, args: calls.append(('self-update', args.check)))
    monkeypatch.setattr(sbx, 'cmd_update', lambda st, args: calls.append(('sub update', args.quiet)))
    sbx.main(['import', 'https://example.test/one'])
    sbx.main(['connect', '0'])
    sbx.main(['disconnect'])
    sbx.main(['update', '--check'])
    sbx.main(['sub', 'update', '-q'])
    sbx.main(['version'])
    sbx.main(['guide', 'windows'])
    assert calls == [('add', 'example.test', 'https://example.test/one'), ('use', '0'), ('up', False),
                     ('down',), ('self-update', True), ('sub update', True)]
    assert 'axiom ' + sbx.__version__ in capsys.readouterr().out
    monkeypatch.setattr(sbx.sys, 'argv', ['sbx.py'])
    sbx.main(['update', '-q'])
    assert calls[-1] == ('sub update', True)


def test_local_import_uses_sbx_cache(monkeypatch, tmp_path):
    source = tmp_path / 'config with spaces.json'
    source.write_text(json.dumps(config(FRANCE)))
    monkeypatch.setattr(sbx, 'CONF_DIR', tmp_path)
    monkeypatch.setattr(sbx, 'STATE_FILE', tmp_path / 'state.json')
    monkeypatch.setattr(sbx, 'SUBS_DIR', tmp_path / 'subs')
    monkeypatch.setattr(sbx, 'apply', lambda st: None)
    st = state()
    sbx.cmd_import(st, argparse.Namespace(source=str(source)))
    assert sbx.load_state()['subs'] == [{'name': 'axiom', 'local_path': str(source)}]
    assert [server['tag'] for server in sbx.all_servers(st)] == [FRANCE]


def test_sbx_subscription_still_sends_hwid(monkeypatch):
    monkeypatch.setattr(sbx, 'hwid', lambda: 'fixture-hwid')

    def urlopen(request, **kwargs):
        assert request.get_header('X-hwid') == 'fixture-hwid'
        assert request.get_header('User-agent') == sbx.DEFAULT_STATE['settings']['ua']
        return response(config(FRANCE))

    monkeypatch.setattr(sbx.urllib.request, 'urlopen', urlopen)
    servers, _, _, _ = sbx.fetch_sub(state(), {'url': 'https://example.test/sub'})
    assert servers[0]['name'] == FRANCE
