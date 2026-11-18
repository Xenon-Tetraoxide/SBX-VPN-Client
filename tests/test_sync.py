"""Синхронизация CLI <-> приложение AxiOm через <каталог приложения>/cli-sync (протокол DESIGN-sync)."""
import argparse
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import closing
from pathlib import Path

import pytest

import sbx

FRANCE = 'France (x) [hy2]'
NETHERLANDS = 'Netherlands (Arco) [ws]'
TCP = 'Netherlands (Arco) [tcp]'
SERVERS = [{'tag': tag, 'source': 'fixture',
            'outbound': {'tag': tag, 'type': 'socks', 'server': 'proxy.example', 'server_port': 1080, 'version': '5'}}
           for tag in (FRANCE, TCP, NETHERLANDS)]
FRANCE_KEY = ('France', 'hysteria2', 'hy2')


def now_ms():
    return int(time.time() * 1000)


@pytest.fixture
def app_dir(monkeypatch, tmp_path):
    directory = tmp_path / 'AxiOm data'
    directory.mkdir()
    with closing(sqlite3.connect(directory / 'db.sqlite')) as connection:
        connection.executescript((Path(__file__).parent / 'fixtures/axiom-v5.sql').read_text())
        connection.execute('PRAGMA journal_mode = WAL')
        connection.commit()
    monkeypatch.setenv('SBX_AXIOM_HOME', str(directory))
    monkeypatch.setattr(sbx, 'BASE', 'axiom')
    monkeypatch.setattr(sbx, 'all_servers', lambda st: SERVERS)
    monkeypatch.setattr(sbx, 'SYNC_ACK_TIMEOUT', 1.5)
    monkeypatch.setattr(sbx, 'SYNC_POLL', 0.02)
    (directory / 'cli-sync').mkdir()
    return directory


@pytest.fixture
def sync(app_dir):
    return app_dir / 'cli-sync'


@pytest.fixture
def cli(monkeypatch):
    """CLI-движок: по умолчанию выключен; записывает, что с ним делали."""
    calls = {'active': False, 'api': [], 'service': []}
    monkeypatch.setattr(sbx, 'is_active', lambda st: calls['active'])
    monkeypatch.setattr(sbx, 'api_up', lambda st, port=None: calls['active'])
    monkeypatch.setattr(sbx, 'api', lambda st, method, path, body=None, **kw: calls['api'].append((method, path, body)))
    monkeypatch.setattr(sbx, 'service_action', lambda action: calls['service'].append(action))
    monkeypatch.setattr(sbx, 'prepare_service', lambda st: None)
    monkeypatch.setattr(sbx, 'refuse_other_brand', lambda st, force: None)
    monkeypatch.setattr(sbx, 'require_windows_admin', lambda argv=None: True)
    monkeypatch.setattr(sbx, 'foreign_tun', lambda: [])
    monkeypatch.setattr(sbx, 'apply', lambda st, reload=True, quiet=False: None)
    monkeypatch.setattr(sbx, 'interactive', lambda: False)
    monkeypatch.setattr(sbx, 'current_node', lambda st: None)
    return calls


def axiom_state():
    st = json.loads(json.dumps(sbx.DEFAULT_STATE))
    st['_axiom'] = sbx.load_axiom_context()
    return st


class FakeApp:
    """Приложение по протоколу: сердцебиение app-state.json, опрос control.json, control-ack.json."""

    def __init__(self, sync, *, connected=True, beat=True, ack=True, ok=True, delay=0.0,
                 selection=('__auto__', '', ''), raw_tag='France (x) [hy2]'):
        self.sync, self.connected, self.beat, self.ack_enabled, self.ok = sync, connected, beat, ack, ok
        self.delay, self.selection, self.raw_tag = delay, list(selection), raw_tag
        self.executed = []
        self.seen = set()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def write(self, name, document):
        tmp = self.sync / f'.{name}.tmp'
        tmp.write_text(json.dumps(document))
        os.replace(tmp, self.sync / name)

    def publish(self, heartbeat=None):
        self.write('app-state.json', {
            'v': 1, 'pid': os.getpid(), 'heartbeat': now_ms() if heartbeat is None else heartbeat,
            'connected': self.connected, 'connecting': False,
            'selection': dict(zip('cpt', self.selection)), 'rawTag': self.raw_tag if self.connected else None})

    def loop(self):
        while not self.stop.is_set():
            if self.beat:
                self.publish()
            try:
                command = json.loads((self.sync / 'control.json').read_text())
            except (OSError, ValueError):
                command = None
            if command and command['id'] not in self.seen:
                self.seen.add(command['id'])
                if now_ms() - command['ts'] <= 30_000:
                    self.execute(command)
            self.stop.wait(0.02)

    def execute(self, command):
        time.sleep(self.delay)
        self.executed.append(command)
        if command['cmd'] == 'disconnect':
            self.connected = False
        elif command['cmd'] == 'select':
            self.selection = [command['selection'][key] for key in 'cpt']
        if self.ack_enabled:
            body = {'v': 1, 'id': command['id'], 'ok': self.ok, 'ts': now_ms()}
            if not self.ok:
                body['error'] = 'boom'
            self.write('control-ack.json', body)
        if self.beat:
            self.publish()

    def __enter__(self):
        self.publish()
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join()


# ── обнаружение и состояние ────────────────────────────────────────────────

def test_sync_dir_discovery(monkeypatch, tmp_path, app_dir):
    assert sbx.sync_dir() == app_dir / 'cli-sync'
    monkeypatch.setattr(sbx, 'BASE', 'sbx')
    assert sbx.sync_dir() is None                      # режим sbx — не трогаем
    monkeypatch.setattr(sbx, 'BASE', 'axiom')
    monkeypatch.delenv('SBX_AXIOM_HOME')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'nothing'))
    monkeypatch.setattr(sbx, 'IS_WIN', False)
    assert sbx.sync_dir() is None                      # приложения нет — no-op
    assert sbx.app_state() is None and sbx.app_engine_connected() is None


def test_app_state_staleness_and_garbage(sync):
    path = sync / 'app-state.json'
    state = {'v': 1, 'heartbeat': now_ms(), 'connected': True}
    path.write_text(json.dumps(state))
    assert sbx.app_engine_connected(sync)['connected'] is True
    path.write_text(json.dumps({**state, 'heartbeat': now_ms() - 10_500}))
    assert sbx.app_state(sync) is None                 # сердцебиение старше 10 с
    path.write_text(json.dumps({**state, 'heartbeat': now_ms() - 9_000}))
    assert sbx.app_state(sync) is not None
    path.write_text(json.dumps({**state, 'connected': False}))
    assert sbx.app_state(sync) is not None and sbx.app_engine_connected(sync) is None
    for text in ('{not json', '[]', json.dumps({'connected': True}), json.dumps({'heartbeat': 'x'})):
        path.write_text(text)
        assert sbx.app_state(sync) is None
    path.unlink()
    assert sbx.app_state(sync) is None


# ── запись команды и подтверждение ────────────────────────────────────────

def test_write_control_format_and_atomic(monkeypatch, sync):
    seen = []
    real_replace = os.replace

    def replace(src, dst):
        seen.append((Path(src).exists(), (sync / 'control.json').exists(), Path(src).parent == sync))
        real_replace(src, dst)

    monkeypatch.setattr(sbx.os, 'replace', replace)
    before = now_ms()
    command_id = sbx.write_control(sync, 'select', (FRANCE_KEY[0], 'hysteria2', 'hy2'))
    assert seen == [(True, False, True)]               # tmp рядом, целевого файла ещё нет — переименование атомарно
    data = json.loads((sync / 'control.json').read_text())
    assert data == {'v': 1, 'id': command_id, 'ts': data['ts'], 'cmd': 'select',
                    'selection': {'c': 'France', 'p': 'hysteria2', 't': 'hy2'}}
    assert uuid.UUID(command_id).version == 4 and before <= data['ts'] <= now_ms()
    assert sorted(p.name for p in sync.iterdir()) == ['control.json']   # временных файлов не осталось
    sbx.write_control(sync, 'disconnect')
    data2 = json.loads((sync / 'control.json').read_text())
    assert data2['cmd'] == 'disconnect' and 'selection' not in data2 and data2['id'] != command_id


def test_wait_ack_matches_id_only(sync):
    (sync / 'control-ack.json').write_text(json.dumps({'v': 1, 'id': 'old', 'ok': True, 'ts': 1}))
    assert sbx.wait_ack(sync, 'new') is None           # чужой (старый) ack не годится
    timer = threading.Timer(0.1, lambda: (sync / 'control-ack.json').write_text(
        json.dumps({'v': 1, 'id': 'new', 'ok': True, 'ts': 2})))
    timer.start()
    assert sbx.wait_ack(sync, 'new')['ok'] is True
    timer.join()


def test_ack_timeout_and_error(app_dir, sync, cli, capsys):
    with FakeApp(sync, ack=False):
        with pytest.raises(SystemExit) as exc:
            sbx.cmd_down(axiom_state(), argparse.Namespace())
        assert exc.value.code == 1
    assert 'не подтвердило' in capsys.readouterr().err
    (sync / 'control.json').unlink()
    with FakeApp(sync, ok=False):
        with pytest.raises(SystemExit) as exc:
            sbx.cmd_down(axiom_state(), argparse.Namespace())
        assert exc.value.code == 1
    assert 'boom' in capsys.readouterr().err


# ── down / disconnect ─────────────────────────────────────────────────────

def test_down_disconnects_app(sync, cli, capsys):
    with FakeApp(sync) as app:
        sbx.cmd_down(axiom_state(), argparse.Namespace())
    assert [c['cmd'] for c in app.executed] == ['disconnect']
    assert cli['service'] == []                        # своего движка не было — служба не тронута
    assert 'выключен' in capsys.readouterr().out


def test_down_stops_both_engines(sync, cli):
    cli['active'] = True
    with FakeApp(sync) as app:
        sbx.cmd_down(axiom_state(), argparse.Namespace())
    assert cli['service'] == ['stop'] and [c['cmd'] for c in app.executed] == ['disconnect']


def test_down_without_app_or_with_stale_heartbeat(sync, cli):
    sbx.cmd_down(axiom_state(), argparse.Namespace())
    assert cli['service'] == ['stop']                  # как раньше
    cli['service'].clear()
    with FakeApp(sync, beat=False) as app:
        app.publish(heartbeat=now_ms() - 60_000)
        sbx.cmd_down(axiom_state(), argparse.Namespace())
    assert cli['service'] == ['stop'] and app.executed == []   # приложение «не запущено» — команд нет


def test_down_app_not_connected(sync, cli):
    with FakeApp(sync, connected=False) as app:
        sbx.cmd_down(axiom_state(), argparse.Namespace())
    assert app.executed == [] and cli['service'] == ['stop']


# ── up / connect ──────────────────────────────────────────────────────────

def test_up_noop_when_app_connected(sync, cli, capsys):
    with FakeApp(sync) as app:
        sbx.cmd_up(axiom_state(), argparse.Namespace(force=False))
    assert 'VPN уже включён в приложении AxiOm' in capsys.readouterr().out
    assert cli['service'] == [] and app.executed == []


def test_up_starts_own_engine_when_app_off(monkeypatch, sync, cli):
    monkeypatch.setattr(sbx, 'show_status', lambda st: None)
    flags = iter([False, True])
    monkeypatch.setattr(sbx, 'is_active', lambda st: next(flags, True))
    monkeypatch.setattr(sbx.time, 'sleep', lambda s: None)
    with FakeApp(sync, connected=False) as app:
        sbx.cmd_up(axiom_state(), argparse.Namespace(force=False))
    assert cli['service'] == ['start'] and app.executed == []


def test_connect_select_with_app_engine(sync, cli, capsys):
    st = axiom_state()
    with FakeApp(sync) as app:
        sbx.cmd_connect(st, argparse.Namespace(number=None, select='France|hysteria2|hy2', force=False))
    assert [(c['cmd'], c['selection']) for c in app.executed] == [
        ('select', {'c': 'France', 'p': 'hysteria2', 't': 'hy2'})]
    out = capsys.readouterr().out
    assert 'VPN уже включён в приложении AxiOm' in out and cli['service'] == []
    prefs = json.loads((app_dir_prefs(st)).read_text())
    assert prefs['flutter.server_selector_country'] == 'France'     # выбор сохранён и в настройках


def app_dir_prefs(st):
    return st['_axiom']['prefs_path']


def test_connect_number_with_app_engine(sync, cli):
    st = axiom_state()
    with FakeApp(sync) as app:
        sbx.cmd_connect(st, argparse.Namespace(number=1, select=None, force=False))
    assert app.executed[0]['selection'] == {'c': 'France', 'p': 'hysteria2', 't': 'hy2'}
    assert len(app.executed) == 1                      # select не дублируется в up


def test_connect_without_app_unchanged(monkeypatch, sync, cli):
    monkeypatch.setattr(sbx, 'show_status', lambda st: None)
    flags = iter([False, False, True])
    monkeypatch.setattr(sbx, 'is_active', lambda st: next(flags, True))
    monkeypatch.setattr(sbx.time, 'sleep', lambda s: None)
    sbx.cmd_connect(axiom_state(), argparse.Namespace(number=None, select='__auto__', force=False))
    assert cli['service'] == ['start'] and not (sync / 'control.json').exists()


# ── use ───────────────────────────────────────────────────────────────────

def test_use_prefers_cli_engine(sync, cli):
    cli['active'] = True
    with FakeApp(sync) as app:
        sbx.cmd_use(axiom_state(), argparse.Namespace(server='1'))
    assert cli['api'] == [('PUT', '/proxies/proxy', {'name': FRANCE})] and app.executed == []


def test_use_sends_select_to_app(sync, cli):
    with FakeApp(sync) as app:
        sbx.cmd_use(axiom_state(), argparse.Namespace(server='2'))      # 2 = Netherlands / vless / tcp
    assert app.executed[0]['selection'] == {'c': 'Netherlands', 'p': 'vless', 't': 'tcp'}
    assert app.selection == ['Netherlands', 'vless', 'tcp'] and cli['api'] == []


def test_use_auto_sends_auto(sync, cli):
    with FakeApp(sync, selection=('France', 'hysteria2', 'hy2')) as app:
        sbx.cmd_use(axiom_state(), argparse.Namespace(server='auto'))
    assert app.executed[0]['selection'] == {'c': '__auto__', 'p': '', 't': ''}


def test_use_select_ack_error(sync, cli):
    with FakeApp(sync, ack=False):
        with pytest.raises(SystemExit):
            sbx.cmd_use(axiom_state(), argparse.Namespace(server=None, select='France|hysteria2|hy2'))


def test_use_no_app_no_command(sync, cli, capsys):
    sbx.cmd_use(axiom_state(), argparse.Namespace(server='1'))
    assert not (sync / 'control.json').exists() and 'выбран' in capsys.readouterr().out


def test_use_own_server_not_sent_to_app(sync, cli, capsys, monkeypatch):
    own = {'tag': 'mine', 'source': 'manual', 'outbound': SERVERS[0]['outbound']}
    monkeypatch.setattr(sbx, 'all_servers', lambda st: SERVERS + [own])
    with FakeApp(sync) as app:
        sbx.cmd_use(axiom_state(), argparse.Namespace(server='mine'))
    assert app.executed == [] and 'свой сервер' in capsys.readouterr().err


# ── --select ──────────────────────────────────────────────────────────────

def test_select_validation(sync, cli, capsys):
    st = axiom_state()
    assert sbx.resolve_select(st, '__auto__||') == (('__auto__', '', ''), 'auto')
    assert sbx.resolve_select(st, '__auto__') == (('__auto__', '', ''), 'auto')
    assert sbx.resolve_select(st, 'France|hysteria2|hy2') == (FRANCE_KEY, FRANCE)
    assert sbx.resolve_select(st, 'France||') == (FRANCE_KEY, FRANCE)       # пустые p/t — первые по меню
    assert sbx.resolve_select(st, 'Netherlands|vless|ws') == (('Netherlands', 'vless', 'ws'), NETHERLANDS)
    for bad in ('Mars|vless|ws', 'France|vless|ws', 'France|hysteria2|tcp', '|a|b', 'a|b|c|d', '__auto__|x|'):
        with pytest.raises(SystemExit) as exc:
            sbx.resolve_select(st, bad)
        assert exc.value.code == 1
    assert 'доступны' in capsys.readouterr().err
    sbx_st = json.loads(json.dumps(sbx.DEFAULT_STATE))
    with pytest.raises(SystemExit):
        sbx.resolve_select(sbx_st, 'France|hysteria2|hy2')


def test_use_select_both_args_rejected(cli):
    with pytest.raises(SystemExit):
        sbx.cmd_use_or_pick(axiom_state(), argparse.Namespace(server='1', select='France||'))


def test_main_wiring(monkeypatch, sync, cli, capsys, tmp_path):
    monkeypatch.setattr(sbx, 'CONF_DIR', tmp_path / 'c')
    monkeypatch.setattr(sbx, 'STATE_FILE', tmp_path / 'c/state.json')
    monkeypatch.setattr(sbx, 'SUBS_DIR', tmp_path / 'c/subs')
    monkeypatch.setattr(sbx.sys, 'argv', ['axiom'])
    with FakeApp(sync) as app:
        sbx.main(['use', '--select', 'Netherlands|vless|tcp'])
        sbx.main(['status', '--json'])
        sbx.main(['disconnect'])
    assert [c['cmd'] for c in app.executed] == ['select', 'disconnect']
    out = capsys.readouterr().out
    report = json.loads(out[out.index('{'):out.rindex('}') + 1])
    assert report['engine'] == 'app' and report['selection'] == {'c': 'Netherlands', 'p': 'vless', 't': 'tcp'}


# ── status ────────────────────────────────────────────────────────────────

def test_status_json_app(sync, cli, capsys):
    with FakeApp(sync, selection=('France', 'hysteria2', 'hy2')):
        sbx.cmd_status(axiom_state(), argparse.Namespace(json=True))
    report = json.loads(capsys.readouterr().out)
    assert report == {'vpn': 'on', 'engine': 'app', 'selection': {'c': 'France', 'p': 'hysteria2', 't': 'hy2'},
                      'server': 'France (x) [hy2]', 'version': sbx.__version__}


def test_status_json_cli_off_and_stale(monkeypatch, sync, cli, capsys):
    st = axiom_state()
    sbx.cmd_status(st, argparse.Namespace(json=True))
    off = json.loads(capsys.readouterr().out)
    assert off['vpn'] == 'off' and off['engine'] is None and off['server'] is None
    assert off['selection'] == {'c': '__auto__', 'p': '', 't': ''}     # из настроек приложения
    with FakeApp(sync, beat=False) as app:
        app.publish(heartbeat=now_ms() - 60_000)
        sbx.cmd_status(st, argparse.Namespace(json=True))
    assert json.loads(capsys.readouterr().out)['vpn'] == 'off'          # устаревшее сердцебиение игнорируется
    cli['active'] = True
    monkeypatch.setattr(sbx, 'current_node', lambda st: 'auto → ' + FRANCE)
    with FakeApp(sync):
        sbx.cmd_status(st, argparse.Namespace(json=True))
    both = json.loads(capsys.readouterr().out)
    assert both['engine'] == 'cli' and both['server'] == FRANCE


def test_status_json_sbx_mode(monkeypatch, cli, capsys):
    monkeypatch.setattr(sbx, 'BASE', 'sbx')
    st = json.loads(json.dumps(sbx.DEFAULT_STATE))
    sbx.cmd_status(st, argparse.Namespace(json=True))
    assert json.loads(capsys.readouterr().out) == {'vpn': 'off', 'engine': None, 'selection': None,
                                                   'server': None, 'version': sbx.__version__}


def test_status_human_mentions_app(monkeypatch, sync, cli, capsys):
    monkeypatch.setattr(sbx, 'task_enabled', lambda name: 'disabled')
    monkeypatch.setattr(sbx, 'unit_prop', lambda prop: 'disabled')
    monkeypatch.setattr(sbx, 'unit_prop_of', lambda unit, prop: 'disabled')
    with FakeApp(sync):
        sbx.cmd_status(axiom_state(), argparse.Namespace(json=False))
    assert 'подключено через приложение AxiOm' in capsys.readouterr().out


# ── перенос состояния старого Go-CLI ──────────────────────────────────────

OLD_CLI_STATE = {"subscription_url": "https://panel.example/sub/abc", "profile_path": "/x/profiles/subscription.json",
                 "connected": False, "connected_at": "2026-01-02T03:04:05Z", "bypass_lan": False}


@pytest.fixture
def old_cli_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(sbx, 'BASE', 'axiom')
    monkeypatch.setattr(sbx, 'CONF_DIR', tmp_path)
    monkeypatch.setattr(sbx, 'STATE_FILE', tmp_path / 'state.json')
    monkeypatch.setattr(sbx, 'SUBS_DIR', tmp_path / 'subs')
    (tmp_path / 'profiles').mkdir()
    (tmp_path / 'profiles/subscription.json').write_text(json.dumps(
        {'outbounds': [{'tag': 'Netherlands (Test) [ws] § 0', 'type': 'direct'}]}))
    (tmp_path / 'workdir').mkdir()
    (tmp_path / 'workdir/000001.log').write_bytes(b'leveldb')
    return tmp_path


def test_old_cli_state_migrated_once(old_cli_dir, capsys):
    original = json.dumps(OLD_CLI_STATE)
    (old_cli_dir / 'state.json').write_text(original)
    st = sbx.load_state()
    assert (old_cli_dir / 'state.old-cli.json').read_text() == original
    assert st['subs'] == [{'name': 'axiom', 'url': OLD_CLI_STATE['subscription_url'], 'hwid': True}]
    assert st['settings']['api_port'] == sbx.AXIOM_API_PORT and st['settings']['api_secret']
    assert 'Перенесена подписка старого AxiOm CLI' in capsys.readouterr().err
    saved = json.loads((old_cli_dir / 'state.json').read_text())
    assert saved['subs'] == st['subs'] and 'subscription_url' not in saved and '_old_cli_migrated' not in saved
    assert (old_cli_dir / 'profiles/subscription.json').exists() and (old_cli_dir / 'workdir/000001.log').exists()
    again = sbx.load_state()                       # второй запуск — обычное состояние, без переноса
    assert again['subs'] == st['subs'] and capsys.readouterr().err == ''
    assert (old_cli_dir / 'state.old-cli.json').read_text() == original


def test_old_cli_state_without_url(old_cli_dir, capsys):
    (old_cli_dir / 'state.json').write_text(json.dumps({**OLD_CLI_STATE, 'subscription_url': ''}))
    st = sbx.load_state()
    assert st['subs'] == [] and (old_cli_dir / 'state.old-cli.json').exists()
    assert 'state.old-cli.json' in capsys.readouterr().err


def test_old_cli_format_ignored_in_sbx_mode_and_new_format(monkeypatch, old_cli_dir):
    monkeypatch.setattr(sbx, 'BASE', 'sbx')
    (old_cli_dir / 'state.json').write_text(json.dumps(OLD_CLI_STATE))
    sbx.load_state()
    assert not (old_cli_dir / 'state.old-cli.json').exists()
    monkeypatch.setattr(sbx, 'BASE', 'axiom')
    (old_cli_dir / 'state.json').write_text(json.dumps({'subs': [], 'settings': {}, 'subscription_url': 'x'}))
    sbx.load_state()
    assert not (old_cli_dir / 'state.old-cli.json').exists()


def test_old_cli_dispatch_fetches_subscription(monkeypatch, old_cli_dir, capsys):
    (old_cli_dir / 'state.json').write_text(json.dumps(OLD_CLI_STATE))
    monkeypatch.setattr(sbx, 'load_axiom_context', lambda: {'root': None, 'profiles': [], 'prefs': {}})
    monkeypatch.setattr(sbx.sys, 'argv', ['axiom'])
    fetched = []
    monkeypatch.setattr(sbx, 'update_subs', lambda st, names=None, quiet=False: fetched.append(names))
    monkeypatch.setattr(sbx, 'cmd_ls', lambda st, a: fetched.append('ls'))
    sbx.main(['ls'])
    assert fetched == [['axiom'], 'ls']
