"""Синхронизация CLI <-> приложение AxiOm через <каталог приложения>/cli-sync (протокол DESIGN-sync)."""
import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
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
    def service_action(action):
        calls['service'].append(action)
        calls['active'] = action != 'stop'
        calls['lock_during'] = (sbx.sync_dir() / 'start.lock').exists() if sbx.sync_dir() else None

    monkeypatch.setattr(sbx, 'service_action', service_action)
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
    """Приложение по протоколу v2: сердцебиение app-state.json (connecting), start.lock, control.json/ack, долговечная дедупликация."""

    def __init__(self, sync, *, connected=True, connecting=False, beat=True, ack=True, ok=True, delay=0.0,
                 selection=('__auto__', '', ''), raw_tag='France (x) [hy2]'):
        self.sync, self.connected, self.connecting, self.beat = sync, connected, connecting, beat
        self.ack_enabled, self.ok, self.delay = ack, ok, delay
        self.selection, self.raw_tag = list(selection), raw_tag
        self.executed = []
        # долговечная дедупликация: команда, на которую уже есть ack с тем же id, не исполняется после перезапуска
        self.seen = {a['id'] for a in [self.read('control-ack.json')] if a}
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def read(self, name):
        try:
            return json.loads((self.sync / name).read_text())
        except (OSError, ValueError):
            return None

    def write(self, name, document):
        tmp = self.sync / f'.{name}.tmp'
        tmp.write_text(json.dumps(document))
        os.replace(tmp, self.sync / name)

    def publish(self, heartbeat=None):
        self.write('app-state.json', {
            'v': 1, 'pid': os.getpid(), 'heartbeat': now_ms() if heartbeat is None else heartbeat,
            'connected': self.connected, 'connecting': self.connecting,
            'selection': dict(zip('cpt', self.selection)), 'rawTag': self.raw_tag if self.connected else None})

    def hold_start_lock(self):
        self.start_handle = sbx.try_lock(self.sync / 'start.lock')
        assert self.start_handle

    def release_start_lock(self):
        sbx.unlock(self.start_handle)

    def loop(self):
        while not self.stop.is_set():
            if self.beat:
                self.publish()
            command = self.read('control.json')
            if command and command['id'] not in self.seen:
                self.seen.add(command['id'])
                if now_ms() - command['ts'] <= 30_000:
                    self.execute(command)
            self.stop.wait(0.02)

    def execute(self, command):
        time.sleep(self.delay)
        self.executed.append(command)
        if command['cmd'] == 'disconnect':
            self.connected = self.connecting = False
        elif command['cmd'] == 'select':
            self.selection = [command['selection'][key] for key in 'cpt']
            if self.selection[0] == '__auto__':
                self.selection = ['__auto__', '', '']
            prefs = self.sync.parent / 'shared_preferences.json'
            prefs.write_text(json.dumps({'flutter.server_selector_country': self.selection[0]}))
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
        if getattr(self, 'start_handle', None):
            sbx.unlock(self.start_handle)
            self.start_handle = None


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
    state = {'v': 1, 'pid': 1, 'heartbeat': now_ms(), 'connected': True, 'connecting': False,
             'selection': {'c': '__auto__', 'p': '', 't': ''}}
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
    old, new = str(uuid.uuid4()), str(uuid.uuid4())
    (sync / 'control-ack.json').write_text(json.dumps({'v': 1, 'id': old, 'ok': True, 'ts': 1}))
    assert sbx.wait_ack(sync, new) is None             # чужой (старый) ack не годится
    timer = threading.Timer(0.1, lambda: (sync / 'control-ack.json').write_text(
        json.dumps({'v': 1, 'id': new, 'ok': True, 'ts': 2})))
    timer.start()
    assert sbx.wait_ack(sync, new)['ok'] is True
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
    monkeypatch.setattr(sbx.time, 'sleep', lambda s: None)
    sbx.cmd_connect(axiom_state(), argparse.Namespace(number=None, select='__auto__', force=False))
    assert cli['service'] == ['start'] and not (sync / 'control.json').exists()


# ── use ───────────────────────────────────────────────────────────────────

def test_use_prefers_cli_engine(sync, cli):
    cli['active'] = True
    with FakeApp(sync) as app:
        sbx.cmd_use(axiom_state(), argparse.Namespace(server='1'))
    assert cli['api'] == [('PUT', '/proxies/proxy', {'name': FRANCE})]
    assert [c['cmd'] for c in app.executed] == ['select']       # приложение тоже получает выбор (оно его сохраняет)


def test_use_sends_select_to_app(sync, cli):
    with FakeApp(sync) as app:
        sbx.cmd_use(axiom_state(), argparse.Namespace(server='2'))      # 2 = Netherlands / vless / tcp
    assert app.executed[0]['selection'] == {'c': 'Netherlands', 'p': 'vless', 't': 'tcp'}
    assert app.selection == ['Netherlands', 'vless', 'tcp'] and cli['api'] == []
    assert not (sync.parent / 'shared_preferences.json').read_text().count('vless')   # файл писало только приложение


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
    assert sbx.resolve_select(st, '__auto__|x|y') == (('__auto__', '', ''), 'auto')   # p/t при auto игнорируются
    assert sbx.resolve_select(st, 'France|hysteria2|hy2') == (FRANCE_KEY, FRANCE)
    assert sbx.resolve_select(st, 'France||') == (FRANCE_KEY, FRANCE)       # пустые p/t — первые по меню
    assert sbx.resolve_select(st, 'Netherlands|vless|ws') == (('Netherlands', 'vless', 'ws'), NETHERLANDS)
    for bad in ('Mars|vless|ws', 'France|vless|ws', 'France|hysteria2|tcp', '|a|b', 'a|b|c|d'):
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


# ══ v2 ═══════════════════════════════════════════════════════════════════════

def test_version_gate():
    assert tuple(int(x) for x in sbx.__version__.split('.')) >= (1, 4, 0)


# ── 1: app-location.json ────────────────────────────────────────────────────

def make_location(tmp_path, **override):
    support = tmp_path / 'portable-support'
    support.mkdir(exist_ok=True)
    (support / 'db.sqlite').write_bytes(b'')
    doc = {'v': 1, 'support_dir': str(support), 'sync_dir': str(tmp_path / 'elsewhere-sync'),
           'prefs_file': str(tmp_path / 'prefs.json'), 'prefs_prefix': 'portable.', 'exe': '/x/axiom-app',
           'pid': os.getpid(), 'ts': now_ms()}
    doc.update(override)
    (sbx.CONF_DIR).mkdir(parents=True, exist_ok=True)
    (sbx.CONF_DIR / 'app-location.json').write_text(json.dumps(doc))
    return support, doc


def test_app_location_used_first(monkeypatch, tmp_path):
    monkeypatch.delenv('SBX_AXIOM_HOME', raising=False)
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'nothing'))
    monkeypatch.setattr(sbx, 'IS_WIN', False)
    monkeypatch.setattr(sbx, 'BASE', 'axiom')
    support, doc = make_location(tmp_path)
    app = sbx.axiom_locations()
    assert app['root'] == support and app['prefix'] == 'portable.'
    assert app['prefs_path'] == Path(doc['prefs_file']) and app['sync_dir'] == Path(doc['sync_dir'])
    assert sbx.sync_dir() == Path(doc['sync_dir'])


def test_app_location_stale_or_invalid_ignored(monkeypatch, tmp_path):
    monkeypatch.delenv('SBX_AXIOM_HOME', raising=False)
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'nothing'))
    monkeypatch.setattr(sbx, 'IS_WIN', False)
    old = now_ms() - 25 * 3600 * 1000
    make_location(tmp_path, ts=old, pid=2 ** 22 + 12345)          # мёртвый pid и старше суток
    assert sbx.axiom_locations() is None
    make_location(tmp_path, ts=old, pid=os.getpid())               # живой pid — годится при любом ts
    assert sbx.axiom_locations() is not None
    make_location(tmp_path, ts=now_ms(), pid=2 ** 22 + 12345)      # свежий ts — годится
    assert sbx.axiom_locations() is not None
    for bad in ({'v': 2}, {'prefs_prefix': 'x.'}, {'sync_dir': 'relative'}, {'ts': 'now'}):
        make_location(tmp_path, **bad)
        assert sbx.axiom_locations() is None
    (sbx.CONF_DIR / 'app-location.json').write_text('{bad')
    assert sbx.axiom_locations() is None


def test_app_location_ignored_with_explicit_home(monkeypatch, tmp_path, app_dir):
    make_location(tmp_path)
    assert sbx.axiom_locations()['root'] == app_dir               # SBX_AXIOM_HOME главнее


# ── 2: единственный писатель настроек ─────────────────────────────────────

def prefs_file(app_dir):
    return app_dir / 'shared_preferences.json'


def test_no_prefs_write_while_app_running(app_dir, sync, cli):
    with FakeApp(sync) as app:
        sbx.cmd_use(axiom_state(), argparse.Namespace(server='1'))
    assert [c['cmd'] for c in app.executed] == ['select']
    assert json.loads(prefs_file(app_dir).read_text()) == {'flutter.server_selector_country': 'France'}  # писало приложение


def test_cli_writes_prefs_when_app_not_running(app_dir, sync, cli):
    assert not prefs_file(app_dir).exists()
    sbx.cmd_use(axiom_state(), argparse.Namespace(server='1'))
    assert json.loads(prefs_file(app_dir).read_text())['flutter.server_selector_country'] == 'France'
    assert not (sync / 'control.json').exists()
    with FakeApp(sync, beat=False) as app:
        app.publish(heartbeat=now_ms() - 60_000)                  # устаревшее сердцебиение = не запущено
        sbx.cmd_use(axiom_state(), argparse.Namespace(server='2'))
    assert app.executed == []
    assert json.loads(prefs_file(app_dir).read_text())['flutter.server_selector_country'] == 'Netherlands'


def test_select_sent_with_app_idle(sync, cli):
    with FakeApp(sync, connected=False) as app:                    # приложение запущено, VPN выключен
        sbx.cmd_use(axiom_state(), argparse.Namespace(server=None, select='France||'))
    assert app.executed[0]['selection'] == {'c': 'France', 'p': '', 't': ''}    # приложение разбирает само
    assert cli['service'] == [] and cli['api'] == []


def test_selection_in_memory_for_cli_start(sync, cli, monkeypatch):
    """После ack выбор виден этому процессу (конфиг CLI строится по нему), хотя файл писало приложение."""
    st = axiom_state()
    with FakeApp(sync, connected=False):
        sbx.cmd_use(st, argparse.Namespace(server='2'))
    assert sbx.axiom_prefs_now(st['_axiom'])[:1] == ['Netherlands']


# ── 5: приложение получает select раньше конфига CLI ──────────────────────

def test_select_sent_before_cli_apply(sync, cli, monkeypatch):
    def broken(st, reload=True, quiet=False):
        raise RuntimeError('нет sing-box')

    monkeypatch.setattr(sbx, 'apply', broken)
    with FakeApp(sync) as app:
        sbx.cmd_use(axiom_state(), argparse.Namespace(server='1'))    # выбор принят приложением — код 0
    assert [c['cmd'] for c in app.executed] == ['select']


def test_select_ok_with_no_own_servers(monkeypatch, sync, cli, capsys):
    """Серверов у CLI нет (apply умирает) — выбор всё равно принят приложением, выход 0."""
    def no_servers(st, reload=True, quiet=False):
        sbx.die('серверов нет')

    monkeypatch.setattr(sbx, 'apply', no_servers)
    with FakeApp(sync) as app:
        sbx.cmd_use(axiom_state(), argparse.Namespace(server=None, select='France||'))
        sbx.cmd_connect(axiom_state(), argparse.Namespace(number=None, select='France||', force=False))
    assert [c['cmd'] for c in app.executed] == ['select', 'select']
    assert 'принят приложением' in capsys.readouterr().out
    monkeypatch.setattr(sbx, 'sync_dir', lambda: None)               # без приложения ошибка apply остаётся ошибкой
    with pytest.raises(SystemExit):
        sbx.cmd_use(axiom_state(), argparse.Namespace(server='1'))


def test_start_lock_is_os_lock_not_file_content(sync):
    lock = sync / 'start.lock'
    lock.write_text('{half')                            # содержимое ничего не значит — только замок ядра
    assert sbx.app_vpn_on(sync) is None
    with sbx.start_reservation(sync) as mine:
        assert mine is True
    assert lock.exists()                                # файлы замков не удаляются

def test_select_resolved_against_app_menu_without_cli_servers(sync, cli):
    with FakeApp(sync) as app:
        sbx.cmd_use(axiom_state(), argparse.Namespace(server=None, select='Netherlands|vless|ws'))
    assert app.executed[0]['selection'] == {'c': 'Netherlands', 'p': 'vless', 't': 'ws'}


# ── 3: start.lock ────────────────────────────────────────────────────────

def test_cli_start_holds_and_releases_lock(monkeypatch, sync, cli):
    monkeypatch.setattr(sbx, 'show_status', lambda st: None)
    monkeypatch.setattr(sbx.time, 'sleep', lambda s: None)
    sbx.cmd_up(axiom_state(), argparse.Namespace(force=False))
    assert cli['service'] == ['start'] and cli['lock_during'] is True      # замок был во время запуска
    assert not sbx.lock_held_by_other(sync / 'start.lock')                  # и отпущен после
    assert (sync / 'start.lock').exists() and json.loads((sync / 'start.owner.json').read_text())['owner'] == 'cli'

def test_lock_released_when_start_fails(monkeypatch, sync, cli):
    monkeypatch.setattr(sbx, 'cmd_log', lambda *a: None)
    monkeypatch.setattr(sbx.time, 'sleep', lambda s: None)
    monkeypatch.setattr(sbx, 'service_action', lambda action: None)        # движок не поднялся
    with pytest.raises(SystemExit):
        sbx.cmd_up(axiom_state(), argparse.Namespace(force=False))
    assert not sbx.lock_held_by_other(sync / 'start.lock')

def test_start_reservation_exclusive_in_process(sync):
    with sbx.start_reservation(sync) as mine:
        assert mine is True
        with sbx.start_reservation(sync) as second:
            assert second is False                                          # второй стартер не получает резерв
        assert sbx.lock_held_by_other(sync / 'start.lock')
    assert not sbx.lock_held_by_other(sync / 'start.lock')

def is_uuid(value):
    return sbx.is_uuid4(value)


def test_app_lock_means_on(sync, cli, capsys):
    with FakeApp(sync, connected=False) as app:
        app.hold_start_lock()
        sbx.cmd_up(axiom_state(), argparse.Namespace(force=False))
    assert 'VPN уже включён в приложении AxiOm' in capsys.readouterr().out and cli['service'] == []


def test_app_connecting_means_on(sync, cli, capsys):
    with FakeApp(sync, connected=False, connecting=True):
        sbx.cmd_up(axiom_state(), argparse.Namespace(force=False))
        sbx.cmd_status(axiom_state(), argparse.Namespace(json=True))
    out = capsys.readouterr().out
    assert 'уже включён' in out and '"vpn": "on"' in out and cli['service'] == []


def test_released_app_lock_allows_start(monkeypatch, sync, cli):
    monkeypatch.setattr(sbx, 'show_status', lambda st: None)
    monkeypatch.setattr(sbx.time, 'sleep', lambda s: None)
    with FakeApp(sync, connected=False) as app:
        app.hold_start_lock()
        app.release_start_lock()
        sbx.cmd_up(axiom_state(), argparse.Namespace(force=False))
    assert cli['service'] == ['start']

def test_recheck_after_acquire_aborts_start(monkeypatch, sync, cli, capsys):
    """Приложение включилось, пока CLI готовился: после взятия замка повторная проверка отменяет запуск (B)."""
    calls = []

    def app_vpn_on(sync=None, ignore_lock=False):
        calls.append(ignore_lock)
        return {'connected': True, 'connecting': False} if ignore_lock else None

    monkeypatch.setattr(sbx, 'app_vpn_on', app_vpn_on)
    sbx.cmd_up(axiom_state(), argparse.Namespace(force=False))
    assert calls == [False, True]
    assert cli['service'] == [] and 'VPN уже включён в приложении AxiOm' in capsys.readouterr().out
    assert not sbx.lock_held_by_other(sync / 'start.lock')              # замок отпущен


def test_network_work_outside_start_lock(monkeypatch, sync, cli):
    """Подготовка (наборы правил, подписки, конфиг) — до замка; под замком только запуск и проверка готовности (C)."""
    seen = {}
    monkeypatch.setattr(sbx, 'show_status', lambda st: None)
    monkeypatch.setattr(sbx.time, 'sleep', lambda s: None)
    monkeypatch.setattr(sbx, 'prepare_service',
                        lambda st: seen.setdefault('prepare_locked', sbx.lock_held_by_other(sync / 'start.lock')))
    sbx.cmd_up(axiom_state(), argparse.Namespace(force=False))
    assert seen['prepare_locked'] is False and cli['lock_during'] is True

def test_down_waits_for_app_start(sync, cli):
    with FakeApp(sync, connected=False, connecting=True) as app:
        app.hold_start_lock()

        def finish():
            time.sleep(0.3)
            app.connected, app.connecting = True, False
            app.release_start_lock()

        thread = threading.Thread(target=finish)
        thread.start()
        started = time.monotonic()
        sbx.cmd_down(axiom_state(), argparse.Namespace())
        thread.join()
    assert time.monotonic() - started >= 0.25
    assert [c['cmd'] for c in app.executed] == ['disconnect']             # выключен уже запущенный движок


# ── 4: control.lock ──────────────────────────────────────────────────────

def test_control_lock_held_until_ack(sync):
    seen = []

    def slow_ack():
        time.sleep(0.2)
        seen.append(sbx.lock_held_by_other(sync / 'control.lock'))
        command = json.loads((sync / 'control.json').read_text())
        (sync / 'control-ack.json').write_text(json.dumps({'v': 1, 'id': command['id'], 'ok': True, 'ts': now_ms()}))

    thread = threading.Thread(target=slow_ack)
    thread.start()
    sbx.send_app_command(sync, 'disconnect')
    thread.join()
    assert seen == [True] and not sbx.lock_held_by_other(sync / 'control.lock')

def test_control_lock_released_on_timeout(sync, monkeypatch):
    monkeypatch.setattr(sbx, 'SYNC_ACK_TIMEOUT', 0.2)
    with pytest.raises(SystemExit):
        sbx.send_app_command(sync, 'disconnect')
    assert not sbx.lock_held_by_other(sync / 'control.lock')

def test_control_lock_serializes_threads(sync):
    order = []
    with FakeApp(sync, delay=0.15) as app:
        def sender(tag):
            sbx.send_app_command(sync, 'select', ('France', 'hysteria2', 'hy2'))
            order.append(tag)

        threads = [threading.Thread(target=sender, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert len(app.executed) == 2 and len(order) == 2                    # обе команды дошли, ни одна не затёрта
    assert (sync / 'control.lock').exists()                              # файл замка не удаляется


# ── настоящие процессы: замки ядра, гибель держателя ────────────────────────

HOLDER = """
import sys, time
sys.path.insert(0, sys.argv[1])
import sbx
handle = sbx.try_lock(sys.argv[2])
print('locked' if handle else 'busy', flush=True)
if handle:
    time.sleep(60)
"""


def spawn_holder(path):
    proc = subprocess.Popen([sys.executable, '-c', HOLDER, str(Path(sbx.__file__).parent), str(path)],
                            stdout=subprocess.PIPE, text=True)
    return proc, proc.stdout.readline().strip()


@pytest.mark.parametrize('name', ['start.lock', 'control.lock'])
def test_two_processes_contend_for_lock(sync, name):
    path = sync / name
    first, status = spawn_holder(path)
    try:
        assert status == 'locked'
        assert sbx.lock_held_by_other(path)                                # другой процесс держит
        assert sbx.try_lock(path) is None
        second, status2 = spawn_holder(path)                               # и второй процесс не получает
        assert status2 == 'busy'
        second.wait(timeout=10)
    finally:
        first.kill()
        first.wait()
    deadline = time.time() + 5
    while sbx.lock_held_by_other(path) and time.time() < deadline:
        time.sleep(0.05)
    handle = sbx.try_lock(path)                                            # убитый (kill -9) держатель отпустил замок
    assert handle is not None
    sbx.unlock(handle)
    assert path.exists()


def test_cli_start_refused_while_other_process_starts(sync, cli, capsys):
    first, status = spawn_holder(sync / 'start.lock')
    try:
        assert status == 'locked'
        sbx.cmd_up(axiom_state(), argparse.Namespace(force=False))
        assert 'VPN уже включён в приложении AxiOm' in capsys.readouterr().out and cli['service'] == []
    finally:
        first.kill()
        first.wait()


def test_control_lock_waits_for_other_process(sync, monkeypatch):
    monkeypatch.setattr(sbx, 'CONTROL_LOCK_WAIT', 0.3)
    first, status = spawn_holder(sync / 'control.lock')
    try:
        assert status == 'locked'
        with pytest.raises(SystemExit):
            with sbx.control_lock(sync):
                pass
    finally:
        first.kill()
        first.wait()
    with sbx.control_lock(sync):                                           # после гибели держателя — свободно
        pass

def test_fake_app_durable_dedup(sync):
    command_id = sbx.write_control(sync, 'disconnect')
    (sync / 'control-ack.json').write_text(json.dumps({'v': 1, 'id': command_id, 'ok': True, 'ts': now_ms()}))
    with FakeApp(sync) as app:
        time.sleep(0.2)
    assert app.executed == []        # уже подтверждённая команда после перезапуска приложения не исполняется


# ── 6: валидация на чтении ───────────────────────────────────────────────

@pytest.mark.parametrize('patch', [{'v': 2}, {'v': True}, {'heartbeat': True}, {'heartbeat': '1'},
                                   {'connected': 'true'}, {'connected': 1}, {'connecting': 'no'},
                                   {'selection': {'c': 1, 'p': '', 't': ''}}, {'selection': 'x'}, {'pid': '1'}, {'pid': True}])
def test_invalid_app_state_rejected(sync, patch):
    doc = {'v': 1, 'pid': 1, 'heartbeat': now_ms(), 'connected': True, 'connecting': False,
           'selection': {'c': '__auto__', 'p': '', 't': ''}}
    (sync / 'app-state.json').write_text(json.dumps(doc))
    assert sbx.app_state(sync) is not None
    (sync / 'app-state.json').write_text(json.dumps({**doc, **patch}))
    assert sbx.app_state(sync) is None


@pytest.mark.parametrize('patch', [{'ok': 'false'}, {'ok': 1}, {'v': 2}, {'ts': 'x'}, {'ts': True}])
def test_invalid_ack_rejected(sync, monkeypatch, patch):
    monkeypatch.setattr(sbx, 'SYNC_ACK_TIMEOUT', 0.1)
    command_id = str(uuid.uuid4())
    (sync / 'control-ack.json').write_text(json.dumps({'v': 1, 'id': command_id, 'ok': True, 'ts': 1, **patch}))
    assert sbx.wait_ack(sync, command_id) is None
    (sync / 'control-ack.json').write_text(json.dumps({'v': 1, 'id': command_id, 'ok': True, 'ts': 1}))
    assert sbx.wait_ack(sync, command_id)['ok'] is True
    (sync / 'control-ack.json').write_text(json.dumps({'v': 1, 'id': 'not-a-uuid', 'ok': True, 'ts': 1}))
    assert sbx.wait_ack(sync, 'not-a-uuid') is None                      # id не uuid4 — не годится


def test_status_json_canonical_auto(sync, cli, capsys):
    with FakeApp(sync, selection=('__auto__', 'x', 'y')):
        sbx.cmd_status(axiom_state(), argparse.Namespace(json=True))
    assert json.loads(capsys.readouterr().out)['selection'] == {'c': '__auto__', 'p': 'x', 't': 'y'}  # как опубликовало приложение


# ── 7: polkit ────────────────────────────────────────────────────────────

def test_polkit_rule_text_and_install(monkeypatch, tmp_path):
    rule = tmp_path / 'rules.d/50-axiom-cli.rules'
    monkeypatch.setattr(sbx, 'POLKIT_RULE', rule)
    monkeypatch.setattr(sbx, 'BASE', 'axiom')
    monkeypatch.setattr(sbx, 'UNIT', 'axiom.service')
    monkeypatch.setenv('SUDO_USER', 'alice')
    text = sbx.polkit_rule_text(sbx.installing_user())
    assert 'subject.user == "alice"' in text and '"axiom.service"' in text and '"stop"' in text and 'restart' in text
    written = []
    monkeypatch.setattr(sbx, 'run', lambda cmd, check=True, **kw: written.append(('run', cmd)))
    monkeypatch.setattr(sbx, 'is_root', lambda: True)

    def fake_write(path, body):
        written.append(('write', path, body))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)

    monkeypatch.setattr(sbx, 'sudo_write', fake_write)
    assert sbx.install_polkit_rule() is True and rule.read_text() == text
    assert sbx.install_polkit_rule() is False                            # без изменений — повторно не пишется
    monkeypatch.setenv('SUDO_USER', 'bad user"; x')
    with pytest.raises(ValueError):
        sbx.installing_user()


def test_service_action_tries_without_sudo_when_rule_exists(monkeypatch, tmp_path):
    rule = tmp_path / 'rule'
    monkeypatch.setattr(sbx, 'POLKIT_RULE', rule)
    monkeypatch.setattr(sbx, 'IS_WIN', False)
    monkeypatch.setattr(sbx, 'BASE', 'axiom')
    calls = []

    def systemctl(*args, sudo=False, check=True, capture=False):
        calls.append((args, sudo))
        return subprocess.CompletedProcess(args, 0 if not sudo and len(calls) == 1 and fail[0] is False else 1)

    fail = [False]
    monkeypatch.setattr(sbx, 'systemctl', systemctl)
    sbx.service_action('stop')                                           # правила нет — сразу sudo
    assert calls == [(('stop', sbx.UNIT), True)]
    calls.clear()
    rule.write_text('x')
    sbx.service_action('stop')                                           # правило есть — без sudo, успех
    assert calls == [(('stop', sbx.UNIT), False)]
    calls.clear()
    fail[0] = True
    sbx.service_action('restart')                                        # без sudo отказ — запасной путь через sudo
    assert calls == [(('restart', sbx.UNIT), False), (('restart', sbx.UNIT), True)]
    calls.clear()
    monkeypatch.setattr(sbx, 'BASE', 'sbx')
    sbx.service_action('start')                                          # режим sbx не меняется
    assert calls == [(('start', sbx.UNIT), True)]


def test_uninstall_removes_polkit_rule(monkeypatch, tmp_path):
    rule = tmp_path / 'rule'
    rule.write_text('x')
    monkeypatch.setattr(sbx, 'POLKIT_RULE', rule)
    monkeypatch.setattr(sbx, 'IS_WIN', False)
    monkeypatch.setattr(sbx, 'BASE', 'axiom')
    monkeypatch.setattr(sbx, 'UNIT_DIR', tmp_path / 'units')
    monkeypatch.setattr(sbx, 'require_windows_admin', lambda argv=None: True)
    commands = []
    monkeypatch.setattr(sbx, 'run', lambda cmd, check=True, **kw: commands.append(cmd) or subprocess.CompletedProcess(cmd, 0))
    monkeypatch.setattr(sbx, 'is_root', lambda: True)
    sbx.cmd_uninstall(axiom_state(), argparse.Namespace())
    assert ['rm', '-f', str(rule)] in commands


def test_install_units_writes_rule_only_in_axiom_mode(monkeypatch, tmp_path):
    monkeypatch.setattr(sbx, 'IS_WIN', False)
    monkeypatch.setattr(sbx, 'UNIT_DIR', tmp_path / 'units')
    monkeypatch.setattr(sbx, 'sudo_write', lambda path, text: None)
    monkeypatch.setattr(sbx, 'systemctl', lambda *a, **k: None)
    monkeypatch.setattr(sbx, 'unit_text', lambda st: 'u')
    monkeypatch.setattr(sbx, 'timer_units', lambda: ('s', 't'))
    monkeypatch.setattr(sbx, 'WORK_DIR', tmp_path / 'work')
    calls = []
    monkeypatch.setattr(sbx, 'install_polkit_rule', lambda: calls.append(1) or True)
    monkeypatch.setattr(sbx, 'BASE', 'sbx')
    sbx.install_units({}, quiet=True)
    assert calls == []
    monkeypatch.setattr(sbx, 'BASE', 'axiom')
    sbx.install_units({}, quiet=True)
    assert calls == [1]


# ── 8: уже работает ──────────────────────────────────────────────────────

def test_up_with_running_cli_does_not_restart(sync, cli, capsys):
    cli['active'] = True
    sbx.cmd_up(axiom_state(), argparse.Namespace(force=False))
    assert cli['service'] == [] and 'применён без перезапуска' in capsys.readouterr().out


def test_connect_select_with_running_cli_applies_only(sync, cli):
    cli['active'] = True
    sbx.cmd_connect(axiom_state(), argparse.Namespace(number=None, select='France||', force=False))
    assert cli['service'] == []
    assert cli['api'] == [('PUT', '/proxies/proxy', {'name': FRANCE})]


# ── 11: перенос профиля старого CLI, отложенная загрузка ─────────────────

def test_old_cli_profile_path_imported(old_cli_dir, capsys):
    profile = old_cli_dir / 'profiles/subscription.json'
    profile.write_text(json.dumps({'outbounds': [
        {'tag': 'Netherlands (Test) [ws] § 0', 'type': 'socks', 'server': 'h.example', 'server_port': 1080}]}))
    (old_cli_dir / 'state.json').write_text(json.dumps({**OLD_CLI_STATE, 'subscription_url': '',
                                                        'profile_path': str(profile)}))
    st = sbx.load_state()
    assert [s['name'] for s in st['subs']] == ['axiom-local'] and 'pending_fetch' not in st
    assert st['subs'][0]['local_path'] == str(profile)
    cached = json.loads((old_cli_dir / 'subs/axiom-local.json').read_text())
    assert len(cached['servers']) == 1 and capsys.readouterr().err.strip()
    assert profile.exists()


def test_old_cli_profile_path_missing_file_ignored(old_cli_dir):
    (old_cli_dir / 'state.json').write_text(json.dumps({**OLD_CLI_STATE, 'subscription_url': '',
                                                        'profile_path': '/nonexistent/subscription.json'}))
    assert sbx.load_state()['subs'] == []


def test_pending_fetch_persists_until_success(monkeypatch, old_cli_dir):
    (old_cli_dir / 'state.json').write_text(json.dumps(OLD_CLI_STATE))
    monkeypatch.setattr(sbx, 'load_axiom_context', lambda: {'root': None, 'profiles': [], 'prefs': {}})
    monkeypatch.setattr(sbx.sys, 'argv', ['axiom'])
    monkeypatch.setattr(sbx, 'cmd_ls', lambda st, a: None)
    monkeypatch.setattr(sbx, 'update_rulesets', lambda *a, **k: None)
    monkeypatch.setattr(sbx, 'cmd_status', lambda st, a: None)
    online = [False]

    def fetch(st, sub):
        if not online[0]:
            raise OSError('нет сети')
        return ([{'name': 'France (x) [hy2]', 'outbound': SERVERS[0]['outbound']}], [], 0,
                {'updated': 1, 'format': 'x', 'title': ''})

    monkeypatch.setattr(sbx, 'fetch_sub', fetch)
    sbx.main(['status'])                                                   # status загрузку не трогает и метку не съедает
    assert json.loads((old_cli_dir / 'state.json').read_text())['pending_fetch'] == ['axiom']
    sbx.main(['ls'])                                                       # нет сети — метка остаётся
    assert json.loads((old_cli_dir / 'state.json').read_text())['pending_fetch'] == ['axiom']
    online[0] = True
    sbx.main(['ls'])
    saved = json.loads((old_cli_dir / 'state.json').read_text())
    assert 'pending_fetch' not in saved
    assert json.loads((old_cli_dir / 'subs/axiom.json').read_text())['servers'][0]['name'] == 'France (x) [hy2]'


# ── G: приложение само разбирает тройку; I: все поля app-state обязательны ──

def test_select_triple_sent_as_given_when_unknown_to_cli(monkeypatch, sync, cli, capsys):
    monkeypatch.setattr(sbx, 'all_servers', lambda st: [])            # у CLI своего меню нет
    with FakeApp(sync) as app:
        sbx.cmd_use(axiom_state(), argparse.Namespace(server=None, select='Mars|vless|ws'))
        sbx.cmd_use(axiom_state(), argparse.Namespace(server=None, select='__auto__|x|y'))
    assert [c['selection'] for c in app.executed] == [{'c': 'Mars', 'p': 'vless', 't': 'ws'},
                                                      {'c': '__auto__', 'p': '', 't': ''}]
    assert 'передан приложению' in capsys.readouterr().out
    with pytest.raises(SystemExit):                                    # только синтаксис проверяется локально
        sbx.cmd_use(axiom_state(), argparse.Namespace(server=None, select='|a|b'))


def test_app_rejects_unknown_triple(monkeypatch, sync, cli, capsys):
    with FakeApp(sync, ok=False):
        with pytest.raises(SystemExit) as exc:
            sbx.cmd_use(axiom_state(), argparse.Namespace(server=None, select='Mars|vless|ws'))
    assert exc.value.code == 1 and 'boom' in capsys.readouterr().err


@pytest.mark.parametrize('missing', ['v', 'pid', 'heartbeat', 'connected', 'connecting', 'selection'])
def test_app_state_requires_every_field(sync, missing):
    doc = {'v': 1, 'pid': 1, 'heartbeat': now_ms(), 'connected': True, 'connecting': False,
           'selection': {'c': '__auto__', 'p': '', 't': ''}}
    del doc[missing]
    (sync / 'app-state.json').write_text(json.dumps(doc))
    assert sbx.app_state(sync) is None
