import argparse
import json
import re
import sqlite3
import subprocess
import sys
import types
from contextlib import closing
from pathlib import Path

import pytest

import sbx
from .test_axiom import FRANCE, NETHERLANDS, TCP, app_directory, config, outbound, response, state  # noqa: F401
from .test_review_fixes import add_profile, windows

MINE = 'Mine'
DUPLICATE = 'Netherlands (b) [ws]'   # тот же ключ «страна/протокол/транспорт», что у NETHERLANDS


def servers_of(*specs):
    out = []
    for tag, app in specs:
        out.append({'tag': tag, 'source': 'app:App' if app else 'manual', 'outbound': outbound(tag),
                    **({'app_profile': True, 'app_group': True, 'app_order': 0} if app else {})})
    return out


def axiom_state(monkeypatch, servers):
    st = state()
    st['_axiom'] = {'root': None, 'profiles': [], 'prefs': {}, 'prefix': 'flutter.', 'version': None}
    monkeypatch.setattr(sbx, 'all_servers', lambda _: servers)
    monkeypatch.setattr(sbx, 'is_active', lambda _: False)
    monkeypatch.setattr(sbx, 'apply', lambda *a, **k: None)
    return st


# H1: one ordered list for ls, use, test, rm and the picker

def listing(st, capsys):
    sbx.cmd_ls(st, argparse.Namespace(filter=None))
    return capsys.readouterr().out


def test_numbers_shown_by_ls_resolve_to_the_same_servers(monkeypatch, capsys):
    servers = servers_of((FRANCE, True), (NETHERLANDS, True), (TCP, True), (MINE, False), (DUPLICATE, False))
    st = axiom_state(monkeypatch, servers)
    out = listing(st, capsys)
    numbered = [s['tag'] for s in sbx.numbered_servers(st, servers)]
    assert numbered[:3] == [FRANCE, TCP, NETHERLANDS] and set(numbered[3:]) == {MINE, DUPLICATE}
    shown = [int(n) for n in re.findall(r'^[●› ]\s+(\d+)\s', out, re.M) if int(n)]
    assert shown == list(range(1, len(numbered) + 1))
    for index, tag in enumerate(numbered, 1):
        assert sbx.resolve(st, str(index)) == tag
    for tag in (MINE, DUPLICATE):   # свои серверы печатаются вместе с номером
        number = re.search(rf'^[●› ]\s+(\d+)\s+{re.escape(tag)}\s', out, re.M)
        assert number and sbx.resolve(st, number[1]) == tag


def test_duplicate_own_server_is_selected_as_own_not_as_menu_entry(monkeypatch, capsys):
    servers = servers_of((FRANCE, True), (NETHERLANDS, True), (DUPLICATE, False))
    st = axiom_state(monkeypatch, servers)
    st['_axiom']['root'] = None
    number = str([s['tag'] for s in sbx.numbered_servers(st, servers)].index(DUPLICATE) + 1)
    sbx.cmd_use(st, argparse.Namespace(server=number))
    assert st['selected'] == DUPLICATE and st['axiom_extra']['tag'] == DUPLICATE


def test_test_and_rm_use_the_same_numbers(monkeypatch, capsys):
    servers = servers_of((FRANCE, True), (NETHERLANDS, True), (MINE, False), (DUPLICATE, False))
    st = axiom_state(monkeypatch, servers)
    st['manual'] = [{'name': MINE, 'outbound': outbound(MINE)}, {'name': DUPLICATE, 'outbound': outbound(DUPLICATE)}]

    class FakeProber:
        def __init__(self, *a):
            pass

        ensure = close = lambda self: None
        delay = lambda self, tag: 10

    monkeypatch.setattr(sbx, 'Prober', FakeProber)
    sbx.cmd_test(st, argparse.Namespace(filter=None, timeout=1))
    printed = {m[2].strip(): int(m[1]) for m in re.finditer(r'^\s*(\d+)\s+(.+?)\s+\d+ мс$', capsys.readouterr().out, re.M)}
    for index, server in enumerate(sbx.numbered_servers(st, servers), 1):
        assert printed[server['tag']] == index
    own = [s['tag'] for s in sbx.numbered_servers(st, servers)].index(DUPLICATE) + 1
    sbx.cmd_rm(st, argparse.Namespace(server=str(own)))
    assert [s['name'] for s in st['manual']] == [MINE]


def test_picker_uses_the_shared_menu(monkeypatch):
    servers = servers_of((FRANCE, True), (NETHERLANDS, True), (MINE, False), (DUPLICATE, False))
    st = axiom_state(monkeypatch, servers)
    ordered, extras = sbx.axiom_menu(servers)
    assert [tag for _, tag in ordered] == [FRANCE, NETHERLANDS] and extras == [MINE, DUPLICATE]
    chosen = {}
    monkeypatch.setattr(sbx, 'interactive', lambda: True)
    monkeypatch.setattr(sbx, 'pick_axiom', lambda options, own: chosen.update(options=options, own=own) or DUPLICATE)
    monkeypatch.setattr(sbx, 'cmd_use', lambda st_, a: chosen.update(used=a.server))
    sbx.cmd_pick(st, argparse.Namespace())
    assert chosen['own'] == extras and chosen['options'] == ordered and chosen['used'] == DUPLICATE


# H2 + M1: app-owned profile data

def app_with_profile(app_directory, *tags, selector=None):
    row = add_profile(app_directory, web_page_url='https://panel.example')
    path = app_directory / 'configs' / f'{row["id"]}.json'
    path.parent.mkdir()
    document = config(*tags)
    if selector is not None:
        document['outbounds'].append({'type': 'selector', 'tag': 'proxy', 'outbounds': selector})
    path.write_text(json.dumps(document))
    return row, path, document


def test_cli_refresh_never_touches_last_update_or_app_config(monkeypatch, app_directory):
    row, path, document = app_with_profile(app_directory, NETHERLANDS)
    before = path.read_text()
    monkeypatch.setattr(sbx.urllib.request, 'urlopen', lambda request, **kw: response(
        config(FRANCE), subscription_userinfo='upload=1; download=2; total=3; expire=4102444800'))
    app = sbx.load_axiom_context()
    assert sbx.update_app_profiles(app, app['profiles'], quiet=True)
    with closing(sqlite3.connect(app_directory / 'db.sqlite')) as db:
        stored = db.execute('SELECT last_update, upload, download, total FROM profile_entries').fetchone()
    assert stored == (row['last_update'], 1, 2, 3) and path.read_text() == before
    st = state()
    st['_axiom'] = app
    assert [s['tag'] for s in sbx.all_servers(st)] == [FRANCE]
    cache = sbx.read_app_cache(app, app['profiles'][0])
    assert cache and isinstance(cache['refreshed'], int)


def test_cache_is_tied_to_app_row_and_config_revision(monkeypatch, app_directory):
    row, path, _ = app_with_profile(app_directory, NETHERLANDS)
    monkeypatch.setattr(sbx.urllib.request, 'urlopen', lambda request, **kw: response(
        config(FRANCE), subscription_userinfo='upload=1; download=2; total=3'))
    app = sbx.load_axiom_context()
    sbx.update_app_profiles(app, app['profiles'], quiet=True)
    st = state()
    st['_axiom'] = app
    assert [s['tag'] for s in sbx.all_servers(st)] == [FRANCE]
    path.write_text(json.dumps(config(NETHERLANDS, TCP)))   # приложение переписало свой конфиг
    assert [s['tag'] for s in sbx.all_servers(st)] == [NETHERLANDS, TCP]


def test_cache_lives_in_own_directory_keyed_by_database(monkeypatch, app_directory):
    row, _, _ = app_with_profile(app_directory, NETHERLANDS)
    monkeypatch.setattr(sbx.urllib.request, 'urlopen', lambda request, **kw: response(config(FRANCE)))
    app = sbx.load_axiom_context()
    sbx.update_app_profiles(app, app['profiles'], quiet=True)
    cache = sbx.app_cache_file(app, row['id'])
    assert cache.parent == sbx.SUBS_DIR / 'axiom-app' / sbx.app_db_key(app) and cache.is_file()
    assert not list(sbx.SUBS_DIR.glob('axiom-app-*.json'))
    # одноимённая подписка sbx не пересекается с кэшем приложения
    st = state()
    st['subs'] = [{'name': f'axiom-app-{row["id"]}', 'url': 'https://example.test'}]
    sbx.write_private(sbx.sub_file(st['subs'][0]['name']), json.dumps({'servers': [], 'meta': {}}))
    assert sbx.read_app_cache(app, app['profiles'][0])
    other = dict(app, root=app['root'].parent / 'another')
    assert sbx.app_cache_file(other, row['id']) != cache


def test_cache_keeps_selector_group_membership_and_order(monkeypatch, app_directory):
    document = config(NETHERLANDS, FRANCE, TCP)
    document['outbounds'].append({'type': 'selector', 'tag': 'proxy', 'outbounds': [TCP, FRANCE]})
    row, path, _ = app_with_profile(app_directory, NETHERLANDS, FRANCE, TCP, selector=[TCP, FRANCE])
    app = sbx.load_axiom_context()
    st = state()
    st['_axiom'] = app
    before = sbx.axiom_options(sbx.all_servers(st))
    assert [tag for _, tag in before] == [TCP, FRANCE]
    body = dict(document, outbounds=[*document['outbounds'][:3], {'type': 'selector', 'tag': 'proxy',
                                                                  'outbounds': [TCP, FRANCE]}])
    monkeypatch.setattr(sbx.urllib.request, 'urlopen', lambda request, **kw: response(
        body, subscription_userinfo='upload=1; download=2; total=3'))
    sbx.update_app_profiles(app, app['profiles'], quiet=True)
    assert sbx.read_app_cache(app, app['profiles'][0])['group'] == [TCP, FRANCE]
    assert [tag for _, tag in sbx.axiom_options(sbx.all_servers(st))] == [TCP, FRANCE]   # NETHERLANDS не просочился


# H3: AxiOm defaults and brand coexistence

def test_axiom_fresh_state_uses_own_ports_only(monkeypatch):
    try:
        sbx.configure_identity(True, {}, False)
        fresh = sbx.load_state()['settings']
        assert (fresh['mixed_port'], fresh['api_port'], fresh['tun_name']) == (2180, 9197, 'axiom0')
        sbx.save_state(sbx.load_state())
        saved = json.loads(sbx.STATE_FILE.read_text())
        saved['settings']['mixed_port'] = 2080
        sbx.STATE_FILE.write_text(json.dumps(saved))
        assert sbx.load_state()['settings']['mixed_port'] == 2080   # существующее состояние не трогаем
    finally:
        sbx.configure_identity(False, {}, False)
    assert sbx.load_state()['settings']['mixed_port'] == 2080 and sbx.load_state()['settings']['api_port'] == 9097


def other_state(mode, axiom):
    conf = sbx.platform_paths(sbx.HOME, sbx.os.environ, False, axiom)[0]
    conf.mkdir(parents=True)
    (conf / 'state.json').write_text(json.dumps({'settings': {'mode': mode}}))


@pytest.mark.parametrize('ours,theirs,force,refused', [
    ('tun', 'tun', False, True), ('tun', 'tun', True, False), ('tun', 'proxy', False, True),
    ('proxy', 'tun', False, True), ('proxy', 'proxy', False, False)])
def test_up_refuses_while_other_brand_is_active(monkeypatch, ours, theirs, force, refused):
    monkeypatch.delenv('SBX_HOME', raising=False)
    monkeypatch.setattr(sbx, 'is_root', lambda: False)
    other_state(theirs, axiom=True)   # мы — sbx, активна AxiOm
    calls = []
    monkeypatch.setattr(sbx, 'systemctl', lambda *a, **k: types.SimpleNamespace(
        stdout='active\n' if a[-1] == 'axiom.service' else 'inactive\n'))
    assert sbx.other_brand_active() == ('axiom', theirs)
    monkeypatch.setattr(sbx, 'foreign_tun', lambda: [])
    monkeypatch.setattr(sbx, 'prepare_service', lambda st: calls.append('prepare') or sbx.die('stop here', 9))
    st = state()
    st['settings']['mode'] = ours
    with pytest.raises(SystemExit) as raised:
        sbx.cmd_up(st, argparse.Namespace(force=force))
    assert (raised.value.code == 1) is refused and (calls == []) is refused


def test_other_brand_inactive_is_not_a_conflict(monkeypatch):
    monkeypatch.setattr(sbx, 'systemctl', lambda *a, **k: types.SimpleNamespace(stdout='inactive\n'))
    assert sbx.other_brand_active() is None


def test_windows_other_brand_uses_its_task(monkeypatch):
    monkeypatch.setattr(sbx, 'IS_WIN', True)
    seen = []
    monkeypatch.setattr(sbx, 'task_running', lambda name=None: seen.append(name) or name == 'axiom')
    assert sbx.other_brand_active() == ('axiom', 'tun') and seen == ['axiom']


# H4 leftovers: PyInstaller/Windows launch plumbing is covered in test_review_fixes


# M2: uninstall

def win_uninstall(monkeypatch, *, listed=True, running=(True,), end_code=0, delete_code=0):
    windows(monkeypatch)
    monkeypatch.setattr(sbx, 'windows_admin', lambda: True)
    monkeypatch.setattr(sbx.time, 'sleep', lambda s: None)
    calls = []
    states = iter(running)
    last = [running[-1]]

    def running_now(name=None):
        calls.append(('running', name))
        value = next(states, last[0])
        return value if name == 'sbx' else False

    def listed_now(name):
        if isinstance(listed, Exception):
            raise listed
        return listed if name == 'sbx' else False

    monkeypatch.setattr(sbx, 'task_running', running_now)
    monkeypatch.setattr(sbx, 'task_listed', listed_now)
    monkeypatch.setattr(sbx, 'task_call', lambda action, name=None, *a, **k: calls.append((action, name)) or
                        subprocess.CompletedProcess([], end_code))
    monkeypatch.setattr(sbx, 'run', lambda cmd, check=True, **kw: calls.append(tuple(cmd)) or
                        subprocess.CompletedProcess(cmd, delete_code))
    return calls


def test_windows_uninstall_stops_verifies_then_deletes(monkeypatch, capsys):
    calls = win_uninstall(monkeypatch, running=(True, True, False))
    sbx.cmd_uninstall(state(), argparse.Namespace())
    assert ('end', 'sbx') in calls
    assert calls.index(('end', 'sbx')) < calls.index(('schtasks', '/delete', '/tn', 'sbx', '/f'))
    assert 'удалены' in capsys.readouterr().out


def test_windows_uninstall_missing_task_is_not_an_error(monkeypatch, capsys):
    calls = win_uninstall(monkeypatch, listed=False)
    sbx.cmd_uninstall(state(), argparse.Namespace())
    assert not any(call[0] == 'schtasks' for call in calls if isinstance(call, tuple))


@pytest.mark.parametrize('kwargs,expected', [
    ({'listed': OSError('планировщик недоступен')}, 'планировщик недоступен'),
    ({'end_code': 1}, 'остановка задачи sbx'),
    ({'running': (True,)}, 'не остановилась'),
    ({'running': (True, False), 'delete_code': 1}, 'удаление задачи sbx')])
def test_windows_uninstall_failures_are_fatal_and_never_delete_a_live_task(monkeypatch, capsys, kwargs, expected):
    calls = win_uninstall(monkeypatch, **kwargs)
    with pytest.raises(SystemExit) as raised:
        sbx.cmd_uninstall(state(), argparse.Namespace())
    assert raised.value.code == 1 and expected in capsys.readouterr().err
    deleted = ('schtasks', '/delete', '/tn', 'sbx', '/f') in calls
    assert deleted is (kwargs.get('delete_code') == 1)


def test_task_listed_distinguishes_missing_from_query_failure(monkeypatch):
    monkeypatch.setattr(sbx, 'task_definition', lambda name: None)
    monkeypatch.setattr(sbx, 'task_call', lambda *a, **k: subprocess.CompletedProcess([], 0, '"\\sbx","N/A","Ready"\n', ''))
    assert sbx.task_listed('sbx') is True and sbx.task_listed('axiom') is False
    monkeypatch.setattr(sbx, 'task_call', lambda *a, **k: subprocess.CompletedProcess([], 5, '', 'Access denied'))
    with pytest.raises(OSError, match='Access denied'):
        sbx.task_listed('sbx')


def test_linux_uninstall_stops_updater_before_removing_units(monkeypatch, tmp_path):
    monkeypatch.setattr(sbx, 'UNIT_DIR', tmp_path)
    for name in ('sbx.service', 'sbx-update.service', 'sbx-update.timer'):
        (tmp_path / name).write_text('x')
    monkeypatch.setattr(sbx, 'IS_WIN', False)
    monkeypatch.setattr(sbx, 'is_root', lambda: True)
    calls = []
    monkeypatch.setattr(sbx, 'run', lambda cmd, check=True, **kw: calls.append(list(cmd)) or
                        subprocess.CompletedProcess(cmd, 0))
    sbx.cmd_uninstall(state(), argparse.Namespace())
    stop = calls.index(['systemctl', 'stop', 'sbx-update.timer', 'sbx-update.service'])
    assert stop < min(i for i, call in enumerate(calls) if call[0] == 'rm')


# M3: service commands survive a broken app directory; updater keeps its paths

def test_down_status_uninstall_work_with_broken_axiom_home(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv('SBX_BRAND', 'axiom')
    monkeypatch.setenv('SBX_AXIOM_HOME', str(tmp_path / 'moved'))
    monkeypatch.setattr(sbx, 'remove_old_exe', lambda: None)
    seen = []
    monkeypatch.setattr(sbx, 'service_action', lambda action: seen.append(action))
    monkeypatch.setattr(sbx, 'show_status', lambda st: seen.append(('status', st['_axiom']['root'])))
    monkeypatch.setattr(sbx, 'cmd_uninstall', lambda st, a: seen.append('uninstall'))
    monkeypatch.setattr(sbx, 'cmd_disable', lambda st, a: seen.append('disable'))
    try:
        for command in ('down', 'status', 'uninstall', 'disable'):
            sbx.main([command])
        assert seen == ['stop', ('status', None), 'uninstall', 'disable']
        assert 'SBX_AXIOM_HOME' in capsys.readouterr().err   # status предупреждает
        with pytest.raises(SystemExit) as raised:
            sbx.main(['ls'])
        assert raised.value.code == 1
    finally:
        sbx.configure_identity(False, {}, False)


def test_windows_updater_task_keeps_resolved_overrides(monkeypatch, tmp_path):
    windows(monkeypatch)
    monkeypatch.setattr(sbx, 'launch_command', lambda argv: ['python.exe', 'axiom.py', *argv])
    monkeypatch.setenv('SBX_HOME', str(tmp_path / 'h'))
    monkeypatch.setenv('SBX_AXIOM_HOME', 'relative-app')
    monkeypatch.setenv('SBX_SING_BOX', str(tmp_path / 'sing-box'))
    monkeypatch.setenv('SBX_BRAND', 'axiom')
    registered = {}
    monkeypatch.setattr(sbx, 'register_task', lambda name, xml, **k: registered.update(name=name, xml=xml))
    sbx.register_windows_updater()
    xml = registered['xml'].decode('utf-16')
    assert registered['name'] == sbx.UPDATE
    for flag, value in (('--sbx-home', tmp_path / 'h'), ('--axiom-home', Path('relative-app').absolute()),
                        ('--sing-box', tmp_path / 'sing-box')):
        assert flag in xml and str(value) in xml
    assert '--axiom sub update -q' in xml


def test_updater_flags_are_accepted_unprivileged_and_apply(monkeypatch, tmp_path):
    windows(monkeypatch)
    monkeypatch.delenv('SBX_HOME', raising=False)
    monkeypatch.delenv('SBX_BRAND', raising=False)
    try:
        elevated, rest = sbx.take_elevated_prefix(['--sbx-home', str(tmp_path), '--axiom', 'sub', 'update', '-q'])
        assert elevated is False and rest == ['sub', 'update', '-q']
        assert sbx.os.environ['SBX_HOME'] == str(tmp_path) and sbx.axiom_mode()
    finally:
        sbx.os.environ.pop('SBX_HOME', None)
        sbx.os.environ.pop('SBX_BRAND', None)
        sbx.configure_identity(False, {}, False)


# Low items

def test_prefs_lock_is_next_to_the_shared_prefs_file(app_directory, monkeypatch):
    locks = []

    @sbx.contextmanager
    def fake_lock(path):
        locks.append(path)
        yield

    monkeypatch.setattr(sbx, 'file_lock', fake_lock)
    app = sbx.load_axiom_context()
    sbx.axiom_write_selection(app, ('France', 'hysteria2', 'hy2'))
    assert locks == [app['prefs_path'].with_name(sbx.AXIOM_FILE + '.sbx-lock')]


def test_windows_lock_seeks_to_zero_before_lock_and_unlock(monkeypatch, tmp_path):
    positions = []

    def locking(fd, mode, size):
        positions.append((mode, sbx.os.lseek(fd, 0, 1)))

    fake = types.SimpleNamespace(LK_LOCK=1, LK_UNLCK=0, locking=locking)
    monkeypatch.setitem(sys.modules, 'msvcrt', fake)
    monkeypatch.setattr(sbx.sys, 'platform', 'win32')
    path = tmp_path / 'x.lock'
    path.write_bytes(b'content')   # append-режим ставит позицию в конец — замок обязан вернуться к нулю
    with sbx.file_lock(path):
        pass
    assert positions == [(1, 0), (0, 0)]


def test_console_tools_decode_oem_and_others_utf8(monkeypatch):
    seen = []
    monkeypatch.setattr(sbx.subprocess, 'run', lambda cmd, check=True, **kw: seen.append(kw['encoding']))
    monkeypatch.setattr(sbx.sys, 'platform', 'win32')
    for command in (['schtasks', '/query'], [r'C:\Windows\System32\whoami.EXE'], ['icacls', 'x'],
                    ['powershell', '-Command', 'x'], [r'C:\p\sing-box.exe', 'check'], ['git', 'x']):
        sbx.run(command)
    assert seen == ['oem', 'oem', 'oem', 'oem', 'utf-8', 'utf-8']
    monkeypatch.setattr(sbx.sys, 'platform', 'linux')
    seen.clear()
    monkeypatch.setattr(sbx.subprocess, 'run', lambda cmd, check=True, **kw: seen.append(kw.get('encoding')))
    sbx.run(['ls'])
    assert seen == [None]


def test_failed_post_command_update_keeps_primary_exit_code(monkeypatch, capsys):
    windows(monkeypatch)
    monkeypatch.setattr(sbx, 'interactive', lambda: True)
    monkeypatch.delenv('SBX_NO_UPDATE_CHECK')
    monkeypatch.setattr(sbx, 'take_update_slot', lambda st: True)
    monkeypatch.setattr(sbx, 'latest_update', lambda: {'tag_name': 'v9.9.9', 'assets': []})
    monkeypatch.setattr(sbx, 'update_prompt', lambda release: True)
    monkeypatch.setattr(sbx, 'NO_ELEVATE', True)

    def install(release):
        sbx.require_windows_admin(['self-update', '--yes'])   # --no-elevate: SystemExit(2)

    monkeypatch.setattr(sbx, 'install_update', install)
    sbx.maybe_notice_update(state(), argparse.Namespace(cmd='ls'))
    assert 'не установлено' in capsys.readouterr().err
