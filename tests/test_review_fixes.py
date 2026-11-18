import argparse
import json
import sqlite3
import subprocess
import sys
import uuid
from contextlib import closing
from pathlib import Path

import pytest

import sbx
from .test_axiom import (FRANCE, GERMANY, NETHERLANDS, TCP, app_directory, config, outbound,  # noqa: F401
                        response, state)


def add_profile(directory, **fields):
    row = {'id': str(uuid.uuid4()), 'type': 'remote', 'active': 1, 'name': 'App', 'url': 'https://example.test/app',
           'last_update': '2026-01-02T03:04:05.000Z', **fields}
    with closing(sqlite3.connect(directory / 'db.sqlite')) as db, db:
        db.execute(f"INSERT INTO profile_entries ({', '.join(row)}) VALUES ({', '.join('?' for _ in row)})",
                   tuple(row.values()))
    return row


def set_version(directory, version):
    with closing(sqlite3.connect(directory / 'db.sqlite')) as db, db:
        db.execute(f'PRAGMA user_version = {version}')


# 1, 13: privileged commands

def test_sudo_self_update_argv(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, check=True, **kw):
        calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout='/x/.sbx-update.ABCDEFGH\n')

    monkeypatch.setattr(sbx, 'run', fake_run)
    target = tmp_path / 'sbx.py'
    target.write_text('old')
    monkeypatch.setattr(sbx, 'is_root', lambda: False)
    sbx.sudo_replace_update(tmp_path / 'download', target)
    assert calls[0] == ['sudo', 'mktemp', '-p', str(tmp_path), '.sbx-update.XXXXXXXX']
    assert all(call[0] == 'sudo' for call in calls)
    calls.clear()
    monkeypatch.setattr(sbx, 'is_root', lambda: True)
    sbx.sudo_replace_update(tmp_path / 'download', target)
    assert calls[0][:2] == ['mktemp', '-p'] and not any('sudo' in call for call in calls)


def test_systemctl_and_units_skip_sudo_for_root(monkeypatch):
    calls = []
    monkeypatch.setattr(sbx, 'run', lambda cmd, check=True, **kw: calls.append(list(cmd)))
    monkeypatch.setattr(sbx, 'is_root', lambda: True)
    sbx.systemctl('daemon-reload', sudo=True)
    sbx.sudo_write(Path('/etc/x'), 'text')
    assert calls == [['systemctl', 'daemon-reload'], ['tee', '/etc/x']]
    monkeypatch.setattr(sbx, 'is_root', lambda: False)
    assert sbx.sudo_cmd('ls') == ['sudo', 'ls']


# 2: AxiOm database robustness

def test_unwritable_app_db_does_not_block_own_subscriptions(monkeypatch, app_directory, capsys):
    add_profile(app_directory)
    set_version(app_directory, 6)
    monkeypatch.setattr(sbx, 'update_rulesets', lambda *a, **k: [])
    monkeypatch.setattr(sbx.urllib.request, 'urlopen', lambda request, **kw: response(config(FRANCE)))
    st = state()
    st['subs'] = [{'name': 'mine', 'url': 'https://example.test/mine', 'hwid': False}]
    st['_axiom'] = sbx.load_axiom_context()
    capsys.readouterr()
    assert sbx.update_subs(st, quiet=True) is True
    assert 'только для чтения' in capsys.readouterr().err
    assert [s['name'] for s in sbx.load_sub_cache('mine')['servers']] == [FRANCE]


def test_locked_app_db_falls_back(monkeypatch, app_directory, tmp_path, capsys):
    with closing(sqlite3.connect(app_directory / 'db.sqlite')) as db:
        db.execute('PRAGMA journal_mode = DELETE')
    other = sqlite3.connect(app_directory / 'db.sqlite', isolation_level=None)
    other.execute('BEGIN EXCLUSIVE')
    try:
        app = sbx.load_axiom_context()
        assert app['profiles'] == [] and app['version'] is None
        assert 'недоступна' in capsys.readouterr().err
        with pytest.raises(ValueError, match='недоступна'):
            sbx.app_writable(app)
        monkeypatch.setattr(sbx.sys, 'argv', ['axiom'])
        monkeypatch.setattr(sbx, 'interactive', lambda: False)
        sbx.main(['rule'])
    finally:
        other.close()


def test_selection_write_does_not_need_v5(monkeypatch, app_directory):
    set_version(app_directory, 6)
    app = sbx.load_axiom_context()
    sbx.axiom_write_selection(app, ('France', 'hysteria2', 'hy2'))
    prefs = json.loads((app_directory / sbx.AXIOM_FILE).read_text())
    assert prefs['flutter.server_selector_country'] == 'France'


# 3, 14: Windows elevation

def windows(monkeypatch):
    monkeypatch.setattr(sbx, 'IS_WIN', True)
    monkeypatch.setattr(sbx, 'windows_user_sid', lambda: 'S-1-5-21-1')
    monkeypatch.setattr(sbx, 'windows_admin', lambda: False)


def test_elevated_arguments_forward_environment(monkeypatch):
    windows(monkeypatch)
    monkeypatch.setenv('SBX_HOME', 'C:/h')
    monkeypatch.setenv('SBX_AXIOM_HOME', 'C:/a')
    monkeypatch.setenv('SBX_SING_BOX', 'C:/s.exe')
    monkeypatch.setenv('SBX_BRAND', 'axiom')
    assert sbx.elevated_arguments() == ['--elevated-for', 'S-1-5-21-1', '--sbx-home', 'C:/h',
                                        '--axiom-home', 'C:/a', '--sing-box', 'C:/s.exe', '--axiom']


def test_request_windows_admin_runs_visible_child_and_exits_with_its_code(monkeypatch, capsys):
    windows(monkeypatch)
    seen = {}

    def runas(exe, params, cwd):
        seen['params'] = params
        return 7

    monkeypatch.setattr(sbx, 'shell_execute_runas', runas)
    with pytest.raises(SystemExit) as raised:
        sbx.request_windows_admin(['restart'])
    assert raised.value.code == 7
    assert '--elevated-log' not in seen['params']   # никакого пути журнала от вызывающего
    assert '--elevated-for S-1-5-21-1' in seen['params'] and seen['params'].endswith('restart')
    monkeypatch.setattr(sbx, 'shell_execute_runas', lambda *a: 0)
    sbx.request_windows_admin(['restart'])
    assert 'администратора' in capsys.readouterr().out


def test_request_windows_admin_reports_win32_failure(monkeypatch, capsys):
    windows(monkeypatch)

    def runas(*args):
        raise OSError('[WinError 1223] Операция отменена пользователем')

    monkeypatch.setattr(sbx, 'shell_execute_runas', runas)
    with pytest.raises(SystemExit) as raised:
        sbx.request_windows_admin(['up'])
    assert raised.value.code == 1 and '1223' in capsys.readouterr().err


def test_wait_exit_code_checks_every_win32_result():
    errors = lambda: OSError('winerror')
    assert sbx.wait_exit_code(5, lambda h: 0, lambda h: (True, 3), errors) == 3
    with pytest.raises(OSError, match='winerror'):
        sbx.wait_exit_code(5, lambda h: 0xFFFFFFFF, lambda h: (True, 0), errors)
    with pytest.raises(OSError, match='0x102'):
        sbx.wait_exit_code(5, lambda h: 0x102, lambda h: (True, 0), errors)
    with pytest.raises(OSError, match='winerror'):
        sbx.wait_exit_code(5, lambda h: 0, lambda h: (False, 0), errors)


def test_elevated_child_pauses_only_on_failure_with_a_console(monkeypatch, capsys):
    windows(monkeypatch)
    monkeypatch.setattr(sbx, 'windows_admin', lambda: True)
    monkeypatch.setattr(sbx, 'remove_old_exe', lambda: None)
    answers = []
    monkeypatch.setattr('builtins.input', lambda *a: answers.append(1) or '')
    stdin = type('Stdin', (), {'isatty': staticmethod(lambda: True)})()
    monkeypatch.setattr(sbx.sys, 'stdin', stdin)
    outcome = {'code': 3}

    def fake_cli(argv):
        if outcome['code']:
            sbx.die('сломалось', outcome['code'])

    monkeypatch.setattr(sbx, 'run_cli', fake_cli)
    try:
        with pytest.raises(SystemExit) as raised:
            sbx.main(['--elevated-for', 'S-1-5-21-1', 'up'])
        assert raised.value.code == 3 and len(answers) == 1
        assert 'сломалось' in capsys.readouterr().err
        outcome['code'] = 0
        sbx.main(['--elevated-for', 'S-1-5-21-1', 'up'])
        assert len(answers) == 1                        # успех — без паузы
        outcome['code'] = 4
        monkeypatch.setattr(sbx.sys, 'stdin', type('Stdin', (), {'isatty': staticmethod(lambda: False)})())
        with pytest.raises(SystemExit):
            sbx.main(['--elevated-for', 'S-1-5-21-1', 'up'])
        assert len(answers) == 1                        # нет консоли — не ждём Enter
    finally:
        sbx.configure_identity(False, {}, False)


def test_elevated_prefix_restores_environment(monkeypatch):
    windows(monkeypatch)
    monkeypatch.setattr(sbx, 'windows_admin', lambda: True)
    monkeypatch.delenv('SBX_HOME', raising=False)
    monkeypatch.delenv('SBX_BRAND', raising=False)
    try:
        elevated, rest = sbx.take_elevated_prefix(['--elevated-for', 'S-1-5-21-1', '--sbx-home', '/tmp/h',
                                                   '--axiom', 'status'])
        assert (elevated, rest) == (True, ['status'])
        assert sbx.os.environ['SBX_HOME'] == '/tmp/h' and sbx.axiom_mode()
    finally:
        sbx.os.environ.pop('SBX_HOME', None)
        sbx.os.environ.pop('SBX_BRAND', None)
        sbx.configure_identity(False, {}, False)
    with pytest.raises(SystemExit):   # привилегированный процесс без --elevated-for
        sbx.take_elevated_prefix(['--sbx-home', '/x', 'status'])
    with pytest.raises(SystemExit):   # --elevated-log больше не существует
        sbx.main(['--elevated-for', 'S-1-5-21-1', '--elevated-log', 'x', 'status'])


def test_no_elevate_exits_with_2(monkeypatch, capsys):
    windows(monkeypatch)
    monkeypatch.setattr(sbx, 'shell_execute_runas', lambda *a: pytest.fail('UAC'))
    monkeypatch.setattr(sbx, 'NO_ELEVATE', True)
    with pytest.raises(SystemExit) as raised:
        sbx.require_windows_admin(['uninstall'])
    assert raised.value.code == 2
    assert 'uninstall' in capsys.readouterr().err


def test_no_elevate_flag_parsed_by_main(monkeypatch):
    windows(monkeypatch)
    monkeypatch.setattr(sbx, 'load_state', lambda: state())
    monkeypatch.setattr(sbx, 'task_definition', lambda name: None)
    with pytest.raises(SystemExit) as raised:
        sbx.main(['--no-elevate', 'uninstall'])
    assert raised.value.code == 2


# 4: app-owned data

def test_app_profile_not_clobbered(monkeypatch, app_directory):
    row = add_profile(app_directory, web_page_url='https://panel.example', profile_override='{"warp":{"enable":true}}',
                      user_override='{"version":1,"name":"Mine"}', populated_headers='{"a":1}')
    config_path = app_directory / 'configs' / f'{row["id"]}.json'
    config_path.parent.mkdir()
    app_text = json.dumps(config(NETHERLANDS))
    config_path.write_text(app_text)
    monkeypatch.setattr(sbx.urllib.request, 'urlopen', lambda request, **kw: response(
        config(FRANCE), subscription_userinfo='upload=1; download=2; total=3', support_url='https://s.example',
        profile_web_page_url='https://other.example'))
    app = sbx.load_axiom_context()
    assert sbx.update_app_profiles(app, app['profiles'], quiet=True)
    assert config_path.read_text() == app_text
    updated = app['profiles'][0]
    assert (updated['upload'], updated['download'], updated['total']) == (1, 2, 3)
    assert updated['web_page_url'] == 'https://panel.example' and updated['support_url'] is None
    assert updated['profile_override'] == '{"warp":{"enable":true}}' and updated['name'] == 'App'
    assert sbx.owned_profile_ids() == set()
    st = state()
    st['_axiom'] = app
    assert [s['tag'] for s in sbx.all_servers(st)] == [FRANCE]
    # приложение обновило строку само — его конфиг снова главный
    with closing(sqlite3.connect(app_directory / 'db.sqlite')) as db, db:
        db.execute('UPDATE profile_entries SET last_update = ?', ('2026-02-02T00:00:00.000Z',))
    st['_axiom'] = sbx.load_axiom_context()
    assert [s['tag'] for s in sbx.all_servers(st)] == [NETHERLANDS]


def test_app_profile_without_userinfo_leaves_row_untouched(monkeypatch, app_directory):
    row = add_profile(app_directory, upload=5, download=6, total=7)
    monkeypatch.setattr(sbx.urllib.request, 'urlopen', lambda request, **kw: response(config(TCP)))
    app = sbx.load_axiom_context()
    sbx.update_app_profiles(app, app['profiles'], quiet=True)
    assert app['profiles'][0]['last_update'] == row['last_update'] and app['profiles'][0]['upload'] == 5
    st = state()
    st['_axiom'] = app
    assert [s['tag'] for s in sbx.all_servers(st)] == [TCP]


def test_sbx_profile_backup_override_and_url_gating(monkeypatch, app_directory):
    monkeypatch.setattr(sbx.urllib.request, 'urlopen', lambda request, **kw: response(
        config(FRANCE), subscription_userinfo='upload=1; download=2; total=3', support_url='not a url',
        profile_web_page_url='https://panel.example'))
    app = sbx.load_axiom_context()
    sbx.write_axiom_profile(app, name='N', url='https://example.test/s')
    profile = app['profiles'][0]
    assert profile['id'] in sbx.owned_profile_ids()
    assert profile['support_url'] is None and profile['web_page_url'] == 'https://panel.example'
    with closing(sqlite3.connect(app_directory / 'db.sqlite')) as db, db:
        db.execute('UPDATE profile_entries SET profile_override = ?', ('{"custom": 1}',))
    app = sbx.load_axiom_context()
    monkeypatch.setattr(sbx.urllib.request, 'urlopen', lambda request, **kw: response(config(TCP)))
    sbx.update_app_profiles(app, app['profiles'], quiet=True)
    path = app_directory / 'configs' / f'{profile["id"]}.json'
    assert json.loads(path.read_text()) == config(TCP)
    assert json.loads(path.with_name(path.name + '.sbx-prev').read_text()) == config(FRANCE)
    assert json.loads(app['profiles'][0]['profile_override'])['custom'] == 1


# 5, 6, 7, 9, 10

def test_notice_skips_connection_commands_and_runs_after(monkeypatch, tmp_path):
    monkeypatch.setattr(sbx, 'interactive', lambda: True)
    monkeypatch.delenv('SBX_NO_UPDATE_CHECK', raising=False)
    monkeypatch.delenv('INVOCATION_ID', raising=False)
    checks = []
    monkeypatch.setattr(sbx, 'take_update_slot', lambda st: checks.append('slot') or False)
    for cmd in ('up', 'down', 'disconnect', 'restart', 'connect', 'status'):
        sbx.maybe_notice_update(state(), argparse.Namespace(cmd=cmd))
    assert checks == []
    order = []
    monkeypatch.setattr(sbx, 'maybe_notice_update', lambda st, a: order.append('notice'))
    monkeypatch.setattr(sbx, 'cmd_ip', lambda st, a: order.append('command'))
    monkeypatch.setattr(sbx, 'load_state', lambda: state())
    monkeypatch.setattr(sbx, 'save_state', lambda st: None)
    sbx.main(['ip'])
    assert order == ['command', 'notice']


def test_task_running_skips_blank_csv_rows(monkeypatch):
    monkeypatch.setattr(sbx, 'task_call', lambda *a, **k: subprocess.CompletedProcess(
        a, 0, stdout='\n"sbx","N/A","Running"\n'))
    assert sbx.task_running() is True


def test_import_url_with_app_keeps_panel_title(monkeypatch):
    calls = []
    monkeypatch.setattr(sbx, 'cmd_sub', lambda st, a: calls.append(a.name))
    st = state()
    st['_axiom'] = {'root': Path('/x'), 'profiles': []}
    sbx.cmd_import(st, argparse.Namespace(source='https://example.test/s'))
    st['_axiom'] = {'root': None, 'profiles': []}
    sbx.cmd_import(st, argparse.Namespace(source='https://example.test/s'))
    assert calls == [None, 'example.test']


def test_pick_without_terminal_dies(monkeypatch, capsys):
    monkeypatch.setattr(sbx, 'interactive', lambda: False)
    with pytest.raises(SystemExit) as raised:
        sbx.cmd_pick(state(), argparse.Namespace())
    assert raised.value.code == 1 and 'нужен терминал' in capsys.readouterr().err


def test_run_survives_undecodable_output():
    result = sbx.run([sys.executable, '-c', 'import sys; sys.stdout.buffer.write(b"\\xff\\xfeok")'],
                     capture_output=True)
    assert result.stdout.endswith('ok')


# 8: own servers stay visible in AxiOm mode

def test_own_servers_listed_and_selectable(monkeypatch, app_directory, capsys):
    row = add_profile(app_directory)
    path = app_directory / 'configs' / f'{row["id"]}.json'
    path.parent.mkdir()
    path.write_text(json.dumps(config(FRANCE, NETHERLANDS)))
    app = sbx.load_axiom_context()
    st = state()
    st['_axiom'] = app
    st['manual'] = [{'name': 'Mine', 'outbound': outbound('Mine')}]
    servers = sbx.all_servers(st)
    options = sbx.axiom_options(servers)
    assert sbx.axiom_extras(servers, options) == ['Mine']
    monkeypatch.setattr(sbx, 'is_active', lambda _: False)
    sbx.cmd_ls(st, argparse.Namespace(filter=None))
    out = capsys.readouterr().out
    assert out.index('Свои серверы') < out.index('Mine')
    assert sbx.resolve(st, '3') == 'Mine'
    assert 'Mine' in sbx.build_config(st, servers)['outbounds'][1]['outbounds']
    monkeypatch.setattr(sbx, 'apply', lambda *a, **k: None)
    monkeypatch.setattr(sbx, 'is_active', lambda _: False)
    sbx.cmd_use(st, argparse.Namespace(server='3'))
    assert sbx.selected_server(st, servers) == 'Mine'
    sbx.cmd_use(st, argparse.Namespace(server='1'))
    assert sbx.selected_server(st, servers) == FRANCE
    answers = iter(['3', '1'])
    monkeypatch.setattr('builtins.input', lambda prompt: next(answers))
    assert sbx.pick_axiom(options, ['Mine']) == 'Mine'


def test_no_app_unclassified_servers_listed_plainly(monkeypatch, capsys):
    servers = [{'tag': GERMANY, 'source': 'fixture', 'outbound': outbound(GERMANY)}]
    st = state()
    st['_axiom'] = {'root': None, 'profiles': []}
    monkeypatch.setattr(sbx, 'all_servers', lambda _: servers)
    monkeypatch.setattr(sbx, 'is_active', lambda _: False)
    sbx.cmd_ls(st, argparse.Namespace(filter=None))
    assert 'Germany' in capsys.readouterr().out
    assert sbx.build_config(st, servers)['outbounds'][1]['outbounds'] == [GERMANY]


# 12: separate identities

def test_identity_per_brand():
    home = Path('/h')
    assert sbx.platform_paths(home, {}, False) == (home / '.config/sbx', home / '.local/state/sbx', None)
    assert sbx.platform_paths(home, {}, False, True) == (home / '.config/axiom/cli', home / '.local/state/axiom', None)
    env = {'APPDATA': 'R', 'LOCALAPPDATA': 'L'}
    assert sbx.platform_paths(home, env, True) == (Path('R/sbx'), Path('L/sbx/work'), Path('L/sbx/core'))
    assert sbx.platform_paths(home, env, True, True) == (Path('R/AxiOm/cli'), Path('L/AxiOm/cli/work'),
                                                         Path('L/AxiOm/cli/core'))
    assert sbx.platform_paths(home, {'SBX_HOME': '/t'}, False, True) == (Path('/t'), Path('/t/work'), None)
    assert sbx.identity_names(False) == {'base': 'sbx', 'unit': 'sbx.service', 'update': 'sbx-update',
                                         'probe': 'sbx-probe', 'probe_unit': 'sbx-probe.service', 'tun': 'sbx0'}
    names = sbx.identity_names(True)
    assert (names['unit'], names['update'], names['tun']) == ('axiom.service', 'axiom-update', 'axiom0')


def test_axiom_uninstall_only_touches_axiom_units(monkeypatch, tmp_path, capsys):
    try:
        sbx.configure_identity(True, {}, False)
        assert sbx.UNIT == 'axiom.service' and sbx.UPDATE == 'axiom-update'
        monkeypatch.setattr(sbx, 'UNIT_DIR', tmp_path)
        for name in ('axiom.service', 'axiom-update.service', 'axiom-update.timer', 'sbx.service'):
            (tmp_path / name).write_text('x')
        monkeypatch.setattr(sbx, 'IS_WIN', False)
        monkeypatch.setattr(sbx, 'is_root', lambda: True)
        calls = []
        code = {'value': 0}
        monkeypatch.setattr(sbx, 'run', lambda cmd, check=True, **kw: calls.append(list(cmd)) or
                            subprocess.CompletedProcess(cmd, code['value']))
        sbx.cmd_uninstall(state(), argparse.Namespace())
        assert calls and not any('sbx' in part for call in calls for part in call)
        assert not any(call[0] == 'sudo' for call in calls)
        code['value'] = 1
        with pytest.raises(SystemExit) as raised:
            sbx.cmd_uninstall(state(), argparse.Namespace())
        assert raised.value.code == 1
        state_new = sbx.load_state()
        assert state_new['settings']['tun_name'] == 'axiom0'
    finally:
        sbx.configure_identity(False, {}, False)
    assert sbx.UNIT == 'sbx.service' and sbx.load_state()['settings']['tun_name'] == 'sbx0'
