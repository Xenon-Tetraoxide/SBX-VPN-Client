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
                    **({'app_profile': True, 'app_group': True, 'app_order': 0} if app else
                       {'manual_index': sum(1 for s in out if 'manual_index' in s)})})
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


def other_runtime(tmp_path, *, tun, mixed=2180, api=9197, axiom=True, unit=True):
    """Установленный юнит другой марки и конфиг, на который указывает его ExecStart."""
    config = tmp_path / 'other-config.json'
    inbounds = [{'type': 'mixed', 'listen_port': mixed}] + ([{'type': 'tun'}] if tun else [])
    config.write_text(json.dumps({'inbounds': inbounds,
                                  'experimental': {'clash_api': {'external_controller': f'127.0.0.1:{api}'}}}))
    name = 'axiom.service' if axiom else 'sbx.service'
    if unit:
        (tmp_path / name).write_text(f'[Service]\nExecStartPre=/usr/bin/sing-box check -c {config}\n'
                                     f'ExecStart=/usr/bin/sing-box run -c {config} -D /tmp/work\n')
    return config


def other_active(monkeypatch, tmp_path, active=True):
    monkeypatch.setattr(sbx, 'UNIT_DIR', tmp_path)
    monkeypatch.setattr(sbx, 'IS_WIN', False)
    monkeypatch.setattr(sbx, 'is_root', lambda: False)
    monkeypatch.setattr(sbx, 'systemctl', lambda *a, **k: types.SimpleNamespace(
        returncode=0, stdout='active\n' if active else 'inactive\n'))


@pytest.mark.parametrize('ours,theirs,force,refused', [
    ('tun', 'tun', False, True), ('tun', 'tun', True, False), ('tun', 'proxy', False, True),
    ('proxy', 'tun', False, True), ('proxy', 'proxy', False, False)])
def test_up_refuses_while_other_brand_is_active(monkeypatch, tmp_path, ours, theirs, force, refused):
    other_active(monkeypatch, tmp_path)
    other_runtime(tmp_path, tun=theirs == 'tun')   # мы — sbx, активна AxiOm со своими портами
    calls = []
    monkeypatch.setattr(sbx, 'foreign_tun', lambda: [])
    monkeypatch.setattr(sbx, 'prepare_service', lambda st: calls.append('prepare') or sbx.die('stop here', 9))
    st = state()
    st['settings']['mode'] = ours
    with pytest.raises(SystemExit) as raised:
        sbx.cmd_up(st, argparse.Namespace(force=force))
    assert (raised.value.code == 1) is refused and (calls == []) is refused


def test_guard_reads_installed_runtime_not_the_callers_state(monkeypatch, tmp_path):
    """SBX_HOME указывает на proxy-состояние, а работающая AxiOm — в TUN: берётся конфиг её юнита."""
    other_active(monkeypatch, tmp_path)
    other_runtime(tmp_path, tun=True)
    home = tmp_path / 'proxy-home'
    home.mkdir()
    (home / 'state.json').write_text(json.dumps({'settings': {'mode': 'proxy', 'mixed_port': 2180}}))
    monkeypatch.setenv('SBX_HOME', str(home))
    other = sbx.other_brand_active()
    assert other['tun'] is True
    st = state()
    st['settings']['mode'] = 'proxy'
    assert 'TUN' in sbx.brand_conflict(st, other)


@pytest.mark.parametrize('unit,broken', [(False, False), (True, True)])
def test_unreadable_runtime_is_a_conflict(monkeypatch, tmp_path, unit, broken):
    other_active(monkeypatch, tmp_path)
    config = other_runtime(tmp_path, tun=False, unit=unit)
    if broken:
        config.write_text('{not json')
    other = sbx.other_brand_active()
    assert other['tun'] is None
    st = state()
    st['settings']['mode'] = 'proxy'
    assert 'не прочитан' in sbx.brand_conflict(st, other)
    with pytest.raises(SystemExit):
        sbx.refuse_other_brand(st, False)
    sbx.refuse_other_brand(st, True)


@pytest.mark.parametrize('ours_mixed,ours_api,named,port', [
    (2180, 9097, 'mixed_port', '2180'), (2080, 9197, 'api_port', '9197'), (2080, 9097, None, None)])
def test_proxy_only_coexistence_checks_listener_ports(monkeypatch, tmp_path, ours_mixed, ours_api, named, port):
    other_active(monkeypatch, tmp_path)
    other_runtime(tmp_path, tun=False)   # AxiOm: mixed 2180, api 9197
    st = state()
    st['settings'].update(mode='proxy', mixed_port=ours_mixed, api_port=ours_api)
    reason = sbx.brand_conflict(st, sbx.other_brand_active())
    if named is None:
        assert reason is None
    else:
        assert named in reason and 'axiom' in reason and port in reason


def test_upgraded_axiom_state_with_sbx_ports_is_refused(monkeypatch, tmp_path):
    other_active(monkeypatch, tmp_path)
    other_runtime(tmp_path, tun=False, mixed=2080, api=9097)   # сохранённое состояние AxiOm со старыми портами
    st = state()
    st['settings']['mode'] = 'proxy'
    with pytest.raises(SystemExit):
        sbx.refuse_other_brand(st, False)


@pytest.mark.parametrize('command', ['restart', 'connect'])
def test_restart_and_connect_apply_the_brand_guard(monkeypatch, tmp_path, command):
    other_active(monkeypatch, tmp_path)
    other_runtime(tmp_path, tun=True)
    monkeypatch.setattr(sbx, 'prepare_service', lambda st: pytest.fail('служба не должна готовиться'))
    monkeypatch.setattr(sbx, 'cmd_use', lambda *a: pytest.fail('выбор не должен меняться'))
    with pytest.raises(SystemExit) as raised:
        getattr(sbx, f'cmd_{command}')(state(), argparse.Namespace(force=False, number=1))
    assert raised.value.code == 1


def test_other_brand_inactive_is_not_a_conflict(monkeypatch, tmp_path):
    other_active(monkeypatch, tmp_path, active=False)
    assert sbx.other_brand_active() is None


def test_windows_other_brand_uses_its_task_and_its_action(monkeypatch, tmp_path):
    monkeypatch.setattr(sbx, 'IS_WIN', True)
    config = other_runtime(tmp_path, tun=True, unit=False)
    xml = (f'<Task xmlns="{sbx.TASK_NS}"><Actions><Exec><Command>sing-box.exe</Command>'
           f'<Arguments>run -c "{config}" -D x</Arguments></Exec></Actions></Task>')
    seen = []
    monkeypatch.setattr(sbx, 'task_listed', lambda name: seen.append(name) or True)
    monkeypatch.setattr(sbx, 'task_state', lambda name=None: 'running')
    monkeypatch.setattr(sbx, 'task_definition', lambda name: sbx.ET.fromstring(xml))
    assert sbx.other_brand_active() == {'name': 'axiom', 'tun': True,
                                        'listeners': {'mixed_port': 2180, 'api_port': 9197}}
    assert seen == ['axiom']
    monkeypatch.setattr(sbx, 'task_state', lambda name=None: 'unknown')   # неясно — считаем активной
    assert sbx.other_brand_active()['name'] == 'axiom'
    monkeypatch.setattr(sbx, 'task_state', lambda name=None: 'stopped')
    assert sbx.other_brand_active() is None
    monkeypatch.setattr(sbx, 'task_listed', lambda name: False)
    assert sbx.other_brand_active() is None


# H4 leftovers: PyInstaller/Windows launch plumbing is covered in test_review_fixes


# M2: uninstall — подставлен только запуск процессов (sbx.run); task_call и разбор вывода настоящие

class Scheduler:
    """Поддельный schtasks/powershell: журнал вызовов и ответы на них."""

    def __init__(self, tasks, *, states=('Running',), listing=0, end=0, delete=0, blind_after=None):
        self.tasks = dict.fromkeys(tasks, True)
        self.states, self.listing, self.end, self.delete, self.blind_after = states, listing, end, delete, blind_after
        self.calls, self.polls = [], 0

    def __call__(self, cmd, check=True, **kw):
        cmd = list(cmd)
        self.calls.append(cmd)
        done = lambda code=0, out='', err='': subprocess.CompletedProcess(cmd, code, out, err)
        if cmd[0] == 'powershell':
            return done(1)
        action = cmd[1]
        name = cmd[cmd.index('/tn') + 1] if '/tn' in cmd else None
        if action == '/query' and name is None:   # перечень всех задач — как у настоящего schtasks
            if self.listing:
                return done(self.listing, '', 'Access denied')
            return done(0, ''.join(f'"\\{task}","N/A","Ready"\n' for task in [*self.tasks, 'Other']))
        if action == '/query' and '/xml' in cmd:
            return done(1) if name not in self.tasks else done(0, '<Task/>')
        if action == '/query':
            if name not in self.tasks or self.blind_after is not None and self.polls >= self.blind_after:
                return done(1, '', 'ERROR')
            state = self.states[min(self.polls, len(self.states) - 1)] if name == 'sbx' else 'Ready'
            self.polls += name == 'sbx'
            return done(0, f'"\\{name}","N/A","{state}"\n')
        if action == '/end':
            return done(self.end)
        if action == '/delete':
            if not self.delete:
                self.tasks.pop(name, None)
            return done(self.delete)
        raise AssertionError(cmd)

    def deleted(self):
        return [call[call.index('/tn') + 1] for call in self.calls if call[1:2] == ['/delete']]


def win_uninstall(monkeypatch, tasks=('sbx', 'sbx-update'), **kw):
    windows(monkeypatch)
    monkeypatch.setattr(sbx, 'windows_admin', lambda: True)
    monkeypatch.setattr(sbx.time, 'sleep', lambda s: None)
    scheduler = Scheduler(tasks, **kw)
    monkeypatch.setattr(sbx, 'run', scheduler)
    return scheduler


def test_windows_uninstall_stops_verifies_then_deletes(monkeypatch, capsys):
    scheduler = win_uninstall(monkeypatch, states=('Running', 'Running', 'Ready'))
    sbx.cmd_uninstall(state(), argparse.Namespace())
    assert scheduler.deleted() == ['sbx', 'sbx-update']
    ends = [i for i, call in enumerate(scheduler.calls) if call[1:2] == ['/end']]
    first_delete = next(i for i, call in enumerate(scheduler.calls) if call[1:2] == ['/delete'])
    assert len(ends) == 1 and ends[0] < first_delete
    assert 'удалены' in capsys.readouterr().out


def test_windows_uninstall_cleans_updater_only_install_and_second_run(monkeypatch, capsys):
    scheduler = win_uninstall(monkeypatch, tasks=('sbx-update',))   # основной задачи уже нет
    sbx.cmd_uninstall(state(), argparse.Namespace())
    assert scheduler.deleted() == ['sbx-update']
    sbx.cmd_uninstall(state(), argparse.Namespace())   # повторный запуск — не ошибка
    assert scheduler.deleted() == ['sbx-update'] and 'удалены' in capsys.readouterr().out
    assert any(call[:2] == ['schtasks', '/query'] and '/tn' not in call for call in scheduler.calls)


def test_windows_uninstall_state_lost_after_end_keeps_the_task(monkeypatch, capsys):
    scheduler = win_uninstall(monkeypatch, blind_after=1)   # первый опрос — Running, дальше запрос не удаётся
    with pytest.raises(SystemExit) as raised:
        sbx.cmd_uninstall(state(), argparse.Namespace())
    assert raised.value.code == 1 and 'sbx' not in scheduler.deleted()
    assert 'не подтверждена' in capsys.readouterr().err


def test_windows_uninstall_unknown_state_keeps_the_task(monkeypatch, capsys):
    scheduler = win_uninstall(monkeypatch, blind_after=0)   # состояние не удалось узнать с самого начала
    with pytest.raises(SystemExit) as raised:
        sbx.cmd_uninstall(state(), argparse.Namespace())
    assert raised.value.code == 1 and 'sbx' not in scheduler.deleted()
    assert not any(call[1:2] == ['/end'] for call in scheduler.calls)
    assert 'неизвестно' in capsys.readouterr().err


@pytest.mark.parametrize('kwargs,expected', [
    ({'listing': 5}, 'Access denied'),
    ({'end': 1}, 'остановка задачи sbx'),
    ({'states': ('Running',)}, 'не остановилась'),
    ({'states': ('Running', 'Ready'), 'delete': 1}, 'удаление задачи sbx')])
def test_windows_uninstall_failures_are_fatal_and_never_delete_a_live_task(monkeypatch, capsys, kwargs, expected):
    scheduler = win_uninstall(monkeypatch, **kwargs)
    with pytest.raises(SystemExit) as raised:
        sbx.cmd_uninstall(state(), argparse.Namespace())
    assert raised.value.code == 1 and expected in capsys.readouterr().err
    assert ('sbx' in scheduler.deleted()) is (kwargs.get('delete') == 1)


def test_task_state_is_tri_state(monkeypatch):
    def answer(code, out, power=''):
        def run(cmd, check=True, **kw):
            if cmd[0] == 'powershell':
                return subprocess.CompletedProcess(cmd, 0 if power else 1, power, '')
            return subprocess.CompletedProcess(cmd, code, out, '')
        monkeypatch.setattr(sbx, 'run', run)
        return sbx.task_state('sbx')

    assert answer(0, '"\\sbx","N/A","Running"\n') == 'running'
    assert answer(0, '"\\sbx","N/A","Ready"\n') == 'stopped'
    assert answer(1, '') == 'unknown' and sbx.task_running('sbx') is False
    assert answer(0, '"\\sbx","N/A","Работает"\n', '4') == 'running'
    assert answer(0, '"\\sbx","N/A","Готово"\n', '3') == 'stopped'
    assert answer(0, '"\\sbx","N/A","Работает"\n', '') == 'unknown'


def test_task_listed_distinguishes_missing_from_query_failure(monkeypatch):
    out = {'text': '"\\sbx","N/A","Ready"\n\n"\\Microsoft\\x","N/A","Ready"\n', 'code': 0}
    monkeypatch.setattr(sbx, 'run', lambda cmd, check=True, **kw: subprocess.CompletedProcess(
        cmd, out['code'], out['text'], 'Access denied'))
    assert sbx.task_listed('sbx') is True and sbx.task_listed('axiom') is False
    out['code'] = 5
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


# Third round: identity of rm, cache rank, updater action, hidden exact names

def test_rm_by_number_deletes_the_numbered_manual_entry_not_a_namesake(monkeypatch):
    sub_entry = {'tag': MINE, 'source': 'subscription', 'outbound': outbound(MINE)}
    first = {'name': MINE, 'outbound': outbound(MINE)}
    second = {'name': MINE, 'outbound': {**outbound(MINE), 'server': 'second.example'}}
    st = state()
    st['manual'] = [first, second]
    tags = [sub_entry, {'tag': MINE + ' [manual]', 'source': 'manual', 'outbound': first['outbound'], 'manual_index': 0},
            {'tag': MINE + ' [manual] #2', 'source': 'manual', 'outbound': second['outbound'], 'manual_index': 1}]
    monkeypatch.setattr(sbx, 'all_servers', lambda _: tags)
    monkeypatch.setattr(sbx, 'apply', lambda *a, **k: None)
    monkeypatch.setattr(sbx, 'save_state', lambda st: None)
    with pytest.raises(SystemExit):   # №1 — запись подписки: удалять нечего, ручные нетронуты
        sbx.cmd_rm(st, argparse.Namespace(server='1'))
    assert st['manual'] == [first, second]
    sbx.cmd_rm(st, argparse.Namespace(server='3'))   # №3 — именно второй ручной
    assert st['manual'] == [first]


def test_rm_with_real_all_servers_uses_manual_index():
    st = state()
    st['manual'] = [{'name': 'Dup', 'outbound': outbound('Dup')}, {'name': 'Dup', 'outbound': outbound('Dup')}]
    servers = sbx.all_servers(st)
    assert [s['manual_index'] for s in servers] == [0, 1] and servers[0]['tag'] != servers[1]['tag']


def test_cache_reload_keeps_effective_rank_of_repeated_selector_members(monkeypatch, app_directory):
    row, path, document = app_with_profile(app_directory, NETHERLANDS, FRANCE, selector=[NETHERLANDS, FRANCE, NETHERLANDS])
    app = sbx.load_axiom_context()
    st = state()
    st['_axiom'] = app
    uncached = [(s['tag'], s['app_order']) for s in sbx.all_servers(st)]
    monkeypatch.setattr(sbx.urllib.request, 'urlopen', lambda request, **kw: response(
        document, subscription_userinfo='upload=1; download=2; total=3'))
    sbx.update_app_profiles(app, app['profiles'], quiet=True)
    assert sbx.read_app_cache(app, app['profiles'][0])
    cached = [(s['tag'], s['app_order']) for s in sbx.all_servers(st)]
    key = lambda pairs: [tag for tag, _ in sorted(pairs, key=lambda item: item[1])]
    assert key(uncached) == key(cached) == [FRANCE, NETHERLANDS]   # последний индекс повтора решает
    options = lambda: [tag for _, tag in sbx.axiom_options(sbx.all_servers(st))]
    assert options()[0] == FRANCE


def test_windows_updater_is_reregistered_when_action_differs(monkeypatch, tmp_path):
    windows(monkeypatch)
    monkeypatch.setattr(sbx, 'launch_command', lambda argv: ['python.exe', 'sbx.py', *argv])
    monkeypatch.setenv('SBX_HOME', str(tmp_path / 'h'))
    registered, changes, state_of = [], [], {'enabled': 'enabled'}
    monkeypatch.setattr(sbx, 'register_task', lambda name, xml, **k: registered.append(name))
    monkeypatch.setattr(sbx, 'task_call', lambda action, name=None, *a, **k: changes.append((action, name, a)))
    monkeypatch.setattr(sbx, 'task_enabled', lambda name: state_of['enabled'])
    command = sbx.updater_command()
    task = lambda cmd, args: sbx.ET.fromstring(
        f'<Task xmlns="{sbx.TASK_NS}"><Actions><Exec><Command>{cmd}</Command><Arguments>{args}</Arguments>'
        f'</Exec></Actions></Task>')
    current = task(command[0], sbx.subprocess.list2cmdline(command[1:]))
    monkeypatch.setattr(sbx, 'task_definition', lambda name: current)
    sbx.update_windows_updater()
    assert registered == []                                    # то же действие — не трогаем
    current = task('python.exe', 'sbx.py update -q')           # прежняя версия без путей
    sbx.update_windows_updater()
    assert registered == [sbx.UPDATE] and changes == []
    state_of['enabled'] = 'disabled'                           # выключенную пользователем — не включаем
    sbx.update_windows_updater()
    assert registered == [sbx.UPDATE] * 2 and changes == [('change', sbx.UPDATE, ('/disable',))]
    monkeypatch.setattr(sbx, 'task_definition', lambda name: None)
    sbx.update_windows_updater()
    assert len(registered) == 3


def test_rule_via_exact_name_reaches_hidden_app_outbound_but_numbers_follow_the_menu(monkeypatch):
    hidden = 'Hidden outbound'
    servers = servers_of((FRANCE, True), (NETHERLANDS, True), (MINE, False))
    servers.append({'tag': hidden, 'source': 'app:App', 'outbound': outbound(hidden),
                    'app_profile': True, 'app_group': False, 'app_order': 0})
    st = axiom_state(monkeypatch, servers)
    numbered = [s['tag'] for s in sbx.numbered_servers(st, servers)]
    assert hidden not in numbered
    assert sbx.parse_via_target(st, hidden) == hidden          # точное имя — по полному списку
    assert sbx.parse_via_target(st, '1') == numbered[0]        # номер — по порядку меню
    with pytest.raises(SystemExit):
        sbx.resolve(st, hidden)                                 # use/rm по-прежнему только из меню
    with pytest.raises(SystemExit):
        sbx.parse_via_target(st, 'Hidden')                      # часть имени скрытого — нет


def test_elevated_interactive_flag_needs_elevation_and_is_recorded(monkeypatch):
    windows(monkeypatch)
    monkeypatch.setattr(sbx, 'windows_admin', lambda: True)
    assert sbx.take_elevated_prefix(['--elevated-for', 'S-1-5-21-1', '--elevated-interactive', '1', 'up'])[0] is True
    assert sbx.PARENT_INTERACTIVE is True
    sbx.take_elevated_prefix(['--elevated-for', 'S-1-5-21-1', '--elevated-interactive', '0', 'up'])
    assert sbx.PARENT_INTERACTIVE is False
    with pytest.raises(SystemExit):
        sbx.take_elevated_prefix(['--elevated-interactive', '1', 'up'])


# Fourth round

def test_rm_keeps_selection_on_the_same_record_among_duplicate_names(monkeypatch):
    st = state()
    st['manual'] = [{'name': 'Dup', 'outbound': {**outbound('Dup'), 'server': f'h{i}.example'}} for i in range(3)]
    tags = [s['tag'] for s in sbx.all_servers(st)]
    st['selected'] = tags[1]                      # второй
    chosen_outbound = st['manual'][1]['outbound']
    monkeypatch.setattr(sbx, 'apply', lambda *a, **k: None)
    monkeypatch.setattr(sbx, 'save_state', lambda s: None)
    sbx.cmd_rm(st, argparse.Namespace(server='1'))   # удаляем первый
    servers = sbx.all_servers(st)
    selected = next(s for s in servers if s['tag'] == st['selected'])
    assert selected['outbound'] is chosen_outbound   # выбор остался на той же записи
    sbx.cmd_rm(st, argparse.Namespace(server=str(1 + [s['tag'] for s in servers].index(st['selected']))))
    assert st['selected'] == 'auto'                   # удалили выбранный


def test_old_cache_without_version_is_invalid(monkeypatch, app_directory):
    row, path, document = app_with_profile(app_directory, NETHERLANDS)
    monkeypatch.setattr(sbx.urllib.request, 'urlopen', lambda request, **kw: response(
        document, subscription_userinfo='upload=1; download=2; total=3'))
    app = sbx.load_axiom_context()
    sbx.update_app_profiles(app, app['profiles'], quiet=True)
    file = sbx.app_cache_file(app, row['id'])
    assert sbx.read_app_cache(app, app['profiles'][0])
    cache = json.loads(file.read_text())
    del cache['version']
    file.write_text(json.dumps(cache))
    assert sbx.read_app_cache(app, app['profiles'][0]) is None
    cache['version'] = sbx.APP_CACHE_VERSION - 1
    file.write_text(json.dumps(cache))
    assert sbx.read_app_cache(app, app['profiles'][0]) is None


@pytest.mark.parametrize('windows_host', [False, True])
def test_install_restarts_a_running_service_and_respects_the_guard(monkeypatch, windows_host):
    monkeypatch.setattr(sbx, 'IS_WIN', windows_host)
    monkeypatch.setattr(sbx, 'windows_admin', lambda: True)
    monkeypatch.setattr(sbx, 'is_active', lambda st: True)
    monkeypatch.setattr(sbx, 'task_running', lambda name=None: True)
    monkeypatch.setattr(sbx, 'other_brand_active', lambda: None)
    events = []
    monkeypatch.setattr(sbx, 'prepare_service', lambda st: events.append('prepare'))
    monkeypatch.setattr(sbx, 'service_action', lambda action: events.append(action))
    sbx.cmd_install(state(), argparse.Namespace(force=False))
    assert events == ['prepare', 'restart']
    monkeypatch.setattr(sbx, 'is_active', lambda st: False)
    monkeypatch.setattr(sbx, 'task_running', lambda name=None: False)
    events.clear()
    sbx.cmd_install(state(), argparse.Namespace(force=False))
    assert events == ['prepare']                      # остановленную службу не запускаем
    monkeypatch.setattr(sbx, 'is_active', lambda st: True)
    monkeypatch.setattr(sbx, 'task_running', lambda name=None: True)
    monkeypatch.setattr(sbx, 'other_brand_active', lambda: {'name': 'axiom', 'tun': True, 'listeners': {}})
    events.clear()
    with pytest.raises(SystemExit):
        sbx.cmd_install(state(), argparse.Namespace(force=False))
    assert events == []
