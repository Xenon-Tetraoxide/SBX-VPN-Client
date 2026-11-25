"""Выбранный сервер переживает обновления подписки: переименование, изменение, удаление."""
import argparse
import json

import pytest

import sbx

USA_DEV = '🇺🇸 USA dev (user) [ws]'
USA = '🇺🇸 USA (user) [ws]'
GERMANY_TCP = 'Germany (user) [tcp]'
GERMANY_WS = 'Germany (user) [ws]'
GERMANY_HY2 = 'Germany (user) [hy2]'
FRANCE_WS = 'France (user) [ws]'


def node(host, *, uuid='00000000-0000-4000-8000-000000000001', path='/ws', port=443, kind='vless'):
    outbound = {'type': kind, 'server': host, 'server_port': port,
                'tls': {'enabled': True, 'server_name': host}}
    if kind == 'vless':
        outbound.update(uuid=uuid, transport={'type': 'ws', 'path': path, 'headers': {'Host': host}})
    else:
        outbound['password'] = uuid
    return outbound


def write_sub(name, servers):
    sbx.write_private(sbx.sub_file(name), json.dumps(
        {'servers': [{'name': tag, 'outbound': outbound} for tag, outbound in servers], 'meta': {}}))


@pytest.fixture
def st(monkeypatch):
    state = json.loads(json.dumps(sbx.DEFAULT_STATE))
    state['settings'].update(api_secret='secret', route='global')
    state['subs'] = [{'name': 'main', 'url': 'https://example.invalid/sub'}]
    monkeypatch.setattr(sbx, 'check_config', lambda path: (True, ''))
    monkeypatch.setattr(sbx, 'is_active', lambda _: False)
    return state


def choose(state, tag):
    """Как `sbx use`: выбор, отпечаток и конфиг на диске."""
    state['selected'] = tag
    sbx.remember_choice(state, tag, sbx.all_servers(state))
    sbx.save_state(state)
    sbx.apply(state)


def default_outbound():
    config = json.loads(sbx.CONFIG_FILE.read_text(encoding='utf-8'))
    return next(o['default'] for o in config['outbounds'] if o['tag'] == 'proxy')


def saved():
    return json.loads(sbx.STATE_FILE.read_text(encoding='utf-8'))


def test_renamed_server_with_same_node_keeps_the_choice(st, capsys):
    """Случай 24.11.2026: панель переименовала «USA dev» в «USA», сам узел тот же."""
    write_sub('main', [(USA_DEV, node('us.example')), (GERMANY_WS, node('de.example'))])
    choose(st, USA_DEV)
    write_sub('main', [(USA, node('us.example')), (GERMANY_WS, node('de.example'))])
    capsys.readouterr()
    sbx.apply(st)
    assert st['selected'] == USA and default_outbound() == USA
    assert saved()['selected'] == USA and saved()['selected_ref']['tag'] == USA
    assert saved()['selection_note']['kind'] == 'renamed'
    err = capsys.readouterr().err
    assert USA_DEV in err and USA in err


def test_renamed_server_with_rotated_keys_is_found_by_address(st):
    write_sub('main', [(USA_DEV, node('us.example')), (GERMANY_WS, node('de.example'))])
    choose(st, USA_DEV)
    write_sub('main', [(USA, node('us.example', uuid='00000000-0000-4000-8000-0000000000ff')),
                       (GERMANY_WS, node('de.example'))])
    sbx.apply(st)
    assert default_outbound() == USA and saved()['selected'] == USA_DEV   # похоже, но не тот же узел — на время


def test_shared_address_is_not_followed_blindly(st, capsys):
    """За одним адресом CDN несколько стран: без однозначного совпадения и без той же страны — auto."""
    write_sub('main', [(USA_DEV, node('cdn.example', path='/us')), (GERMANY_WS, node('cdn.example', path='/de'))])
    choose(st, USA_DEV)
    write_sub('main', [('Italy (user) [ws]', node('cdn.example', path='/it')),
                       (GERMANY_WS, node('cdn.example', path='/de'))])
    capsys.readouterr()
    sbx.apply(st)
    assert default_outbound() == 'auto'
    assert saved()['selected'] == USA_DEV                    # выбор не перезаписан: он вернётся
    assert saved()['selection_note'] == {**saved()['selection_note'], 'kind': 'lost', 'from': USA_DEV, 'to': 'auto'}
    assert 'auto' in capsys.readouterr().err


def test_two_servers_at_the_old_address_are_a_tie_not_a_guess(st):
    """Прежние адрес и имя хоста теперь у двух серверов с другими ключами: какой из них прежний — неизвестно."""
    write_sub('main', [(USA_DEV, node('us.example')), (GERMANY_WS, node('de.example'))])
    choose(st, USA_DEV)
    write_sub('main', [('Canada (user) [ws]', node('us.example', uuid='00000000-0000-4000-8000-0000000000bb')),
                       ('Mexico (user) [ws]', node('us.example', uuid='00000000-0000-4000-8000-0000000000cc')),
                       (GERMANY_WS, node('de.example'))])
    sbx.apply(st)
    assert default_outbound() == 'auto' and saved()['selection_note']['kind'] == 'lost'


@pytest.mark.parametrize('new_name', ['🇺🇸 United States (other) [ws]', 'USA (other) [ws]', 'США (other) [ws]',
                                      '🇺🇸 USA (user) [ws]'])
def test_country_is_found_by_flag_or_name_not_by_exact_string(st, new_name):
    """«🇺🇸 USA dev» пропал, вместо него другой узел «США»/«United States»: страна та же — он и используется."""
    write_sub('main', [(USA_DEV, node('us.example')), (GERMANY_WS, node('de.example'))])
    choose(st, USA_DEV)
    write_sub('main', [(new_name, node('us2.example', uuid='00000000-0000-4000-8000-0000000000aa')),
                       (GERMANY_WS, node('de.example'))])
    sbx.apply(st)
    assert default_outbound() == new_name
    assert saved()['selected'] == USA_DEV and saved()['selection_note']['kind'] == 'changed'


def test_country_names_and_flags():
    for name in ('🇺🇸 USA dev', 'USA', 'United States', 'США', 'usa-dev'):
        assert sbx.country_code(name) == 'US', name
    assert sbx.country_code('🇩🇪Германия [Билайн]') == 'DE'
    assert sbx.country_code('Germany #2') == 'DE'
    assert sbx.country_code('South Korea') == 'KR'
    assert sbx.country_code('🔁 Запасной') is None


def test_removed_transport_is_replaced_inside_the_country_and_comes_back(st, capsys):
    """Как в приложении AxiOm: транспорта не стало — тот же протокол той же страны, первый транспорт.
    В отличие от приложения 4.x — только на время: вернулся транспорт — вернулся и выбор."""
    full = [(GERMANY_WS, node('de-ws.example')), (GERMANY_TCP, node('de-tcp.example', path='/tcp')),
            (GERMANY_HY2, node('de-hy.example', kind='hysteria2')), (FRANCE_WS, node('fr.example'))]
    write_sub('main', full)
    choose(st, GERMANY_WS)
    write_sub('main', full[1:])
    capsys.readouterr()
    sbx.apply(st)
    assert default_outbound() == GERMANY_TCP and saved()['selected'] == GERMANY_WS
    assert saved()['selection_note']['kind'] == 'changed'
    assert GERMANY_TCP in capsys.readouterr().err
    write_sub('main', full)
    sbx.apply(st)
    assert default_outbound() == GERMANY_WS and 'selection_note' not in saved()
    assert 'снова в подписке' in capsys.readouterr().err


def test_removed_protocol_falls_back_to_the_first_protocol_of_the_country(st):
    write_sub('main', [(GERMANY_HY2, node('de-hy.example', kind='hysteria2')),
                       (GERMANY_TCP, node('de-tcp.example', path='/tcp')), (FRANCE_WS, node('fr.example'))])
    choose(st, GERMANY_HY2)
    write_sub('main', [(GERMANY_TCP, node('de-tcp.example', path='/tcp')), (FRANCE_WS, node('fr.example'))])
    sbx.apply(st)
    assert default_outbound() == GERMANY_TCP


def test_removed_country_is_auto_until_it_comes_back(st, capsys, monkeypatch):
    write_sub('main', [(GERMANY_WS, node('de.example')), (FRANCE_WS, node('fr.example'))])
    choose(st, GERMANY_WS)
    write_sub('main', [(FRANCE_WS, node('fr.example'))])
    capsys.readouterr()
    sbx.apply(st)
    assert default_outbound() == 'auto' and saved()['selected'] == GERMANY_WS
    assert GERMANY_WS in capsys.readouterr().err
    sbx.apply(st)                                   # повторная сборка не шумит и ничего не меняет
    assert 'выбор сервера' not in capsys.readouterr().err
    monkeypatch.setattr(sbx, 'IS_WIN', False, raising=False)
    monkeypatch.setattr(sbx, 'unit_prop', lambda prop: '')
    monkeypatch.setattr(sbx, 'unit_prop_of', lambda unit, prop: '')
    monkeypatch.setattr(sbx, 'app_vpn_on', lambda *args, **kwargs: None)
    sbx.show_status(st)
    out = capsys.readouterr().out
    assert f'выбран:      {GERMANY_WS}' in out and 'пока auto' in out and 'внимание:' in out
    write_sub('main', [(GERMANY_WS, node('de.example')), (FRANCE_WS, node('fr.example'))])
    sbx.apply(st)
    assert default_outbound() == GERMANY_WS and 'selection_note' not in saved()


def test_state_from_1_4_0_finds_a_renamed_country_by_flag(st, capsys):
    """Состояние старой версии без отпечатка, ровно случай 24.11.2026: «🇺🇸 USA dev» -> «🇺🇸 USA»."""
    write_sub('main', [(USA, node('us.example')), (GERMANY_WS, node('de.example'))])
    st['selected'] = USA_DEV
    sbx.save_state(st)
    sbx.apply(st)
    assert default_outbound() == USA and saved()['selection_note']['to'] == USA
    assert USA_DEV in capsys.readouterr().err


def test_state_from_1_4_0_gets_a_fingerprint_while_the_server_is_still_there(st, capsys):
    write_sub('main', [(USA_DEV, node('us.example')), (GERMANY_WS, node('de.example'))])
    st['selected'] = USA_DEV
    sbx.save_state(st)
    sbx.apply(st)
    assert saved()['selected'] == USA_DEV and saved()['selected_ref']['tag'] == USA_DEV
    assert 'selection_note' not in saved() and 'выбор сервера' not in capsys.readouterr().err
    write_sub('main', [(USA, node('us.example')), (GERMANY_WS, node('de.example'))])
    sbx.apply(st)
    assert saved()['selected'] == USA and saved()['selection_note']['kind'] == 'renamed'


def test_same_name_wins_over_the_fingerprint(st, capsys):
    """Имя на месте, а узел под ним другой: остаётся имя (как в приложении), отпечаток обновляется."""
    write_sub('main', [(GERMANY_WS, node('de.example')), (FRANCE_WS, node('fr.example'))])
    choose(st, GERMANY_WS)
    before = saved()['selected_ref']
    write_sub('main', [(GERMANY_WS, node('de-new.example')), ('Old (user) [ws]', node('de.example')),
                       (FRANCE_WS, node('fr.example'))])
    capsys.readouterr()
    sbx.apply(st)
    assert saved()['selected'] == GERMANY_WS and saved()['selected_ref'] != before
    assert 'selection_note' not in saved() and 'выбор сервера' not in capsys.readouterr().err


def test_fingerprint_holds_no_addresses_or_keys(st):
    write_sub('main', [(USA_DEV, node('us.example'))])
    choose(st, USA_DEV)
    text = json.dumps(saved()['selected_ref'])
    assert 'us.example' not in text and '00000000-0000-4000-8000-000000000001' not in text


def test_use_clears_the_note_and_auto_drops_the_fingerprint(st, monkeypatch):
    write_sub('main', [(GERMANY_WS, node('de.example')), (FRANCE_WS, node('fr.example'))])
    choose(st, GERMANY_WS)
    write_sub('main', [(FRANCE_WS, node('fr.example'))])
    sbx.apply(st)
    assert 'selection_note' in saved()
    sbx.cmd_use(st, argparse.Namespace(server=FRANCE_WS))
    assert saved()['selected'] == FRANCE_WS and 'selection_note' not in saved()
    assert saved()['selected_ref']['tag'] == FRANCE_WS
    sbx.cmd_use(st, argparse.Namespace(server='auto'))
    assert saved()['selected'] == 'auto' and 'selected_ref' not in saved()


def test_unsaved_settings_are_not_written_together_with_the_choice(st):
    """set/rule сохраняют настройки только после проверки конфига: сверка выбора не должна их опередить."""
    write_sub('main', [(USA_DEV, node('us.example')), (GERMANY_WS, node('de.example'))])
    choose(st, USA_DEV)
    write_sub('main', [(USA, node('us.example')), (GERMANY_WS, node('de.example'))])
    st['settings']['proxy_domains'] = ['pending.example']
    sbx.apply(st)
    assert saved()['selected'] == USA and saved()['settings']['proxy_domains'] == []


def test_update_command_carries_the_choice_over_a_rename(st, monkeypatch):
    write_sub('main', [(USA_DEV, node('us.example')), (GERMANY_WS, node('de.example'))])
    choose(st, USA_DEV)

    def refreshed(state, names=None, quiet=False):
        write_sub('main', [(USA, node('us.example')), (GERMANY_WS, node('de.example'))])
        return True

    monkeypatch.setattr(sbx, 'update_subs', refreshed)
    sbx.cmd_update(st, argparse.Namespace(names=[], quiet=True))
    assert saved()['selected'] == USA and default_outbound() == USA


def test_own_server_over_the_app_choice_follows_a_rename_and_never_touches_app_settings(st, monkeypatch):
    """Режим AxiOm с базой приложения: выбор по странам ведёт приложение, CLI чинит только «свой сервер»."""
    app_server = {'tag': FRANCE_WS, 'source': 'app:App', 'outbound': node('fr.example'),
                  'app_profile': True, 'app_group': True, 'app_order': 0}
    own = lambda tag: {'tag': tag, 'source': 'main', 'outbound': node('mine.example')}   # noqa: E731
    servers = [app_server, own('Mine')]
    prefs = {'flutter.server_selector_country': 'France', 'flutter.server_selector_protocol': 'vless',
             'flutter.server_selector_transport': 'ws'}
    st['_axiom'] = {'root': 'present', 'profiles': [], 'prefs': dict(prefs), 'prefix': 'flutter.', 'version': None}
    monkeypatch.setattr(sbx, 'axiom_write_selection', lambda *a, **k: pytest.fail('настройки приложения изменены'))
    st['selected'] = 'Mine'
    st['axiom_extra'] = {'tag': 'Mine', 'prefs': sbx.axiom_prefs_now(st['_axiom'])}
    assert sbx.reconcile_selection(st, servers) and st['axiom_extra']['ref']['tag'] == 'Mine'
    assert not sbx.reconcile_selection(st, servers)

    renamed = [app_server, own('Mine 2')]
    assert sbx.reconcile_selection(st, renamed)
    assert st['axiom_extra']['tag'] == 'Mine 2' and sbx.selected_server(st, renamed) == 'Mine 2'

    assert sbx.reconcile_selection(st, [app_server])              # свой сервер пропал — пока выбор приложения
    assert st['axiom_extra']['tag'] == 'Mine 2' and st['selection_note']['kind'] == 'extra'
    assert sbx.selected_server(st, [app_server]) == FRANCE_WS
    assert sbx.reconcile_selection(st, renamed)                   # вернулся — вернулся и выбор
    assert sbx.selected_server(st, renamed) == 'Mine 2' and 'selection_note' not in st
    assert st['_axiom']['prefs'] == prefs


def test_app_country_is_found_by_code_and_comes_back():
    """Режим AxiOm: страна в настройках приложения — «🇺🇸 USA dev», в меню только «🇺🇸 USA»: это она же."""
    usa = {'tag': USA, 'source': 'app:App', 'outbound': node('us.example'),
           'app_profile': True, 'app_group': True, 'app_order': 0}
    germany = {**usa, 'tag': GERMANY_WS, 'outbound': node('de.example')}
    app = {'root': 'present', 'prefix': 'flutter.', 'prefs': {
        'flutter.server_selector_country': '🇺🇸 USA dev', 'flutter.server_selector_protocol': 'vless',
        'flutter.server_selector_transport': 'ws'}}
    assert sbx.axiom_chosen(app, sbx.axiom_options([usa, germany])) == USA
    assert sbx.axiom_chosen(app, sbx.axiom_options([germany])) == 'auto'
    back = {**usa, 'tag': USA_DEV}
    assert sbx.axiom_chosen(app, sbx.axiom_options([usa, back, germany])) == USA_DEV   # точное имя важнее


def test_status_json_is_unchanged_by_the_note(st, monkeypatch):
    write_sub('main', [(GERMANY_WS, node('de.example')), (FRANCE_WS, node('fr.example'))])
    choose(st, GERMANY_WS)
    write_sub('main', [(FRANCE_WS, node('fr.example'))])
    sbx.apply(st)
    monkeypatch.setattr(sbx, 'sync_dir', lambda: None)
    assert set(sbx.status_info(st)) == {'vpn', 'engine', 'selection', 'server', 'version'}
