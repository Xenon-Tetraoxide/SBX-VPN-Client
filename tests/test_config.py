import json
from pathlib import Path

import sbx


def fixture_config(monkeypatch):
    state = json.loads(json.dumps(sbx.DEFAULT_STATE))
    state['settings'].update(
        api_secret='fixture-secret',
        direct_domains=['local.example'],
        proxy_domains=['proxy.example'],
        via_rules=[{'to': 're:^Germany', 'items': ['video.example']}],
        auto_exclude='France',
    )
    state['selected'] = 'Germany (Arco) [tcp]'
    monkeypatch.setattr(sbx, 'RULESET_DIR', Path('sbx-nonexistent-fixture-rulesets'))
    servers = [
        {'tag': 'Germany (Arco) [tcp]', 'outbound': {
            'type': 'vless', 'server': 'de.example', 'server_port': 443,
            'uuid': '00000000-0000-4000-8000-000000000001',
        }},
        {'tag': 'France (Arco) [hy2]', 'outbound': {
            'type': 'hysteria2', 'server': 'fr.example', 'server_port': 443,
            'password': 'fixture', 'tls': {'enabled': True, 'server_name': 'fr.example'},
        }},
    ]
    return sbx.build_config(state, servers)


def test_linux_config_golden(monkeypatch):
    monkeypatch.setattr(sbx, 'IS_WIN', False, raising=False)
    expected = (Path(__file__).parent / 'fixtures/linux-v1.2.0.json').read_text(encoding='utf-8')
    output = json.dumps(fixture_config(monkeypatch), ensure_ascii=False, indent=2)
    assert (output + '\n').encode('utf-8') == expected.encode('utf-8')
