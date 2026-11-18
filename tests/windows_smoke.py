import json
import os
import subprocess
import sys
from pathlib import Path

import sbx


def main():
    state = sbx.load_state()
    state['settings']['route'] = 'global'
    state['_axiom'] = {'root': None}
    document = (Path(__file__).parent / 'fixtures/axiom-smoke.json').read_text(encoding='utf-8')
    items, errors, _ = sbx.parse_subscription(document)
    assert not errors
    servers = [{'tag': name, 'outbound': outbound, 'source': 'fixture'} for name, outbound in items]
    results = [key for key, _ in sbx.axiom_sorted(sbx.axiom_options(servers))]
    assert results == [('France', 'hysteria2', 'hy2'), ('Netherlands', 'vless', 'ws')], results
    print(f'Классификация AxiOm: {results}', flush=True)
    sbx.WORK_DIR.mkdir(parents=True, exist_ok=True)
    for tun in (True, False):
        config = sbx.build_config(state, servers, tun=tun)
        path = sbx.WORK_DIR / ('tun.json' if tun else 'proxy.json')
        sbx.write_private(path, json.dumps(config, ensure_ascii=False, indent=2))
        subprocess.run([sbx.core_path(), 'check', '-c', str(path)], check=True)
        print(f'sing-box check: {path.name} OK', flush=True)
    sbx.write_private(sbx.SUBS_DIR / 'smoke.json', json.dumps({'servers': [
        {'name': name, 'outbound': outbound} for name, outbound in items], 'meta': {}}))
    state['subs'] = [{'name': 'smoke', 'url': 'https://example.test/sub'}]
    sbx.save_state(state)
    cli_env = {**os.environ, 'SBX_BRAND': 'axiom', 'XDG_DATA_HOME': str(sbx.WORK_DIR)}
    result = subprocess.run([sys.executable, 'sbx.py', 'ls'], env=cli_env, check=True,
                            capture_output=True, encoding='utf-8')
    out = result.stdout
    assert 'France' in out and 'WebSocket' in out, out
    # [reality] нет в классификации приложения: такой сервер виден только среди своих
    assert 'Свои серверы' in out and out.index('Germany') > out.index('Свои серверы'), out
    print(result.stdout, end='')


if __name__ == '__main__':
    main()
