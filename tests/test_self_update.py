import argparse
import io
import json

import pytest

import sbx


def test_release_versions(monkeypatch):
    monkeypatch.setenv('SBX_RELEASES_URL', 'https://releases.example.test/latest')
    monkeypatch.setattr(sbx, '__version__', '1.9.0')
    assert sbx.version_key('v1.10.0') > sbx.version_key('1.9.0')
    assert sbx.version_key('v1.10.0') > sbx.version_key('v1.10.0-rc.10') > sbx.version_key('v1.10.0-rc.2')
    assert sbx.version_key('1.9.0+build') == sbx.version_key('1.9.0')

    def urlopen(request, **kwargs):
        assert request.full_url == 'https://releases.example.test/latest'
        return io.BytesIO(json.dumps({'tag_name': tag}).encode())

    monkeypatch.setattr(sbx.urllib.request, 'urlopen', urlopen)
    tag = 'v1.9.0'
    assert sbx.latest_update() is None
    tag = 'v1.10.0'
    assert sbx.latest_update()['tag_name'] == tag


def test_notice_throttle_and_quiet(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sbx, 'CONF_DIR', tmp_path)
    monkeypatch.setattr(sbx, 'STATE_FILE', tmp_path / 'state.json')
    monkeypatch.setattr(sbx, 'interactive', lambda: True)
    monkeypatch.setattr(sbx.time, 'time', lambda: now)
    monkeypatch.delenv('SBX_NO_UPDATE_CHECK', raising=False)
    monkeypatch.delenv('INVOCATION_ID', raising=False)
    monkeypatch.setattr('builtins.input', lambda message: print(message) or 'n')
    checks = []
    monkeypatch.setattr(sbx, 'latest_update', lambda: checks.append(now) or {'tag_name': 'v9.0.0'})
    args = argparse.Namespace(cmd='rule', quiet=False)
    now = 900_000
    stale = sbx.load_state()
    sbx.maybe_notice_update(sbx.load_state(), args)
    assert 'Доступна новая версия sbx 9.0.0' in capsys.readouterr().out
    assert sbx.load_state()['last_update_check'] == now
    sbx.maybe_notice_update(stale, args)
    assert stale['last_update_check'] == now
    now += sbx.UPDATE_PERIOD - 1
    sbx.maybe_notice_update(sbx.load_state(), args)
    assert len(checks) == 1
    now += 1
    for env in ('SBX_NO_UPDATE_CHECK', 'INVOCATION_ID'):
        monkeypatch.setenv(env, '1')
        sbx.maybe_notice_update(sbx.load_state(), args)
        monkeypatch.delenv(env)
    args.quiet = True
    sbx.maybe_notice_update(sbx.load_state(), args)
    assert len(checks) == 1
    args.quiet = False
    sbx.maybe_notice_update(sbx.load_state(), args)
    assert len(checks) == 2


@pytest.mark.parametrize('executable', [False, True])
def test_replace_update(tmp_path, executable):
    target = tmp_path / 'axiom'
    download = tmp_path / 'asset'
    target.write_bytes(b'old')
    download.write_bytes(b'new')
    sbx.replace_update(download, target, executable)
    assert target.read_bytes() == b'new'
    if executable:
        assert target.with_name('axiom.old').read_bytes() == b'old'
