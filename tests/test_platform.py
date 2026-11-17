import hashlib
import io
import json
import subprocess
import zipfile

import pytest

import sbx
from test_config import fixture_config


def test_windows_paths_and_commands(monkeypatch, tmp_path):
    roaming, local = tmp_path / 'Roaming', tmp_path / 'Local'
    config, work, core = sbx.platform_paths(tmp_path, {'APPDATA': str(roaming),
                                                      'LOCALAPPDATA': str(local)}, True)
    assert config == roaming / 'sbx'
    assert work == local / 'sbx/work'
    assert sbx.sing_box_path({}, True, core) == str(local / 'sbx/core/sing-box.exe')
    assert sbx.sing_box_path({'SBX_SING_BOX': 'custom'}, True, core) == 'custom'
    assert sbx.platform_paths(tmp_path, {'SBX_HOME': str(config)}, False)[:2] == (config, config / 'work')
    monkeypatch.setattr(sbx, 'IS_WIN', True)
    monkeypatch.setattr(sbx, 'LOG_FILE', work / 'sing-box.log')
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        output = '"\\sbx","N/A","Running"\n' if command[1] == '/query' else ''
        return subprocess.CompletedProcess(command, 0, output, '')

    monkeypatch.setattr(sbx, 'run', run)
    monkeypatch.setattr(sbx, 'api_up', lambda state: state['up'])
    assert sbx.is_active({'up': True})
    assert not sbx.is_active({'up': False})
    assert sbx.foreign_tun() == []
    sbx.service_action('start')
    sbx.service_action('stop')
    assert calls == [['schtasks', '/query', '/tn', 'sbx', '/fo', 'csv', '/nh']] * 2 + [
        ['schtasks', '/run', '/tn', 'sbx'], ['schtasks', '/end', '/tn', 'sbx'],
    ]
    assert fixture_config(monkeypatch)['log']['output'] == str(work / 'sing-box.log')


def test_task_xml_quotes_paths_and_separates_privileges(tmp_path):
    ns = {'t': sbx.TASK_NS}
    path = tmp_path / 'Program Files/sing-box.exe'
    xml = sbx.task_xml([str(path), 'run', '-c', 'a b.json'], 'S-1-5-18', boot=False)
    root = sbx.ET.fromstring(xml)
    assert root.findtext('.//t:Command', namespaces=ns) == str(path)
    assert root.findtext('.//t:Arguments', namespaces=ns) == 'run -c "a b.json"'
    assert root.findtext('.//t:BootTrigger/t:Enabled', namespaces=ns) == 'false'
    assert root.findtext('.//t:RunLevel', namespaces=ns) == 'HighestAvailable'
    root = sbx.ET.fromstring(sbx.task_xml(['sbx.exe', 'update', '-q'], 'S-1-5-21-1000'))
    assert root.findtext('.//t:Interval', namespaces=ns) == 'PT6H'
    assert root.findtext('.//t:LogonType', namespaces=ns) == 'InteractiveToken'
    assert root.findtext('.//t:RunLevel', namespaces=ns) == 'LeastPrivilege'


def test_windows_elevation_dispatch(monkeypatch):
    monkeypatch.setattr(sbx, 'IS_WIN', True)
    monkeypatch.setattr(sbx, 'windows_admin', lambda: False)
    monkeypatch.setattr(sbx, 'request_windows_admin', lambda args: calls.append(args))
    calls = []
    sbx.cmd_up({}, sbx.argparse.Namespace(force=True))
    sbx.cmd_down({}, None)
    assert calls == [['up', '--force'], ['down']]


def test_core_download_checks_digest_and_extracts_only_expected_files(monkeypatch, tmp_path):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as out:
        out.writestr('core/sing-box.exe', b'fixture exe')
        out.writestr('core/libcronet.dll', b'fixture dll')
        out.writestr('../unexpected', b'discarded')
    payload = archive.getvalue()
    release = {'tag_name': 'v1.13.0', 'assets': [{
        'name': 'sing-box-1.13.0-windows-amd64.zip',
        'browser_download_url': 'https://example.test/core.zip',
        'digest': 'sha256:' + hashlib.sha256(payload).hexdigest(),
    }]}
    monkeypatch.setattr(sbx, 'windows_arch', lambda: 'amd64')

    def urlopen(request, **kwargs):
        return io.BytesIO(json.dumps(release).encode() if isinstance(request, sbx.urllib.request.Request)
                          else payload)

    monkeypatch.setattr(sbx.urllib.request, 'urlopen', urlopen)
    core = sbx.install_core(tmp_path)
    assert core.read_bytes() == b'fixture exe'
    assert {path.name for path in tmp_path.iterdir()} == {'sing-box.exe', 'libcronet.dll'}
    release['assets'][0]['digest'] = 'sha256:' + '0' * 64
    with pytest.raises(ValueError, match='не совпала'):
        sbx.install_core(tmp_path)
    assert core.read_bytes() == b'fixture exe'
