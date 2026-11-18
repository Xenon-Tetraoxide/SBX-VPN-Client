import pytest

import sbx


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('Тест пытался выйти в сеть без подстановки urlopen')

    monkeypatch.setattr(sbx.urllib.request, 'urlopen', blocked)
    monkeypatch.setenv('SBX_NO_UPDATE_CHECK', '1')


@pytest.fixture(autouse=True)
def isolated_identity(monkeypatch, tmp_path_factory):
    """Тесты не трогают настоящие ~/.config/sbx и не ждут блокировок базы по 3 с."""
    root = tmp_path_factory.mktemp('sbx-home')
    monkeypatch.setattr(sbx, 'HOME', root / 'home')   # пересчёт путей никогда не видит настоящий домашний каталог
    monkeypatch.setattr(sbx, 'CONF_DIR', root)
    monkeypatch.setattr(sbx, 'STATE_FILE', root / 'state.json')
    monkeypatch.setattr(sbx, 'SUBS_DIR', root / 'subs')
    monkeypatch.setattr(sbx, 'RULESET_DIR', root / 'rulesets')
    monkeypatch.setattr(sbx, 'CONFIG_FILE', root / 'config.json')
    monkeypatch.setattr(sbx, 'WORK_DIR', root / 'work')
    monkeypatch.setattr(sbx, 'AXIOM_DB_TIMEOUT', 0.05)
    monkeypatch.setattr(sbx, 'NO_ELEVATE', False)
    monkeypatch.setattr(sbx, 'PARENT_INTERACTIVE', False)
