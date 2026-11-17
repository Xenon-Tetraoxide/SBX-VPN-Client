import pytest

import sbx


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('Тест пытался выйти в сеть без подстановки urlopen')

    monkeypatch.setattr(sbx.urllib.request, 'urlopen', blocked)
    monkeypatch.setenv('SBX_NO_UPDATE_CHECK', '1')
