import pytest
from electrum import constants


@pytest.fixture(autouse=True, scope='module')
def _bitcoin_regtest_genesis(request):
    """These upstream tests build on headers of Bitcoin's regtest chain."""
    name = request.module.__name__.rsplit('.', 1)[-1]
    if name not in ('test_blockchain', 'test_interface'):
        yield
        return
    net = constants.BitcoinRegtest
    old = net.GENESIS
    net.GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    yield
    net.GENESIS = old
