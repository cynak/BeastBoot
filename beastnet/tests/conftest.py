import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "python"))
sys.path.insert(0, HERE)

from bn_helpers import Server, Site, have, make_certs  # noqa: E402


@pytest.fixture(scope="session")
def certs(tmp_path_factory):
    if not have("openssl"):
        pytest.skip("openssl is needed to make a throwaway CA")
    return make_certs(str(tmp_path_factory.mktemp("certs")))


@pytest.fixture
def site():
    return Site()


@pytest.fixture
def https(site, certs):
    srv = Server(site, (certs.good_cert, certs.good_key))
    yield srv
    srv.close()


@pytest.fixture
def http(site):
    srv = Server(site)
    yield srv
    srv.close()


@pytest.fixture
def data_root(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    return str(d)
