import pytest

from savitar.graph import build_sample_graph, NOW


@pytest.fixture
def graph():
    return build_sample_graph(seed=42)


@pytest.fixture
def now():
    return NOW
