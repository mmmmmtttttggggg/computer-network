import copy
import json
from importlib.resources import files
import pytest


@pytest.fixture
def example():
    def get(name="clean-baseline"):
        return copy.deepcopy(
            json.loads(files("app").joinpath("resources/examples", name + ".json").read_text())
        )

    return get
