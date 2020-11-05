import configparser
import pathlib
import shutil
import tempfile
from unittest.mock import MagicMock
from unittest.mock import patch

import lobotomy
import toml
from pytest import mark

import hacksaws

scenarios = [
    {"path": p, **toml.loads(p.read_text())}
    for p in pathlib.Path(__file__).parent.joinpath("scenarios").iterdir()
    if p.is_file() and p.name.endswith(".toml")
]


def _write_settings(path: pathlib.Path, data: dict):
    if data is None:
        return

    entry = configparser.ConfigParser()
    entry.read_dict(data)
    with open(path, "w+") as fp:
        entry.write(fp)


def _read_settings(directory: pathlib.Path) -> dict:
    output = {}
    for item in directory.iterdir():
        if not item.is_file():
            continue

        reader = configparser.ConfigParser()
        reader.read(item)
        output[item.name] = {k: v for k, v in reader.items()}

    return output


@mark.parametrize("scenario", scenarios)
@lobotomy.Patch()
@patch("subprocess.run")
def test_scenario(
    subprocess_run: MagicMock,
    lobotomized: lobotomy.Lobotomy,
    scenario: dict,
):
    """Should execute the invocation as expected for the given scenario."""
    lobotomized.data = scenario.get("lobotomy") or {}
    command = scenario["args"]
    aws = scenario.get("aws")

    aws_directory = None
    if aws:
        aws_directory = pathlib.Path(tempfile.mkdtemp())
        command.append(f"--directory={aws_directory}")

    for filename, contents in (aws or {}).items():
        _write_settings(aws_directory.joinpath(filename), contents)

    expected = scenario.get("expected") or {}

    try:
        result = hacksaws.console_main(scenario["args"])
        assert result.code == expected.get("code", result.code)
        assert subprocess_run.call_count == expected.get(
            "subprocess_run_call_count",
            subprocess_run.call_count,
        )
        if aws_directory:
            assert (
                expected.get("aws", {}).items() <= _read_settings(aws_directory).items()
            )
    finally:
        if aws_directory:
            shutil.rmtree(aws_directory)
