import pathlib as _pathlib
from importlib import metadata as _metadata

from hacksaws._cli import console_main  # noqa

try:
    __version__ = _metadata.version(__package__)
except _metadata.PackageNotFoundError:  # pragma: no-cover
    # If the package is not installed such that it has distribution metadata
    # fallback to loading the version from the pyproject.toml file.
    import toml as _toml

    __version__ = _toml.loads(
        _pathlib.Path(__file__).parent.parent.joinpath("pyproject.toml").read_text()
    )["tool"]["poetry"]["version"]
