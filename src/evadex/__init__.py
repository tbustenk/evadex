from importlib.metadata import version, PackageNotFoundError
try:
    __version__ = version("evadex")
except PackageNotFoundError:
    __version__ = "0.1.0"
