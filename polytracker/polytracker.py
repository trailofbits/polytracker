__docformat__ = "google"

import logging
from importlib.metadata import version as metadata_version

from .tracing import *

log = logging.getLogger("PolyTracker")

VersionElement = Union[int, str]


def version() -> str:
    return metadata_version("polytracker")
