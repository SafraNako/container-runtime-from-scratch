"""The exceptions of the package."""
from __future__ import annotations


class KonteynerError(Exception):
    """Base class of every error that is raised on purpose (the command line shows its message, without a traceback)."""


class ImageError(KonteynerError):
    pass


class NoSuchImage(ImageError):
    pass


class NoSuchContainer(KonteynerError):
    pass


class StartError(KonteynerError):
    """The container could not be started: the message says which step failed (the file system, a mount, the command ...)."""

    def __init__(self, message: str, exit_code: int = 126) -> None:
        super().__init__(message)
        self.exit_code = exit_code
