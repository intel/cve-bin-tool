# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
from enum import Enum
from logging import Logger
from typing import Union

from rich.console import Console
from rich.traceback import Traceback

CONSOLE = Console(file=sys.stderr)


class InsufficientArgs(Exception):
    """Insufficient command line arguments"""


class EmptyTxtError(Exception):
    """Given txt File is empty"""


class InvalidListError(Exception):
    """Given File is an invalid package list"""


class InvalidCsvError(Exception):
    """Given File is an Invalid CSV"""


class InvalidCheckerError(Exception):
    """Raised when data provided to Checker is not correct"""


class MissingFieldsError(Exception):
    """Missing needed fields"""


class InvalidJsonError(Exception):
    """Given File is an Invalid JSON"""


class InvalidIntermediateJsonError(Exception):
    """Given Intermediate File is not in valid Format"""


class EmptyCache(Exception):
    """
    Raised when NVD is opened when verify=False and there are no files in the
    cache.
    """


class CVEDataForYearNotInCache(Exception):
    """
    Raised when the CVE data for a year is not present in the cache.
    """


class CVEDataForCurlVersionNotInCache(Exception):
    """
    Raised when the CVE data for a curl version is not present in the cache.
    """


class CVEDataMissing(Exception):
    """
    Raised when no CVE data is present in the database.
    """


class AttemptedToWriteOutsideCachedir(Exception):
    """
    Raised if we attempted to write to a file that would have been outside the
    cachedir.
    """


class NVDRateLimit(Exception):
    """
    Raised if you have been ratelimited by NVD.
    """


class SHAMismatch(Exception):
    """
    Raised if the sha of a file in the cache was not what it should be.
    """


class ExtractionFailed(ValueError):
    """Extraction fail"""


class UnknownArchiveType(ValueError):
    """Unknown archive type"""


class UnknownConfigType(Exception):
    """Unknown configuration file type"""


class ErrorMode(Enum):
    Ignore = 0
    NoTrace = 1
    TruncTrace = 2
    FullTrace = 3


def excepthook(exc_type, exc_val, exc_tb):
    trace = Traceback.from_exception(exc_type, exc_val, exc_tb)
    CONSOLE.print(trace)
    if ERROR_CODES.get(exc_type):
        sys.exit(ERROR_CODES[exc_type])


class ErrorHandler:
    """Error handler context manager.

    Supports Different modes like ignore error, print full trace, truncated trace and no trace.
    Log messages if logger specified.

    Args:
        mode (ErrorMode): Can take any valid ErrorMode as an arg and change output according to that.
        logger (Logger): logs error message specified while raising Exception if logger is passed
                         while class initialization.
                         Ex: raise ValueError("file required") will log 'ValueError: file required'.
    Attributes:
        exit_code (int): Stores exit code for raised Exception, set -1 for generic Exception and 0
                         if code executes without Exception.
        exc_val (Union[BaseException, None]): Stores exception instance if Exception raises otherwise None.
    """

    exit_code: int
    exc_val: Union[BaseException, None]

    def __init__(self, logger: Logger = None, mode: ErrorMode = ErrorMode.TruncTrace):
        self.mode = mode
        self.logger = logger
        self.exit_code = 0
        self.exc_val = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if isinstance(exc_val, BaseException):
            self.exit_code = ERROR_CODES.get(exc_type, -1)
            self.exc_val = exc_val
        if self.mode == ErrorMode.Ignore:
            return True
        if exc_type:
            if self.logger and exc_val:
                self.logger.error(f"{exc_type.__name__}: {exc_val}")
            if self.mode == ErrorMode.NoTrace:
                sys.exit(self.exit_code)
            if self.mode == ErrorMode.TruncTrace:
                CONSOLE.print_exception()
                sys.exit(self.exit_code)
            return False


# Exit codes for Exception. exit code -1 is reserved for unknown exceptions.
ERROR_CODES = {
    SystemExit: -2,
    FileNotFoundError: -3,
    InvalidCsvError: -4,
    InvalidJsonError: -4,
    EmptyTxtError: -4,
    InvalidListError: -4,
    MissingFieldsError: -5,
    InsufficientArgs: -6,
    EmptyCache: -7,
    CVEDataForYearNotInCache: -8,
    CVEDataForCurlVersionNotInCache: -9,
    AttemptedToWriteOutsideCachedir: -10,
    SHAMismatch: -11,
    ExtractionFailed: -12,
    UnknownArchiveType: -13,
    UnknownConfigType: -14,
    CVEDataMissing: -15,
    InvalidCheckerError: -16,
    NVDRateLimit: -17,
    InvalidIntermediateJsonError: -18,
}
