# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""Logging"""
import logging

from rich.logging import RichHandler


class LevelFilter(logging.Filter):
    """
    Initialize the LevelFilter instance.
    """

    def __init__(self, level):
        super().__init__()
        self.level = level

    def filter(self, record):
        """
        Filter out logs based on filter level

        Args:
            record (LogRecord): The log record to be filtered.

        Returns:
            bool: True if the log record's level is below the specified level,
                  indicating that it should be processed and logged; False otherwise,
                  indicating that it should be filtered out.
        """
        return record.levelno < self.level


# Rich Handler by default Initalize a Console with stderr stream for logs
logging.basicConfig(
    level="INFO",
    format="%(name)s - %(message)s",
    datefmt="[%X]",
    handlers=[RichHandler()],
)

# Add the handlers to the root logger
root_logger = logging.getLogger()

LOGGER = logging.getLogger(__package__)
LOGGER.setLevel(logging.INFO)
