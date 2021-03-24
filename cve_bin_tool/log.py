# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""Logging"""
import logging

from rich.logging import RichHandler


# A log filter to filter out logs based on filter level
# Any log above and equal the specified level will not be logged
class LevelFilter(logging.Filter):
    def __init__(self, level):
        super().__init__()
        self.level = level

    def filter(self, record):
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
