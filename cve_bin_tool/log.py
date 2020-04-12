"""Logging"""
import logging
import sys


# A log filter to filter out logs based on filter level
# Any log above and equal the specified level will not be logged
class LevelFilter(logging.Filter):
    def __init__(self, level):
        super().__init__()
        self.level = level

    def filter(self, record):
        return record.levelno < self.level


log_formatter = logging.Formatter("%(name)s - %(levelname)s - %(message)s")

# An handler for stderr
stderr_handler = logging.StreamHandler(sys.stderr)

# stderr_handler will log all logs
stderr_handler.setLevel(logging.DEBUG)
stderr_handler.setFormatter(log_formatter)

# Add the handlers to the root logger
root_logger = logging.getLogger()
root_logger.addHandler(stderr_handler)

LOGGER = logging.getLogger(__package__)
LOGGER.setLevel(logging.INFO)
