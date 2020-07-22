#!/usr/bin/python3
import os
import sys

from . import cli
from .error_handler import excepthook, ErrorHandler, InsufficientArgs
from .log import LOGGER

sys.excepthook = excepthook


def main(argv=None):
    logger = LOGGER.getChild("CSV2CVE")
    argv = argv or sys.argv
    if len(argv) < 2:
        with ErrorHandler(logger=logger):
            raise InsufficientArgs("csv file required")

    flag = False
    for idx, arg in enumerate(argv):
        if arg.endswith(".csv"):
            argv[idx] = f"-i={arg}"
            flag = True
    if flag:
        return cli.main(argv)
    else:
        with ErrorHandler(logger=logger):
            raise InsufficientArgs("csv file required")


if __name__ == "__main__":
    if os.getenv("NO_EXIT_CVE_NUM"):
        main()
    else:
        sys.exit(main())
