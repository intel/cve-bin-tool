# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import logging
import os
import sys

from cve_bin_tool import cli
from cve_bin_tool.error_handler import ErrorHandler, InsufficientArgs, excepthook
from cve_bin_tool.log import LOGGER

sys.excepthook = excepthook


def main(argv: list[str] | None = None):
    """Used to scan a .csv file that lists the dependencies."""
    if sys.version_info < (3, 8):
        raise OSError(
            "Python no longer provides security updates for version 3.7 as of June 2023. Please upgrade to python 3.8+ to use CVE Binary Tool."
        )
    logger: logging.Logger = LOGGER.getChild("CSV2CVE")
    argv = argv or sys.argv
    if len(argv) < 2:
        with ErrorHandler(logger=logger):
            raise InsufficientArgs("csv file required")

    flag: bool = False
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
