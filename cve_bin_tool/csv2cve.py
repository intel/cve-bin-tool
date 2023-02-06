# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os
import sys
from typing import List, Optional

from cve_bin_tool import cli
from cve_bin_tool.error_handler import ErrorHandler, InsufficientArgs, excepthook
from cve_bin_tool.log import LOGGER

sys.excepthook = excepthook


def main(argv: Optional[List[str]] = None):
    if sys.version_info < (3, 7):
        raise OSError(
            "Python no longer provides security updates for version 3.6 as of December 2021. Please upgrade to python 3.7+ to use CVE Binary Tool."
        )
    logger: logging.Logger = LOGGER.getChild("CSV2CVE")
    argv: List[str] = argv or sys.argv
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
