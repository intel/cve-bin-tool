# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This module contains fuzz testing for the CVE-Bin-CLI.
"""

import atheris

with atheris.instrument_imports():
    import sys

    from cve_bin_tool import cli


def TestOneInput(data):
    """
    Fuzz test the CLI with the given data.

    Args:
        data (protobuf message): The protobuf message to convert and process.
    """
    try:
        # uncomment the one below to run tests where there is a valid filename:
        # cli.main(["test/assets/test-curl-7.34.0.out", data])
        cli.main(data)

    except SystemExit:
        # force return on SystemExit since those are mostly InsufficientArgs
        return


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
