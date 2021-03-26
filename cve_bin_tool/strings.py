# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

#!/usr/bin/python3

"""
These are the customized strings and file classes, by doing this
the tool is able to support other operating systems like Windows
and MacOS.
"""

from cve_bin_tool.async_utils import FileIO, run_coroutine


class Strings:
    # printable characters
    PRINTABLE = set(range(32, 128))
    # add tab to the printable character
    PRINTABLE.add(9)

    def __init__(self, filename=""):
        self.filename = filename
        self.output = [""]

    async def aio_parse(self):
        async with FileIO(self.filename, "rb") as f:
            tmp = []
            async for line in f:
                for char in line:
                    # remove all unprintable characters
                    if char in Strings.PRINTABLE:
                        tmp.append(chr(char))
                    elif tmp:
                        self.output.append("".join(tmp))
                        tmp = []
        return self.output

    def parse(self):
        return run_coroutine(self.aio_parse())
