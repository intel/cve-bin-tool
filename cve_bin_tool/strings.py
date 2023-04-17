# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
These are the customized strings and file classes, by doing this
the tool is able to support other operating systems like Windows
and MacOS.
"""

import subprocess
from typing import ClassVar, List, Set

from cve_bin_tool.async_utils import FileIO, run_coroutine
from cve_bin_tool.util import inpath


class Strings:
    # printable characters
    PRINTABLE: ClassVar[Set[int]] = set(range(32, 128))
    # add tab to the printable character
    PRINTABLE.add(9)

    def __init__(self, filename: str = "") -> None:
        self.filename = filename
        self.output: str = ""

    async def aio_parse(self) -> str:
        async with FileIO(self.filename, "rb") as f:
            tmp: List[str] = []
            async for line in f:
                for char in line:
                    # remove all unprintable characters
                    if char in Strings.PRINTABLE:
                        tmp.append(chr(char))
                    elif tmp:
                        if len(tmp) >= 3:
                            self.output += "".join(tmp) + "\n"
                        tmp = []
        return self.output

    def parse(self) -> str:
        return run_coroutine(self.aio_parse())


def parse_strings(filename: str) -> str:
    """parse binary file's strings"""

    if inpath("strings"):
        # use "strings" on system if available (for performance)
        data = subprocess.check_output(["strings", "-n", "3", filename])
        lines = data.decode("utf-8", errors="backslashreplace")
    else:
        # Otherwise, use python implementation
        s = Strings(filename)
        lines = s.parse()
    return lines
