# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for lua

https://www.cvedetails.com/product/28436/?q=LUA

"""
from cve_bin_tool.checkers import Checker


class LuaChecker(Checker):
    CONTAINS_PATTERNS = [
        r"PANIC: unprotected error in call to Lua API \(%s\)",
        r"-o name  output to file `name' \(default is \"luac.out\"\)",
    ]
    FILENAME_PATTERNS = [r"lua"]
    VERSION_PATTERNS = [r"Lua ([0-9]+\.[0-9]+\.[0-9]+) "]
    VENDOR_PRODUCT = [("lua", "lua")]
