# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for zsh
--------
References:
https://www.cvedetails.com/product/12642/ZSH-ZSH.html?vendor_id=7498
https://www.cvedetails.com/product/43927/Zsh-Project-ZSH.html?vendor_id=17702

"""

from cve_bin_tool.checkers import Checker


class ZshChecker(Checker):
    CONTAINS_PATTERNS = [
        r"zsh: sure you want to delete all %d files in",
        r"zsh: sure you want to delete all the files in",
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"--version  show zsh version number, then exit",
        # r"zsh: sure you want to delete more than %d files in",
        # r"zsh: sure you want to delete the only file in",
    ]
    FILENAME_PATTERNS = [
        r"newuser.so",
        r"zsh",
    ]
    VERSION_PATTERNS = [r"zsh/([0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [("zsh", "zsh"), ("zsh_project", "zsh")]
