# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for irssi

https://www.cvedetails.com/product/2131/Irssi-Irssi.html?vendor_id=1229

"""
from cve_bin_tool.checkers import Checker


class IrssiChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Configuration file was modified since irssi was last started - do you want to overwrite the possible changes\?",
        r"# The real text formats that irssi uses are the ones you can find with",
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"# %%s : must be second - use Irssi; use Irssi::Irc; etc\.\.",
        # r"# When irssi expands the templates in \"format\", the final string would be:",
        # r"# When irssi sees this kind of text, it goes to find \"name\" from abstracts",
        # r"Log file \{hilight $0\} is locked, probably by another running Irssi",
        # r"my $code = qq{package Irssi::Script::$id; %s $data};",
        # r"#       statically with irssi binary, 0 if not",
    ]
    FILENAME_PATTERNS = [r"irssi"]
    VERSION_PATTERNS = [r"irssi ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("irssi", "irssi")]
