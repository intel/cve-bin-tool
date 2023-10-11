# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for e2fsprogs

https://www.cvedetails.com/product/12670/Ext2-Filesystems-Utilities-E2fsprogs.html?vendor_id=7512
https://www.cvedetails.com/product/31107/E2fsprogs-Project-E2fsprogs.html?vendor_id=15251

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class E2FsprogsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [
        r"libe2p\.so",
        r"libe2p\.so",
        r"libext2fs\.so",
        r"libext2fs\.so",
        r"libcom_err\.so",
        r"badblocks$",
        r"debugfs$",
        r"dumpe2fs$",
        r"e2fsck$",
        r"e2image$",
        r"e2label$",
        r"e2mmpstatus$",
        r"e2undo$",
        r"fsck\.ext2$",
        r"fsck\.ext3$",
        r"fsck\.ext4$",
        r"logsave$",
        r"mke2fs$",
        r"mkfs\.ext2$",
        r"mkfs\.ext3$",
        r"mkfs\.ext4$",
        r"resize2fs$",
        r"tune2fs$",
        r"hattr",
        r"sattr",
        r"e2freefrag",
        r"e4crypt",
        r"e4defrag",
        r"filefrag",
        r"mklost\+found",
    ]
    VERSION_PATTERNS = [
        r"e2fsprogs\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
        r"e2fsprogs-([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nError: ext2fs",
        r"EXT2FS Library version ([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [
        ("ext2_filesystems_utilities", "e2fsprogs"),
        ("e2fsprogs_project", "e2fsprogs"),
    ]
