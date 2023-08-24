# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for fluidsynth

https://www.cvedetails.com/product/82484/Fluidsynth-Fluidsynth.html?vendor_id=23141

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class FluidsynthChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"FluidSynth executable version ([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)[a-zA-Z0-9=:% \(\)\-\.\r\n]*FluidSynth",
        r"fluidsynth-([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("fluidsynth", "fluidsynth")]
