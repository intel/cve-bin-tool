# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for ffmpeg

References:
https://www.ffmpeg.org/
https://www.cvedetails.com/vulnerability-list/vendor_id-3611/Ffmpeg.html

Note: Some of the "first vulnerable in" data may not be entered correctly.
"""
from cve_bin_tool.checkers import Checker


class FfmpegChecker(Checker):
    # NOTE:XXX: can we optimize version pattern
    CONTAINS_PATTERNS = [
        r"Codec '%s' is not recognized by FFmpeg.",
        r"Codec '%s' is known to FFmpeg, but no %s for it are available.",
    ]
    FILENAME_PATTERNS = [r"ffmpeg"]
    VERSION_PATTERNS = [
        r"%s version ([0-9]+\.[0-9]+\.[0-9]+)[a-zA-Z0-9 \(\)%~\-\r\n]*(?:avutil|FFmpeg)",
        r"FFmpeg version ([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("ffmpeg", "ffmpeg")]
