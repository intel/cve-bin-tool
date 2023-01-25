# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for openjpeg

https://www.cvedetails.com/product/50039/Uclouvain-Openjpeg.html?vendor_id=19248

"""
from . import Checker


class OpenjpegChecker(Checker):
    CONTAINS_PATTERNS = [
        r"OpenJPEG cannot encode raw components with bit depth higher than 16 bits."
    ]
    FILENAME_PATTERNS = [
        r"extract_j2k_from_mj2",
        r"frames_to_mj2",
        r"image_to_j2k",
        r"j2k_dump",
        r"j2k_to_image",
        r"mj2_to_frames",
        r"wrap_j2k_in_mj2",
    ]
    VERSION_PATTERNS = [
        r"openjpeg-([0-9]+\.[0-9]+\.[0-9]+)",
        r"openjpeg2-([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("uclouvain", "openjpeg")]
