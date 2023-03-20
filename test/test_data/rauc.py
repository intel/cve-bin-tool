# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "rauc", "version": "1.5.1", "version_strings": ["rauc 1.5.1"]},
    {"product": "rauc", "version": "1.8", "version_strings": ["rauc 1.8"]},
]
package_test_data = [
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/r/rauc/",
        "package_name": "rauc_1.5.1-1_amd64.deb",
        "product": "rauc",
        "version": "1.5.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/r/rauc/",
        "package_name": "rauc_1.8-2_arm64.deb",
        "product": "rauc",
        "version": "1.8",
    },
]
