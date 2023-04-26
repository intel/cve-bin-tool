# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "exiv2", "version": "0.27.5", "version_strings": ["exiv2 0.27.5"]},
    {"product": "exiv2", "version": "0.25", "version_strings": ["exiv2 0.25"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/tumbleweed/repo/oss/i586/",
        "package_name": "exiv2-0.27.5-3.1.i586.rpm",
        "product": "exiv2",
        "version": "0.27.5",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/tumbleweed/repo/oss/x86_64/",
        "package_name": "exiv2-0.27.5-3.1.x86_64.rpm",
        "product": "exiv2",
        "version": "0.27.5",
    },
    {
        "url": "http://ftp.de.debian.org/debian/pool/main/e/exiv2/",
        "package_name": "exiv2_0.25-3.1+deb9u2_arm64.deb",
        "product": "exiv2",
        "version": "0.25",
    },
]
