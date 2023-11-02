# Copyright (C) 2023 SCHUTZWERK GmbH
# SPDX-License-Identifier: GPL-3.0-or-later


mapping_test_data = [
    {
        "product": "gawk",
        "version": "5.1.1",
        "version_strings": ["GNU Awk 5.1.1"],
    },
    {
        "product": "gawk",
        "version": "5.2.0",
        "version_strings": ["GNU Awk 5.2.0"],
    },
    {
        "product": "gawk",
        "version": "5.2.1",
        "version_strings": ["GNU Awk 5.2.1"],
    },
]

package_test_data = [
    {
        "url": "http://ftp.de.debian.org/debian/pool/main/g/gawk/",
        "package_name": "gawk_5.2.1-2_amd64.deb",
        "product": "gawk",
        "version": "5.2.1",
    },
    {
        "url": "https://rpmfind.net/linux/fedora/linux/releases/38/Everything/x86_64/os/Packages/g/",
        "package_name": "gawk-5.1.1-5.fc38.x86_64.rpm",
        "product": "gawk",
        "version": "5.1.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/22.03.5/packages/x86_64/packages/",
        "package_name": "gawk_5.2.0-1_x86_64.ipk",
        "product": "gawk",
        "version": "5.2.0",
    },
]
