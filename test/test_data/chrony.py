# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "chrony", "version": "4.2", "version_strings": ["chrony\n4.2"]},
    {"product": "chrony", "version": "4.2", "version_strings": ["4.2\nchronyd"]},
]
package_test_data = [
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/c/chrony/",
        "package_name": "chrony_1.30-2+deb8u2_amd64.deb",
        "product": "chrony",
        "version": "1.30",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/c/chrony/",
        "package_name": "chrony_1.30-2+deb8u2_armel.deb",
        "product": "chrony",
        "version": "1.30",
    },
    {
        "url": "https://downloads.openwrt.org/releases/22.03.0/packages/x86_64/packages/",
        "package_name": "chrony_4.2-5_x86_64.ipk",
        "product": "chrony",
        "version": "4.2",
    },
]
