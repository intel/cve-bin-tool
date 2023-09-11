# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "terminology",
        "version": "1.3.2",
        "version_strings": ["1.3.2\nterminology"],
    },
    {
        "product": "terminology",
        "version": "1.13.0",
        "version_strings": ["terminology 1.13.0"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/t/",
        "package_name": "terminology-1.13.0-3.fc39.aarch64.rpm",
        "product": "terminology",
        "version": "1.13.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/t/terminology/",
        "package_name": "terminology_1.3.2-1_amd64.deb",
        "product": "terminology",
        "version": "1.3.2",
    },
]
