# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "apparmor",
        "version": "2.9.0",
        "version_strings": ["%s version 2.9.0\napparmor"],
    }
]
package_test_data = [
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/a/apparmor/",
        "package_name": "apparmor_2.9.0-3_amd64.deb",
        "product": "apparmor",
        "version": "2.9.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/22.03.0/packages/x86_64/packages/",
        "package_name": "apparmor-utils_3.0.3-4_x86_64.ipk",
        "product": "apparmor",
        "version": "3.0.3",
    },
]
