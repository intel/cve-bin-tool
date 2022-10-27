# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "boinc", "version": "7.20.2", "version_strings": ["boinc.so.7.20.2"]},
    {"product": "boinc", "version": "7.10.2", "version_strings": ["7.10.2\nboinc"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "libboinc7-7.20.2-1.3.aarch64.rpm",
        "product": "boinc",
        "version": "7.20.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/b/boinc/",
        "package_name": "boinc-client_7.10.2+dfsg-2~bpo9+1_amd64.deb",
        "product": "boinc",
        "version": "7.10.2",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "boinc_7.16.16-1_x86_64.ipk",
        "product": "boinc",
        "version": "7.16.16",
    },
]
