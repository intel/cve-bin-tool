# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "pcre",
        "version": "8.43",
        "version_strings": [
            "8.43 2019-02-23\nargument is not a compiled regular expression"
        ],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/p/",
        "package_name": "pcre-8.45-1.fc38.3.aarch64.rpm",
        "product": "pcre",
        "version": "8.45",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libpcre_8.43-1_x86_64.ipk",
        "product": "pcre",
        "version": "8.43",
    },
]
