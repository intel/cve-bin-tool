# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "long_range_zip",
        "version": "0.631",
        "version_strings": ["lrz%s version %s\n0.631"],
    },
    {
        "product": "long_range_zip",
        "version": "0.651",
        "version_strings": ["0.651\nlrz%s version %s"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/i586/tumbleweed/repo/oss/i586/",
        "package_name": "lrzip-0.651-2.3.i586.rpm",
        "product": "long_range_zip",
        "version": "0.651",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/l/lrzip/",
        "package_name": "lrzip_0.631+git180528-1+deb10u1_amd64.deb",
        "product": "long_range_zip",
        "version": "0.631",
    },
    {
        "url": "http://dl-cdn.alpinelinux.org/alpine/v3.11/community/x86_64/",
        "package_name": "lrzip-0.631-r0.apk",
        "product": "long_range_zip",
        "version": "0.631",
    },
]
