# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "pcre2", "version": "10.22", "version_strings": ["BSR_UNICODE)\n10.22"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/tumbleweed/repo/oss/i586/",
        "package_name": "libpcre2-16-0-10.42-3.3.i586.rpm",
        "product": "pcre2",
        "version": "10.42",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/p/pcre2/",
        "package_name": "libpcre2-16-0_10.22-3_amd64.deb",
        "product": "pcre2",
        "version": "10.22",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libpcre2_10.32-1_x86_64.ipk",
        "product": "pcre2",
        "version": "10.32",
    },
]
