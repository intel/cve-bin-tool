# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "speex", "version": "1.2.1", "version_strings": ["speexdec-1.2.1"]},
    {
        "product": "speex",
        "version": "1.2",
        "version_strings": ["Unknown wb_mode_query request: \nwarning: %s %d\n1.2"],
    },
    {
        "product": "speex",
        "version": "1.2.0",
        "version_strings": ["1.2.0\nUnknown wb_mode_query request:"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "speex-1.2.1-1.2.aarch64.rpm",
        "product": "speex",
        "version": "1.2.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/s/speex/",
        "package_name": "libspeex1_1.2~rc1.2-1+b2_amd64.deb",
        "product": "speex",
        "version": "1.2",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libspeex_1.2.0-1_x86_64.ipk",
        "product": "speex",
        "version": "1.2.0",
    },
]
