# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "nghttp2", "version": "1.50.0", "version_strings": ["nghttp2/1.50.0"]},
    {
        "product": "nghttp2",
        "version": "1.18.1",
        "version_strings": ["1.18.1\nnghttp2-"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/riscv/tumbleweed/repo/oss/riscv64/",
        "package_name": "nghttp2-1.50.0-7.1.riscv64.rpm",
        "product": "nghttp2",
        "version": "1.50.0",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "nghttp2-1.50.0-1.1.aarch64.rpm",
        "product": "nghttp2",
        "version": "1.50.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/n/nghttp2/",
        "package_name": "libnghttp2-14_1.18.1-1+deb9u1_amd64.deb",
        "product": "nghttp2",
        "version": "1.18.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/n/nghttp2/",
        "package_name": "libnghttp2-14_1.18.1-1+deb9u1_arm64.deb",
        "product": "nghttp2",
        "version": "1.18.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "libnghttp2-14_1.41.0-1_x86_64.ipk",
        "product": "nghttp2",
        "version": "1.41.0",
    },
]
