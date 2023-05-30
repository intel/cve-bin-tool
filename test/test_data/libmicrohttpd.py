# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libmicrohttpd",
        "version": "0.9.62",
        "version_strings": ["MHD-worker\n0.9.62"],
    }
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "libmicrohttpd-0.9.76-1.fc39.aarch64.rpm",
        "product": "libmicrohttpd",
        "version": "0.9.76",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libm/libmicrohttpd/",
        "package_name": "libmicrohttpd12_0.9.62-1_amd64.deb",
        "product": "libmicrohttpd",
        "version": "0.9.62",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libmicrohttpd-no-ssl_0.9.62-3_x86_64.ipk",
        "product": "libmicrohttpd",
        "version": "0.9.62",
    },
]
