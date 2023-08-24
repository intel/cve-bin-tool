# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "libcoap", "version": "4.3.1", "version_strings": ["libcoap 4.3.1"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "libcoap-4.3.2-0.1.rc1.fc39.aarch64.rpm",
        "product": "libcoap",
        "version": "4.3.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libc/libcoap/",
        "package_name": "libcoap-1-0_4.1.2-1_amd64.deb",
        "product": "libcoap",
        "version": "4.1.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libc/libcoap3/",
        "package_name": "libcoap3_4.3.1-1_amd64.deb",
        "product": "libcoap",
        "version": "4.3.1",
        "other_products": ["gnutls"],
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-21.02/x86_64/packages/",
        "package_name": "libcoap2_4.2.1-1_x86_64.ipk",
        "product": "libcoap",
        "version": "4.2.1",
    },
]
