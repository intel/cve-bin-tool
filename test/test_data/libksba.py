# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "libksba", "version": "1.5.0", "version_strings": ["Libksba 1.5.0"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "libksba-1.6.2-1.fc38.aarch64.rpm",
        "product": "libksba",
        "version": "1.6.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libk/libksba/",
        "package_name": "libksba8_1.5.0-3_amd64.deb",
        "product": "libksba",
        "version": "1.5.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-21.02/x86_64/packages/",
        "package_name": "libksba_1.6.1-1_x86_64.ipk",
        "product": "libksba",
        "version": "1.6.1",
    },
]
