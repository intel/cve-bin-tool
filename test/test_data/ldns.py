# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "ldns",
        "version": "4.4.0",
        "version_strings": ["ldns_buffer_write_at\n4.4.0"],
    }
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "ldns-1.8.3-6.fc38.aarch64.rpm",
        "product": "ldns",
        "version": "1.8.3",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/l/ldns/",
        "package_name": "libldns2_1.7.0-4_amd64.deb",
        "product": "ldns",
        "version": "1.7.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libldns_1.7.0-5_x86_64.ipk",
        "product": "ldns",
        "version": "1.7.0",
    },
]
