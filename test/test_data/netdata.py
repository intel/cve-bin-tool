# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "netdata", "version": "1.12.0", "version_strings": ["NETDATA\nv1.12.0"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/n/",
        "package_name": "netdata-1.44.1-1.fc40.aarch64.rpm",
        "product": "netdata",
        "version": "1.44.1",
        "other_products": ["sqlite"],
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/n/netdata/",
        "package_name": "netdata-core_1.12.0-1+deb10u1_amd64.deb",
        "product": "netdata",
        "version": "1.12.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "netdata_1.30.1-2_x86_64.ipk",
        "product": "netdata",
        "version": "1.30.1",
        "other_products": ["sqlite"],
    },
]
