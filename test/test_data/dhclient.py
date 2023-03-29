# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "dhcp", "version": "4.3.1", "version_strings": ["dhclient.c\n4.3.1"]},
    {"product": "dhcp", "version": "4.4.3", "version_strings": ["4.4.3\ndhclient.c"]},
]
package_test_data = [
    {
        "url": "https://www.rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/d/",
        "package_name": "dhcp-client-4.4.3-5.P1.fc38.aarch64.rpm",
        "product": "dhcp",
        "version": "4.4.3",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/i/isc-dhcp/",
        "package_name": "isc-dhcp-client_4.3.1-6+deb8u3_amd64.deb",
        "product": "dhcp",
        "version": "4.3.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "isc-dhcp-client-ipv4_4.4.1-4_x86_64.ipk",
        "product": "dhcp",
        "version": "4.4.1",
    },
]
