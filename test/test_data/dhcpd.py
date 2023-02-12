# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "dhcpd", "version": "4.3.5", "version_strings": ["4.3.5\ndhcpd.c"]},
    {
        "product": "dhcpd",
        "version": "4.4.3",
        "version_strings": ["dhcpd.c\nCan't allocate new generic object: %s\n4.4.3"],
    },
]
package_test_data = [
    {
        "url": "https://www.rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/d/",
        "package_name": "dhcp-server-4.4.3-7.P1.fc38.aarch64.rpm",
        "product": "dhcpd",
        "version": "4.4.3",
        "other_products": ["dhcp"],
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/i/isc-dhcp/",
        "package_name": "isc-dhcp-server_4.3.5-3+deb9u1_arm64.deb",
        "product": "dhcpd",
        "version": "4.3.5",
        "other_products": ["dhcp"],
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "isc-dhcp-server-ipv6_4.4.1-4_x86_64.ipk",
        "product": "dhcpd",
        "version": "4.4.1",
        "other_products": ["dhcp"],
    },
]
