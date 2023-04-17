# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "point-to-point_protocol",
        "version": "2.4.9",
        "version_strings": ["pppd/2.4.9"],
    },
    {
        "product": "point-to-point_protocol",
        "version": "2.4.3",
        "version_strings": ["pppd %s started by %s, uid :%d)\n2.4.3"],
    },
    {
        "product": "point-to-point_protocol",
        "version": "2.4.3",
        "version_strings": ["2.4.3\npppd %s started"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/p/",
        "package_name": "ppp-2.4.9-8.fc37.aarch64.rpm",
        "product": "point-to-point_protocol",
        "version": "2.4.9",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/p/",
        "package_name": "ppp-2.4.9-8.fc37.i686.rpm",
        "product": "point-to-point_protocol",
        "version": "2.4.9",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/p/ppp/",
        "package_name": "ppp_2.4.6-3.1_amd64.deb",
        "product": "point-to-point_protocol",
        "version": "2.4.6",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/p/ppp/",
        "package_name": "ppp_2.4.6-3.1_armel.deb",
        "product": "point-to-point_protocol",
        "version": "2.4.6",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "ppp_2.4.7.git-2019-05-25-3_x86_64.ipk",
        "product": "point-to-point_protocol",
        "version": "2.4.7",
    },
]
