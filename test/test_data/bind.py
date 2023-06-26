# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "bind",
        "version": "9.10.2",
        "version_strings": ["version: BIND 9.10.2"],
    },
    {"product": "bind", "version": "9.10.2", "version_strings": ["/bind-9.10.2"]},
    {"product": "bind", "version": "9.10.2", "version_strings": ["libbind9-9.10.2"]},
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/bind/9.10.3/1.fc23/x86_64/",
        "package_name": "bind-9.10.3-1.fc23.x86_64.rpm",
        "product": "bind",
        "version": "9.10.3",
    },
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "bind-9.11.4-26.P2.el7.x86_64.rpm",
        "product": "bind",
        "version": "9.11.4",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/b/bind9/",
        "package_name": "bind9-libs_9.16.27-1~deb11u1~bpo10+1_amd64.deb",
        "product": "bind",
        "version": "9.16.27",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "bind-libs_9.16.28-1_x86_64.ipk",
        "product": "bind",
        "version": "9.16.28",
    },
]
