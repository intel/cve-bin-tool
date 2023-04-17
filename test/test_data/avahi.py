# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "avahi", "version": "0.6.24", "version_strings": ["avahi 0.6.24"]},
    {"product": "avahi", "version": "0.7", "version_strings": ["avahi-0.7"]},
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/avahi/0.6.26/3.fc14/x86_64/",
        "package_name": "avahi-0.6.26-3.fc14.x86_64.rpm",
        "product": "avahi",
        "version": "0.6.26",
    },
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/avahi/0.6.32/7.fc26/ppc64/",
        "package_name": "avahi-0.6.32-7.fc26.ppc64.rpm",
        "product": "avahi",
        "version": "0.6.32",
    },
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "avahi-0.6.31-20.el7.x86_64.rpm",
        "product": "avahi",
        "version": "0.6.31",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/a/avahi/",
        "package_name": "avahi-daemon_0.6.31-5_amd64.deb",
        "product": "avahi",
        "version": "0.6.31",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "avahi-dbus-daemon_0.8-1_x86_64.ipk",
        "product": "avahi",
        "version": "0.8",
    },
]
