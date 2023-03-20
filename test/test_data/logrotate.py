# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "logrotate",
        "version": "3.18.0",
        "version_strings": [
            "logrotate 3.18.0 - Copyright (C) 1995-2001 Red Hat, Inc.",
            "WARNING: logrotate in debug mode does nothing except printing debug messages!  Consider using verbose mode (-v) instead if this is not what you want.",
            'Set "su" directive in config file to tell logrotate which user/group should be used for rotation',
        ],
    },
    {
        "product": "logrotate",
        "version": "3.14.0",
        "version_strings": [
            "logrotate 3.14.0 - Copyright (C) 1995-2001 Red Hat, Inc.",
            "WARNING: logrotate in debug mode does nothing except printing debug messages!  Consider using verbose mode (-v) instead if this is not what you want.",
            'Set "su" directive in config file to tell logrotate which user/group should be used for rotation',
        ],
    },
]
package_test_data = [
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/34/Everything/aarch64/os/Packages/l/",
        "package_name": "logrotate-3.18.0-2.fc34.aarch64.rpm",
        "product": "logrotate",
        "version": "3.18.0",
    },
    {
        "url": "http://mirror.centos.org/centos/8/BaseOS/aarch64/os/Packages/",
        "package_name": "logrotate-3.14.0-4.el8.aarch64.rpm",
        "product": "logrotate",
        "version": "3.14.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/l/logrotate/",
        "package_name": "logrotate_3.11.0-0.1_amd64.deb",
        "product": "logrotate",
        "version": "3.11.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "logrotate_3.17.0-1_x86_64.ipk",
        "product": "logrotate",
        "version": "3.17.0",
    },
]
