# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "netpbm",
        "version": "10.35.32",
        "version_strings": ["Netpbm 10.35.32"],
    },
    {"product": "netpbm", "version": "10.0", "version_strings": ["netpbm-free-10.0"]},
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/netpbm/10.35.46/1.fc10/x86_64/",
        "package_name": "netpbm-10.35.46-1.fc10.x86_64.rpm",
        "product": "netpbm",
        "version": "10.35.46",
    },
    {
        "url": "http://vault.centos.org/4.9/os/x86_64/CentOS/RPMS/",
        "package_name": "netpbm-10.35.58-6.el4.x86_64.rpm",
        "product": "netpbm",
        "version": "10.35.58",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/n/netpbm-free/",
        "package_name": "libnetpbm10_10.0-15.2_amd64.deb",
        "product": "netpbm",
        "version": "10.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/n/netpbm-free/",
        "package_name": "netpbm_10.0-15.3+b2_amd64.deb",
        "product": "netpbm",
        "version": "10.0",
    },
]
