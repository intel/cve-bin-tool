# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "dnsmasq", "version": "2.79", "version_strings": ["dnsmasq-2.79"]},
    {"product": "dnsmasq", "version": "2.84", "version_strings": ["dnsmasq-2.84"]},
]

package_test_data = [
    {
        "url": "http://mirror.centos.org/centos/8/AppStream/aarch64/os/Packages/",
        "package_name": "dnsmasq-2.79-13.el8_3.1.aarch64.rpm",
        "product": "dnsmasq",
        "version": "2.79",
    },
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/d/",
        "package_name": "dnsmasq-2.84-1.fc34.aarch64.rpm",
        "product": "dnsmasq",
        "version": "2.84",
    },
]
