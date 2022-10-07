# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "dnsmasq", "version": "2.79", "version_strings": ["dnsmasq-2.79"]},
    {"product": "dnsmasq", "version": "2.84", "version_strings": ["dnsmasq-2.84"]},
    {
        "product": "dnsmasq",
        "version": "2.80",
        "version_strings": ["2.80\nDnsmasq version %s"],
    },
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
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "dnsmasq_2.80-16.3_x86_64.ipk",
        "product": "dnsmasq",
        "version": "2.80",
    },
]
