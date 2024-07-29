# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "haproxy",
        "version": "1.7.3",
        "version_strings": ["HA-Proxy version 1.7.3"],
    },
    {
        "product": "haproxy",
        "version": "2.6.6",
        "version_strings": ["2.6.6-1\nHAProxy version follows"],
    },
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/haproxy/1.8.4/2.fc28/x86_64/",
        "package_name": "haproxy-1.8.4-2.fc28.x86_64.rpm",
        "product": "haproxy",
        "version": "1.8.4",
        "other_products": ["gcc"],
    },
    {
        "url": "https://mirrors.edge.kernel.org/centos/7/os/x86_64/Packages/",
        "package_name": "haproxy-1.5.18-9.el7.x86_64.rpm",
        "product": "haproxy",
        "version": "1.5.18",
        "other_products": ["gcc"],
    },
    {
        "url": "http://ftp.br.debian.org/debian/pool/main/h/haproxy/",
        "package_name": "haproxy_2.6.6-1_arm64.deb",
        "product": "haproxy",
        "version": "2.6.6",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "haproxy_2.0.25-1_x86_64.ipk",
        "product": "haproxy",
        "version": "2.0.25",
        "other_products": ["lua"],
    },
]
