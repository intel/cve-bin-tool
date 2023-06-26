# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "nginx",
        "version": "1.13.2",
        "version_strings": ["NGINX environment variable", "nginx/1.13.2"],
    }
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/nginx/1.8.0/10.fc22/x86_64/",
        "package_name": "nginx-1.8.0-10.fc22.x86_64.rpm",
        "product": "nginx",
        "version": "1.8.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/n/nginx/",
        "package_name": "nginx-full_1.10.3-1+deb9u4_amd64.deb",
        "product": "nginx",
        "version": "1.10.3",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "nginx_1.17.7-3_x86_64.ipk",
        "product": "nginx",
        "version": "1.17.7",
    },
]
