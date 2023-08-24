# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "http_server",
        "version": "2.4.51",
        "version_strings": ["Apache/2.4.51 "],
    },
]

package_test_data = [
    {
        "url": "https://rpmfind.net/linux/fedora/linux/releases/35/Everything/x86_64/os/Packages/h/",
        "package_name": "httpd-2.4.51-2.fc35.x86_64.rpm",
        "product": "http_server",
        "version": "2.4.51",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/a/apache2/",
        "package_name": "apache2-bin_2.4.10-10+deb8u12_amd64.deb",
        "product": "http_server",
        "version": "2.4.10",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "apache_2.4.51-1_x86_64.ipk",
        "product": "http_server",
        "version": "2.4.51",
    },
]
