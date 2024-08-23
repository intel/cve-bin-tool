# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "libyaml", "version": "0.2.1", "version_strings": ["0.2.1\ntag:yaml"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "libyaml-0.2.5-15.fc41.aarch64.rpm",
        "product": "libyaml",
        "version": "0.2.5",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/liby/libyaml/",
        "package_name": "libyaml-0-2_0.2.1-1_amd64.deb",
        "product": "libyaml",
        "version": "0.2.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libyaml_0.2.2-1_x86_64.ipk",
        "product": "libyaml",
        "version": "0.2.2",
    },
]
