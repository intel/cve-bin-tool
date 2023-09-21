# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "civetweb", "version": "1.13", "version_strings": ["civetweb-%s\n1.13"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/c/",
        "package_name": "civetweb-1.16-2.fc40.aarch64.rpm",
        "product": "civetweb",
        "version": "1.16",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/c/civetweb/",
        "package_name": "libcivetweb1_1.13+dfsg-5_amd64.deb",
        "product": "civetweb",
        "version": "1.13",
    },
]
