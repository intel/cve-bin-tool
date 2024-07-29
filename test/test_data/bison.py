# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "bison", "version": "3.8.2", "version_strings": ["GNU Bison 3.8.2"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/openmandriva/cooker/repository/aarch64/main/release/",
        "package_name": "bison-3.8.2-6-omv4090.aarch64.rpm",
        "product": "bison",
        "version": "3.8.2",
    },
    {
        "url": "http://rpmfind.net/linux/openmandriva/cooker/repository/x86_64/main/release/",
        "package_name": "bison-3.8.2-6-omv4090.x86_64.rpm",
        "product": "bison",
        "version": "3.8.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/b/bison/",
        "package_name": "bison_3.0.2.dfsg-2_amd64.deb",
        "product": "bison",
        "version": "3.0.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/b/bison/",
        "package_name": "bison_3.0.2.dfsg-2_armel.deb",
        "product": "bison",
        "version": "3.0.2",
    },
]
