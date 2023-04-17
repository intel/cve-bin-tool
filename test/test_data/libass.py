# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "libass", "version": "0.16.0", "version_strings": ["0.16.0\nlibass"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "libass-0.16.0-2.fc37.aarch64.rpm",
        "product": "libass",
        "version": "0.16.0",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/l/",
        "package_name": "libass-0.16.0-2.fc37.i686.rpm",
        "product": "libass",
        "version": "0.16.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/liba/libass/",
        "package_name": "libass9_0.16.0-1_amd64.deb",
        "product": "libass",
        "version": "0.16.0",
    },
]
