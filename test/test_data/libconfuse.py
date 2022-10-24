# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "libconfuse", "version": "3.2", "version_strings": ["libConfuse 3.2"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "libconfuse-3.3-7.fc38.aarch64.rpm",
        "product": "libconfuse",
        "version": "3.3",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/l/",
        "package_name": "libconfuse-3.3-7.fc38.i686.rpm",
        "product": "libconfuse",
        "version": "3.3",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libc/libconfuse/",
        "package_name": "libconfuse2_3.3-2_arm64.deb",
        "product": "libconfuse",
        "version": "3.3",
    },
]
