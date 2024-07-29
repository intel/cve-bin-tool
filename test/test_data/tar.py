# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "tar", "version": "1.30", "version_strings": ["GNU tar\n1.30"]},
    {"product": "tar", "version": "1.35", "version_strings": ["1.35\nTAR_VERSION"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/t/",
        "package_name": "tar-1.35-2.fc40.aarch64.rpm",
        "product": "tar",
        "version": "1.35",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/t/tar/",
        "package_name": "tar_1.30+dfsg-6_amd64.deb",
        "product": "tar",
        "version": "1.30",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "tar_1.32-2_x86_64.ipk",
        "product": "tar",
        "version": "1.32",
    },
]
