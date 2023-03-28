# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "flac", "version": "1.4.2", "version_strings": ["flac-1.4.2"]},
    {
        "product": "flac",
        "version": "1.3.0",
        "version_strings": ["reference libFLAC 1.3.0"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/f/",
        "package_name": "flac-1.4.2-1.fc38.aarch64.rpm",
        "product": "flac",
        "version": "1.4.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/f/flac/",
        "package_name": "libflac8_1.3.0-3_amd64.deb",
        "product": "flac",
        "version": "1.3.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libflac_1.3.3-1_x86_64.ipk",
        "product": "flac",
        "version": "1.3.3",
    },
]
