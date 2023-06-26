# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libgd",
        "version": "2.2.5",
        "version_strings": ["gd-tga: premature end of image data\n2.2.5"],
    }
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/mageia/distrib/cauldron/armv7hl/media/core/release/",
        "package_name": "libgd3-2.3.3-6.mga9.armv7hl.rpm",
        "product": "libgd",
        "version": "2.3.3",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libg/libgd2/",
        "package_name": "libgd3_2.2.5-5.2_amd64.deb",
        "product": "libgd",
        "version": "2.2.5",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libgd_2.2.5-2_x86_64.ipk",
        "product": "libgd",
        "version": "2.2.5",
    },
]
