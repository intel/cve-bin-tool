# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "kodi", "version": "17.1", "version_strings": ["kodi-17.1"]},
    {"product": "xbmc", "version": "20.1", "version_strings": ["xbmc-20.1"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/mageia/distrib/cauldron/aarch64/media/core/release/",
        "package_name": "kodi-20.1-2.mga9.aarch64.rpm",
        "product": "kodi",
        "version": "20.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/k/kodi/",
        "package_name": "kodi-bin_17.1+dfsg1-3_amd64.deb",
        "product": "kodi",
        "version": "17.1",
    },
]
