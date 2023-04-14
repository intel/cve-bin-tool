# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "freerdp", "version": "2.8.1", "version_strings": ["FreeRDP-2.8.1"]},
    {"product": "freerdp", "version": "2.2.0", "version_strings": ["freerdp2-2.2.0"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/openmandriva/cooker/repository/aarch64/main/release/",
        "package_name": "freerdp-2.8.1-2-omv4090.aarch64.rpm",
        "product": "freerdp",
        "version": "2.8.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/f/freerdp2/",
        "package_name": "libfreerdp-client2-2_2.0.0~git20190204.1.2693389a%2Bdfsg1-1~bpo9%2B1_amd64.deb",
        "product": "freerdp",
        "version": "2.0.0",
    },
]
