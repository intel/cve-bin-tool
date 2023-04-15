# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "acpid", "version": "2.0.34", "version_strings": ["acpid-2.0.34"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/openmandriva/cooker/repository/aarch64/main/release/",
        "package_name": "acpid-2.0.34-1-omv4090.aarch64.rpm",
        "product": "acpid2",
        "version": "2.0.34",
    },
    {
        "url": "http://rpmfind.net/linux/openmandriva/cooker/repository/x86_64/main/release/",
        "package_name": "acpid-2.0.34-1-omv4090.x86_64.rpm",
        "product": "acpid2",
        "version": "2.0.34",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/a/acpid/",
        "package_name": "acpid_2.0.23-2_amd64.deb",
        "product": "acpid2",
        "version": "2.0.23",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/a/acpid/",
        "package_name": "acpid_2.0.23-2_armel.deb",
        "product": "acpid2",
        "version": "2.0.23",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "acpid_2.0.30-1_x86_64.ipk",
        "product": "acpid2",
        "version": "2.0.30",
    },
]
