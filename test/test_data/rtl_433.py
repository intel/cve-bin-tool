# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "rtl_433", "version": "21.12", "version_strings": ["rtl_433-21.12"]},
    {"product": "rtl_433", "version": "20.11", "version_strings": ["rtl-433-20.11"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "rtl_433-21.12-2.4.aarch64.rpm",
        "product": "rtl_433",
        "version": "21.12",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/r/rtl-433/",
        "package_name": "rtl-433_20.11-1_amd64.deb",
        "product": "rtl_433",
        "version": "20.11",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "rtl_433_20.02-1_x86_64.ipk",
        "product": "rtl_433",
        "version": "20.02",
    },
]
