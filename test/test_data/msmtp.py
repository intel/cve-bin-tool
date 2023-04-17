# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "msmtp",
        "version": "1.6.6",
        "version_strings": ["msmtp\n%s version %s\n1.6.6"],
    },
    {"product": "msmtp", "version": "1.8.19", "version_strings": ["msmtp\n1.8.19"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/m/",
        "package_name": "msmtp-1.8.22-4.fc38.aarch64.rpm",
        "product": "msmtp",
        "version": "1.8.22",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/m/msmtp/",
        "package_name": "msmtp_1.6.6-1_amd64.deb",
        "product": "msmtp",
        "version": "1.6.6",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "msmtp_1.8.19-1_x86_64.ipk",
        "product": "msmtp",
        "version": "1.8.19",
    },
]
