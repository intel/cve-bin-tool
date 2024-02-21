# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "exfatprogs",
        "version": "1.1.0",
        "version_strings": ["1.1.0\nexfatprogs version : %s"],
    }
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/e/",
        "package_name": "exfatprogs-1.2.2-1.fc40.aarch64.rpm",
        "product": "exfatprogs",
        "version": "1.2.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/e/exfatprogs/",
        "package_name": "exfatprogs_1.1.0-1_amd64.deb",
        "product": "exfatprogs",
        "version": "1.1.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/21.02.0/packages/x86_64/packages/",
        "package_name": "exfat-fsck_1.1.3-1_x86_64.ipk",
        "product": "exfatprogs",
        "version": "1.1.3",
    },
]
