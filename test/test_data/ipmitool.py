# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "ipmitool",
        "version": "1.8.19",
        "version_strings": ["1.8.19\n%s version %s\nIPMI_KGKEY"],
    }
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/i586/tumbleweed/repo/oss/i586/",
        "package_name": "ipmitool-1.8.19.0.g19d7878-1.2.i586.rpm",
        "product": "ipmitool",
        "version": "1.8.19",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/i/ipmitool/",
        "package_name": "ipmitool_1.8.14-4_amd64.deb",
        "product": "ipmitool",
        "version": "1.8.14",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "ipmitool_1.8.18-4_x86_64.ipk",
        "product": "ipmitool",
        "version": "1.8.18",
    },
]
