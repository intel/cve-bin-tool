# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "zabbix", "version": "4.0.4", "version_strings": ["Zabbix 4.0.4"]},
    {"product": "zabbix", "version": "4.0.37", "version_strings": ["4.0.37\nZabbix"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/z/",
        "package_name": "zabbix-6.0.13-2.fc39.aarch64.rpm",
        "product": "zabbix",
        "version": "6.0.13",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/z/zabbix/",
        "package_name": "zabbix-server-mysql_4.0.4+dfsg-1_amd64.deb",
        "product": "zabbix",
        "version": "4.0.4",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "zabbix-server_4.0.37-1_x86_64.ipk",
        "product": "zabbix",
        "version": "4.0.37",
    },
]
