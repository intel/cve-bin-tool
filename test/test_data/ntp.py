# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "ntp",
        "version": "4.2.8p15",
        "version_strings": [
            "ntpd 4.2.8p15",
            "ntpdate 4.2.8p15",
            "ntpdc 4.2.8p15",
            "ntpq 4.2.8p15",
        ],
    },
    {
        "product": "ntp",
        "version": "4.2.6p5",
        "version_strings": [
            "ntpd 4.2.6p5",
            "ntpdate 4.2.6p5",
            "ntpdc 4.2.6p5",
            "ntpq 4.2.6p5",
        ],
    },
]
package_test_data = [
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/33/Everything/x86_64/os/Packages/n/",
        "package_name": "ntp-4.2.8p15-3.fc33.x86_64.rpm",
        "product": "ntp",
        "version": "4.2.8p15",
    },
    {
        "url": "https://rpmfind.net/linux/mageia/distrib/5/x86_64/media/core/release/",
        "package_name": "ntp-4.2.6p5-24.mga5.x86_64.rpm",
        "product": "ntp",
        "version": "4.2.6p5",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "ntpdate_4.2.8p15-1_x86_64.ipk",
        "product": "ntp",
        "version": "4.2.8p15",
    },
]
