# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "hostapd", "version": "2.4", "version_strings": ["hostapd v2.4"]},
    {
        "product": "hostapd",
        "version": "2.10",
        "version_strings": ["2.10-devel\nhostapd v"],
    },
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/hostapd/2.3/1.fc20/x86_64/",
        "package_name": "hostapd-2.3-1.fc20.x86_64.rpm",
        "product": "hostapd",
        "version": "2.3",
    },
    {
        "url": "http://security.ubuntu.com/ubuntu/pool/universe/w/wpa/",
        "package_name": "hostapd_2.1-0ubuntu1.7_amd64.deb",
        "product": "hostapd",
        "version": "2.1",
    },
]
