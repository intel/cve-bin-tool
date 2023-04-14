# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "samba", "version": "4.10.2", "version_strings": ["SAMBA_4.10.2"]},
    {"product": "samba", "version": "3.6.22", "version_strings": ["samba/3.6.22"]},
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/samba/4.10.4/0.fc30/x86_64/",
        "package_name": "samba-4.10.4-0.fc30.x86_64.rpm",
        "product": "samba",
        "version": "4.10.4",
    },
    {
        "url": "http://www.rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/s/",
        "package_name": "samba-4.13.3-1.fc34.aarch64.rpm",
        "product": "samba",
        "version": "4.13.3",
    },
]
