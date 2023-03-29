# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "openldap",
        "version": "2.4.37",
        "version_strings": ["ldapsearch 2.4.37"],
    },
    {
        "product": "openldap",
        "version": "2.4.48",
        "version_strings": ["OpenLDAP: slapd 2.4.48"],
    },
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/openldap/2.4.34/1.fc18/x86_64/",
        "package_name": "openldap-clients-2.4.34-1.fc18.x86_64.rpm",
        "product": "openldap",
        "version": "2.4.34",
    },
    {
        "url": "https://mirrors.kernel.org/mageia/distrib/5/x86_64/media/core/release/",
        "package_name": "openldap-clients-2.4.40-3.mga5.x86_64.rpm",
        "product": "openldap",
        "version": "2.4.40",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "openldap-server_2.4.48-1_x86_64.ipk",
        "product": "openldap",
        "version": "2.4.48",
    },
]
