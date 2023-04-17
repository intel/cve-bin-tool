# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "kerberos_5",
        "version": "1.15.1",
        "version_strings": [
            "An unknown option was passed in to kerberos",
            "CLIENT kerberos 5-1.15.1",
            "KRB5_BRAND: ",
        ],
    },
    {
        "product": "kerberos_5",
        "version": "1.15.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1",
        "version_strings": [
            "An unknown option was passed in to kerberos",
            "CLIENT kerberos 5-1.15.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1",
            "KRB5_BRAND: ",
        ],
    },
]
package_test_data = [
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "krb5-libs-1.15.1-50.el7.x86_64.rpm",
        "product": "kerberos_5",
        "version": "1.15.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/k/krb5/",
        "package_name": "libkrb5-3_1.12.1+dfsg-19+deb8u4_amd64.deb",
        "product": "kerberos_5",
        "version": "1.12.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "krb5-libs_1.17-2_x86_64.ipk",
        "product": "kerberos_5",
        "version": "1.17",
    },
]
