# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libvirt",
        "version": "1.2.3",
        "version_strings": ["LIBVIRT_PRIVATE_1.2.3"],
    },
    {
        "product": "libvirt",
        "version": "1.2.9",
        "version_strings": ["libvirt version: 1.2.9"],
    },
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/libvirt/1.2.2/1.fc21/x86_64/",
        "package_name": "libvirt-client-1.2.2-1.fc21.x86_64.rpm",
        "product": "libvirt",
        "version": "1.2.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libv/libvirt/",
        "package_name": "libvirt0_1.2.9-9+deb8u5_amd64.deb",
        "product": "libvirt",
        "version": "1.2.9",
    },
]
