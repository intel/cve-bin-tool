# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "hdf5",
        "version": "1.10.6",
        "version_strings": [
            "HDF5 library version: 1.10.6",
            "HDF5 Version: 1.10.6",
        ],
    }
]
package_test_data = [
    {
        "url": "https://download-ib01.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/h/",
        "package_name": "hdf5-1.10.5-4.el8.aarch64.rpm",
        "product": "hdf5",
        "version": "1.10.5",
        "other_products": ["gcc"],
    },
    {
        "url": "https://ftp.netbsd.org/pub/pkgsrc/packages/NetBSD/amd64/9.1/All/",
        "package_name": "hdf5-1.10.6.tgz",
        "product": "hdf5",
        "version": "1.10.6",
    },
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/h/",
        "package_name": "hdf5-1.10.6-5.fc34.x86_64.rpm",
        "product": "hdf5",
        "version": "1.10.6",
        "other_products": ["gcc"],
    },
    {
        "url": "http://ports.ubuntu.com/pool/universe/h/hdf5/",
        "package_name": "libhdf5-103-1_1.10.6+repack-2_arm64.deb",
        "product": "hdf5",
        "version": "1.10.6",
    },
]
