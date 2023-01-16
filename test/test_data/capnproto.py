# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "capnproto", "version": "0.5.3", "version_strings": ["libcapnp-0.5.3"]},
    {
        "product": "capnproto",
        "version": "0.10.3",
        "version_strings": ["Cap'n Proto version 0.10.3"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/c/",
        "package_name": "capnproto-0.10.3-1.fc38.aarch64.rpm",
        "product": "capnproto",
        "version": "0.10.3",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/c/capnproto/",
        "package_name": "libcapnp-0.5.3_0.5.3-2_amd64.deb",
        "product": "capnproto",
        "version": "0.5.3",
    },
]
