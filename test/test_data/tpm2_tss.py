# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "tpm2_software_stack",
        "version": "3.0.3",
        "version_strings": ["tpm2-tss 3.0.3"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/t/",
        "package_name": "tpm2-tss-3.2.0-3.fc37.aarch64.rpm",
        "product": "tpm2_software_stack",
        "version": "3.2.0",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/t/",
        "package_name": "tpm2-tss-3.2.0-3.fc37.i686.rpm",
        "product": "tpm2_software_stack",
        "version": "3.2.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/t/tpm2-tss/",
        "package_name": "libtss2-fapi1_3.0.3-2_amd64.deb",
        "product": "tpm2_software_stack",
        "version": "3.0.3",
    },
]
