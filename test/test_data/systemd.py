# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "systemd",
        "version": "239",
        "version_strings": ["systemd 239", "sd_bus_error_copy"],
    }
]
package_test_data = [
    {
        "url": "http://mirror.centos.org/centos/8/BaseOS/x86_64/os/Packages/",
        "package_name": "systemd-239-40.el8.i686.rpm",
        "product": "systemd",
        "version": "239",
    },
    {
        "url": "http://security.ubuntu.com/ubuntu/pool/main/s/systemd/",
        "package_name": "systemd_229-4ubuntu21.27_amd64.deb",
        "product": "systemd",
        "version": "229",
    },
    {
        "url": "https://rpmfind.net/linux/openmandriva/4.1/repository/x86_64/main/release/",
        "package_name": "systemd-244.20191203-2-omv4001.x86_64.rpm",
        "product": "systemd",
        "version": "244",
    },
    {
        "url": "https://rpmfind.net/linux/fedora/linux/releases/33/Everything/x86_64/os/Packages/s/",
        "package_name": "systemd-246.6-3.fc33.i686.rpm",
        "product": "systemd",
        "version": "246",
    },
    # Below is the package with multiple systemd versions present
    {
        "url": "https://github.com/intel/cve-bin-tool/files/6452330/",
        "package_name": "libsystemd.tar.gz",
        "product": "systemd",
        "version": "246",
    },
]
