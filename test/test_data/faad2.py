# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "freeware_advanced_audio_decoder_2",
        "version": "2.10.1",
        "version_strings": [
            "faad-2.10.1",
        ],
    },
    {
        "product": "freeware_advanced_audio_decoder_2",
        "version": "2.8.6",
        "version_strings": [
            "TAG\n2.8.6\n Copyright 2002-2004: Ahead Software AG",
        ],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/openmandriva/cooker/repository/aarch64/restricted/release/",
        "package_name": "faad2-2.10.1-2-omv4090.aarch64.rpm",
        "product": "freeware_advanced_audio_decoder_2",
        "version": "2.10.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/f/faad2/",
        "package_name": "libfaad2_2.10.0-1_amd64.deb",
        "product": "freeware_advanced_audio_decoder_2",
        "version": "2.10.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/18.06.1/packages/x86_64/packages/",
        "package_name": "libfaad2_2.8.6-1_x86_64.ipk",
        "product": "freeware_advanced_audio_decoder_2",
        "version": "2.8.6",
    },
]
