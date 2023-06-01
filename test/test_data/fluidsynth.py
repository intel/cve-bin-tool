# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "fluidsynth",
        "version": "2.3.2",
        "version_strings": ["FluidSynth executable version 2.3.2"],
    },
    {
        "product": "fluidsynth",
        "version": "1.1.11",
        "version_strings": ["1.1.11\nFluidSynth"],
    },
    {
        "product": "fluidsynth",
        "version": "1.1.11",
        "version_strings": ["fluidsynth-1.1.11"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/f/",
        "package_name": "fluidsynth-2.3.2-1.fc39.aarch64.rpm",
        "product": "fluidsynth",
        "version": "2.3.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/f/fluidsynth/",
        "package_name": "fluidsynth_1.1.11-1+deb10u1_amd64.deb",
        "product": "fluidsynth",
        "version": "1.1.11",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/f/fluidsynth/",
        "package_name": "libfluidsynth1_1.1.11-1+deb10u1_arm64.deb",
        "product": "fluidsynth",
        "version": "1.1.11",
    },
]
