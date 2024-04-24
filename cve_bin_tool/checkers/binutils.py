# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for binutils

References:
https://www.gnu.org/software/binutils/
https://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-6825/GNU-Binutils.html
"""

from cve_bin_tool.checkers import Checker


class BinutilsChecker(Checker):
    CONTAINS_PATTERNS = [
        # for all programs - special alternate for ubuntu
        r"\(GNU Binutils\) ",
        r"\(GNU Binutils for Ubuntu\) ",
        # bfd
        r"Auxiliary filter for shared object symbol table",
        # ld - the GNU linker.
        r"Do not copy DT_NEEDED links mentioned inside DSOs that follow",
        r"%F%P:%S: error: memory region `%s' for alias `%s' does not exist",
        # as - the GNU assembler.
        r"can't mix positional and keyword arguments",
        r".bundle_lock sequence at %u bytes but .bundle_align_mode limit is %u bytes",
        # addr2line - Converts addresses into filenames and line numbers.
        r"%s: error: too many @-files encountered",
        r"Warning: '%s' has negative size, probably it is too large",
        # ar - A utility for creating, modifying and extracting from archives.
        r"Cannot convert existing library %s to thin format",
        # c++filt - Filter to demangle encoded C++ symbols.
        r"Internal error: no symbol alphabet for current style",
        # dlltool - Creates files for building and using DLLs.
        # gold - A new, faster, ELF only linker, still in beta test.
        r"restart link with --incremental-full",
        # gprof - Displays profiling information.
        r"%s: gmon.out file is missing histogram",
        # nlmconv - Converts object code into an NLM.
        # nm - Lists symbols from object files.
        r"Using the --size-sort and --undefined-only options together",
        # objcopy - Copies and translates object files.
        r"alloc, load, noload, readonly, debug, code, data, rom, share, contents, merge, strings",
        # objdump - Displays information from object files.
        # ranlib - Generates an index to the contents of an archive.
        # readelf - Displays information from any ELF format object file.
        # size - Lists the section sizes of an object or archive file.
        # strings - Lists printable strings from files.
        r"can't set BFD default target to `%s': %s",
        # strip - Discards symbols.
        # windmc - A Windows compatible message compiler.get_ver
        # windres - A compiler for Windows resource files.
    ]
    FILENAME_PATTERNS = [
        # check if it's the library instead of the command line utils
        r"libbfd-((\d+\.)*\d+)[\d\w.-]*so",
        # command line utils
        r"^ld$",  # the GNU linker.
        r"^as$",  # the GNU assembler.
        r"addr2line",  # Converts addresses into filenames and line numbers.
        r"^ar$",  # A utility for creating, modifying and extracting from archives.
        r"c\+{2}filt",  # Filter to demangle encoded C++ symbols.
        r"dlltool",  # Creates files for building and using DLLs.
        r"^gold$",  # A new, faster, ELF only linker, still in beta test.
        r"gprof",  # Displays profiling information.
        r"nlmconv",  # Converts object code into an NLM.
        r"^nm$",  # Lists symbols from object files.
        r"objcopy",  # Copies and translates object files.
        r"objdump",  # Displays information from object files.
        r"ranlib",  # Generates an index to the contents of an archive.
        r"readelf",  # Displays information from any ELF format object file.
        r"^size$",  # Lists the section sizes of an object or archive file.
        r"^strings$",  # Lists printable strings from files.
        r"^strip$",  # Discards symbols.
        r"windmc",  # A Windows compatible message compiler.
        r"windres",  # A compiler for Windows resource files.
        # distro-specific names
        r"ld.bfd",  # as seen on ubuntu
    ]
    VERSION_PATTERNS = [
        r"GNU Binutils[a-zA-Z ]*\) ([0-9]+\.[0-9]+\.?[0-9]*)",
        r"BFD header file version %s\r?\nversion ([0-9]+\.[0-9]+\.?[0-9]*)",
    ]
    VENDOR_PRODUCT = [("gnu", "binutils")]
