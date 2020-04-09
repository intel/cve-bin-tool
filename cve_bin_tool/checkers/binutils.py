#!/usr/bin/python3

"""
CVE checker for binutils

References:
https://www.gnu.org/software/binutils/
https://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-6825/GNU-Binutils.html
"""
import re


def guess_version(lines):
    """ Guesses the binutils version from the file contents """
    new_guess = ""
    # below pattern is found across many distribution
    pattern1 = re.compile(r"libbfd-((\d+\.)*\d+)[\d\w.-]*so")

    for line in lines:
        match = pattern1.search(line)
        if match:
            new_guess2 = match.group(1).strip()
            if len(new_guess2) > len(new_guess):
                new_guess = new_guess2

    # check if new_guess actually found some version
    if len(new_guess) > 0:
        return new_guess
    else:
        return "UNKNOWN"


def guess_contains(lines):
    """
    Tries to determine if a file includes binutils.
    Since binutils is actually collection of different utils we'll try to include strings
    for all of them.
    """
    signatures = [
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
        r"can't set BFD default target to `%s': %s"
        # strip - Discards symbols.
        # windmc - A Windows compatible message compiler.
        # windres - A compiler for Windows resource files.
    ]

    for line in lines:
        for signature in signatures:
            pattern = re.compile(signature)
            if pattern.search(line):
                return 1
    return 0


def get_version(lines, filename):
    """returns version information for binutiles as found in a given file.

    VPkg: gnu, binutils
    """
    version_info = dict()

    util_names = [
        # command line utils
        "ld",  # the GNU linker.
        "as",  # the GNU assembler.
        "addr2line",  # Converts addresses into filenames and line numbers.
        "ar",  # A utility for creating, modifying and extracting from archives.
        "c++filt",  # Filter to demangle encoded C++ symbols.
        "dlltool",  # Creates files for building and using DLLs.
        "gold",  # A new, faster, ELF only linker, still in beta test.
        "gprof",  # Displays profiling information.
        "nlmconv",  # Converts object code into an NLM.
        "nm",  # Lists symbols from object files.
        "objcopy",  # Copies and translates object files.
        "objdump",  # Displays information from object files.
        "ranlib",  # Generates an index to the contents of an archive.
        "readelf",  # Displays information from any ELF format object file.
        "size",  # Lists the section sizes of an object or archive file.
        "strings",  # Lists printable strings from files.
        "strip",  # Discards symbols.
        "windmc",  # A Windows compatible message compiler.
        "windres",  # A compiler for Windows resource files.
        # distro-specific names
        "ld.bfd",  # as seen on ubuntu
    ]

    # check if it's the library instead of the command line utils
    lib_pattern = re.compile(r"libbfd-((\d+\.)*\d+)[\d\w.-]*so")
    if lib_pattern.match(filename):
        version_info["is_or_contains"] = "is"

    for name in util_names:
        if name in filename:
            version_info["is_or_contains"] = "is"

    if "is_or_contains" not in version_info:
        # then guess
        if guess_contains(lines):
            version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "binutils"
        version_info["version"] = guess_version(lines)

    return version_info
