#!/usr/bin/python3
# pylint: disable=invalid-name, useless-object-inheritance
# useless-object-inheritance kept for python2 compatibility

"""
This tool scans for a number of common, vulnerable open source components
(openssl, libpng, libxml2, expat and a few others) to let you know if your
system includes common libraries with known vulnerabilities.  It emits a list
of CVE numbers that may be relevant to your binary based on the versions.  It
cannot detect backported fixes.
"""

# Python 2 compatibility stuff
from __future__ import print_function
import sys
import os
import csv
import glob
import platform
import subprocess
import logging
import argparse
import threading
import pkg_resources
import multiprocessing

from .util import DirWalk, inpath
from .extractor import Extractor
from .strings import Strings
from .file import is_binary
from .NVDAutoUpdate import NVDSQLite
from .log import LOGGER

try:
    import queue
except ImportError:
    import Queue as queue


class InvalidFileError(Exception):
    """ Filepath is invalid for scanning."""

    # pass


class Scanner(object):
    """"Scans files for CVEs using CVE checkers"""

    CHECKER_ENTRYPOINT = "cve_bin_tool.checker"

    def __init__(self, nvd, checkers=None, verbose=True, logger=None):
        if logger is None:
            logger = LOGGER.getChild(self.__class__.__name__)
        # Load checkers if not given
        if checkers is None:
            checkers = self.load_checkers()
        self.nvd = nvd
        self.checkers = checkers
        self.logger = logger
        self.verbose = verbose
        self.all_cves = {}
        self.files_with_cve = 0
        self.logger.info("Checkers loaded: %s", ", ".join(self.checkers.keys()))

    @staticmethod
    def vendor_package_pairs(docstring):
        """Generator yielding each instance of a vendor name, package name pair
        in a checkers docstring"""
        for line in docstring.split("\n"):
            if line.strip().startswith("VPkg:"):
                yield tuple(
                    map(lambda x: x.strip(), line.replace("VPkg:", "").split(","))
                )

    @classmethod
    def load_checkers(cls):
        """ Loads CVE checkers """
        checkers = dict(
            map(
                lambda checker: (checker.name, checker.load()),
                pkg_resources.iter_entry_points(cls.CHECKER_ENTRYPOINT),
            )
        )

        for checker_name, checker in checkers.items():
            vendor_package_pairs = list(cls.vendor_package_pairs(checker.__doc__))
            if not vendor_package_pairs:
                raise ValueError(
                    "Docstring of %r checker" % (checker_name)
                    + " does not define a vendor package pair"
                )
            checkers[checker_name] = (checker, vendor_package_pairs)
        return checkers

    @classmethod
    def available_checkers(cls):
        checkers = pkg_resources.iter_entry_points(cls.CHECKER_ENTRYPOINT)
        checker_list = [item.name for item in checkers]
        return checker_list

    def remove_skiplist(self, skips=None, quiet=False):
        # Take out any checkers that are on the skip list
        # (string of comma-delimited checker names)
        skiplist = skips.split(",") if skips else []
        for skipme in skiplist:
            if skipme in self.checkers:
                del self.checkers[skipme]
                if not quiet:
                    print("Skipping checker: {}".format(skipme))
            else:
                if not quiet:
                    print("Checker {} is not a valid checker name".format(skipme))

    def print_checkers(self):
        print("Checkers: {}".format(", ".join(self.checkers.keys())))

    def get_cves(self, vendor_package_pairs, vers):
        """Returns a list of cves affecting a given version of a piece of software
        """
        cves_by_version = dict()
        for row in self.nvd.get_cves(*vendor_package_pairs):
            for ver in [ver.strip() for ver in row.version.split(",")]:
                if not ver in cves_by_version:
                    cves_by_version[ver] = {}
                cves_by_version[ver][row.number] = row
        # `-` version is all versions are affected. Aka no patch
        grab_all = {}
        grab_all.update(cves_by_version.get("-", {}))
        grab_all.update(cves_by_version.get(vers, {}))
        return grab_all

    def scan_file(self, filename):
        """Scans a file to see if it contains any of the target libraries,
        and whether any of those contain CVEs"""

        self.logger.debug("Scanning file: %r", filename)

        # Do not try to scan symlinks
        if os.path.islink(filename):
            return None

        # Ensure filename is a file
        if not os.path.isfile(filename):
            raise InvalidFileError(filename)

        # step 1: check if it's an ELF binary file
        if inpath("file"):
            # use system file if available (for performance reasons)
            o = subprocess.check_output(["file", filename])
            if sys.version_info.major == 3:
                o = o.decode("utf-8")

            if "cannot open" in o:
                raise InvalidFileError(filename)

            if (
                ("LSB " not in o)
                and ("LSB shared" not in o)
                and ("LSB executable" not in o)
                and ("PE32 executable" not in o)
                and ("PE32+ executable" not in o)
                and ("Mach-O" not in o)
            ):
                return None
        else:
            # otherwise use python implementation of file
            if not is_binary(filename):
                return None
        # parse binary file's strings
        o = []
        if inpath("strings"):
            # use "strings" on system if available (for performance)
            o = subprocess.check_output(["strings", filename])
            if sys.version_info.major == 3:
                o = o.decode("utf-8")
        else:
            # Otherwise, use python implementation
            s = Strings(filename)
            o = s.parse()
        lines = o.split("\n")

        # tko
        for (
            dummy_checker_name,
            (get_version, vendor_package_pairs),
        ) in self.checkers.items():
            result = get_version(lines, filename)
            if "is_or_contains" in result:
                modulename, version = result["modulename"], result["version"]
                found_cves = self.get_cves(vendor_package_pairs, version)
                if found_cves.keys():
                    self.files_with_cve = self.files_with_cve + 1
                if not modulename in self.all_cves:
                    self.all_cves[modulename] = {}
                self.all_cves[modulename][version] = found_cves
                if self.verbose:
                    print(filename, result["is_or_contains"], modulename, version)
                    if found_cves.keys():
                        print("Known CVEs in version " + version)
                        print(", ".join(found_cves.keys()))

        self.logger.debug("Done scanning file: %r", filename)
        return self.all_cves

    def extract_and_scan(self, filename, walker=None):
        # make a directory walker if it's set to None
        if walker is None:
            exclude_folders = [".git"]
            walker = DirWalk(folder_exclude_pattern=";".join(exclude_folders)).walk

        # Scan the file
        self.scan_file(filename)

        # Attempt to extract the file and scan the contents
        with Extractor()() as ectx:
            if ectx.can_extract(filename):
                for extracted_file in walker([ectx.extract(filename)]):
                    self.extract_and_scan(extracted_file, walker)

        return self.all_cves

    def affected(self):
        """ Returns list of module name and version tuples identified from
        scan"""
        return [
            (modulename, version)
            for modulename, versions in self.all_cves.items()
            for version in versions.keys()
        ]


class LogAction(argparse.Action):
    """ Argparse action for selecting logging level."""

    def __call__(self, parser, namespace, value, option_string=None):
        """ Turns string into logging level definition."""
        setattr(namespace, self.dest, getattr(logging, value.upper(), logging.WARNING))


def scan_and_or_extract_file(scanner, ectx, walker, should_extract, filepath):
    """ Runs extraction if possible and desired otherwise scans."""
    # Scan the file
    scanner.scan_file(filepath)
    # Attempt to extract the file and scan the contents
    if ectx.can_extract(filepath):
        if not should_extract:
            print("%s is an archive. Pass " % (filepath,) + "-x option to auto-extract")
            return
        for filename in walker([ectx.extract(filepath)]):
            scan_and_or_extract_file(scanner, ectx, walker, should_extract, filename)


def extract_file(ectx, walker, should_extract, filepath, file_list):
    """ Extract files recursively if possible. """
    if ectx.can_extract(filepath):
        if not should_extract:
            file_list.append(filepath)
            print("%s is an archive. Pass " % (filepath,) + "-x option to auto-extract")
            return
        for filename in walker([ectx.extract(filepath)]):
            extract_file(ectx, walker, should_extract, filename, file_list)
    file_list.append(filepath)


def scan_files(scanning_file, args):
    nvd = NVDSQLite(quiet=args["quiet"])
    if args["update"] != "never":
        nvd.get_cvelist_if_stale()
    with nvd:
        scanner = Scanner(nvd, verbose=args["verbose"])
        scanner.remove_skiplist(args["skips"], args["quiet"])
        scanner.scan_file(scanning_file)
        return scanner.files_with_cve


def scan_files_unpack(unpacked):
    return scan_files(*unpacked)


def output_cves(outfile, modules, include_details=False):
    """ Output a list of CVEs """
    writer = csv.writer(outfile)
    for modulename, versions in modules.items():
        for version, cves in versions.items():
            for dummy_number, cve in cves.items():
                row = [modulename, version, cve.number, cve.severity]
                if include_details:
                    # TODO Include description in import from NVD jsons
                    # row.append(cve.description)
                    pass
                writer.writerow(row)


def main(argv=sys.argv, outfile=sys.stdout):
    """ Scan a binary file for certain open source libraries that may have CVEs """
    parser = argparse.ArgumentParser(
        prog="cve-bin-tool",
        description="The CVE Binary Tool scans for a number of common, vulnerable open source components (openssl, libpng, libxml2, expat and a few others) to let you know if a given directory or binary file includes common libraries with known vulnerabilities.",
        epilog="Available Checkers: {} \n Please disclose issues responsibly!".format(
            ", ".join(Scanner.available_checkers())
        ),
    )
    parser.add_argument("directory", help="directory to scan")
    parser.add_argument(
        "-x", "--extract", action="store_true", help="autoextract compressed files"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="details on found issues as script runs",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress output")
    parser.add_argument(
        "-l",
        "--log",
        help="log level",
        dest="log_level",
        action=LogAction,
        choices=["debug", "info", "warning", "error", "critical"],
    )
    parser.add_argument(
        "-s",
        "--skips",
        dest="skips",
        action="store",
        type=str,
        help="comma-separated list of checkers to disable",
    )
    parser.add_argument(
        "-m", "--multithread", action="store_true", help="enable multithread"
    )

    parser.add_argument(
        "-u",
        "--update",
        action="store",
        choices=["now", "daily", "never"],
        default="daily",
        help="update schedule for NVD database. Default is daily.",
    )

    if len(argv) <= 1:
        parser.print_help()
        return 0

    try:
        args = parser.parse_args(argv[1:])
    except SystemExit:
        # override default argparse exit(2) behaviour so positive numbers can indicate
        # number of cves (useful in quiet mode)
        sys.exit(-2)

    logging.basicConfig(level=args.log_level)

    if platform.system() != "Linux":
        warning_nolinux = """
                          **********************************************
                          Warning: this utility was developed for Linux.
                          You may need to install additional utilities
                          to use it on other operating systems.
                          **********************************************
                          """
        print(warning_nolinux)

    if not os.path.isfile(args.directory) and not os.path.isdir(args.directory):
        print("Error: directory/file invalid")
        parser.print_usage()
        return -1

    exclude_folders = [".git"]
    walker = DirWalk(
        # pattern='*.*',
        # folder_include_pattern='*',
        folder_exclude_pattern=";".join(exclude_folders),
        # file_exclude_pattern=';'.join(exclude_files)
    ).walk

    if args.update == "now":
        if not args.quiet:
            print("Removing all cached CVE data.")
        NVDSQLite.clear_cached_data()

    # Single-thread mode
    if not args.multithread:
        # Close database when done
        nvd = NVDSQLite(quiet=args.quiet)
        # Update CVE database
        if args.update != "never":
            if not args.quiet:
                print("Updating CVE data. This will take a few minutes.")
            nvd.get_cvelist_if_stale()
        with nvd:
            extractor = Extractor()
            scanner = Scanner(nvd, verbose=args.verbose)
            scanner.remove_skiplist(args.skips, args.quiet)
            if args.verbose:
                scanner.print_checkers()

            with extractor() as ectx:
                if os.path.isdir(args.directory):
                    for filepath in walker([args.directory]):
                        scan_and_or_extract_file(
                            scanner, ectx, walker, args.extract, filepath
                        )
                elif os.path.isfile(args.directory):
                    scan_and_or_extract_file(
                        scanner, ectx, walker, args.extract, args.directory
                    )

            if not args.quiet:
                print("")
                print("Overall CVE summary: ")
                print(
                    "There are",
                    scanner.files_with_cve,
                    "files with known CVEs detected",
                )
            if (not args.quiet) and scanner.files_with_cve > 0:
                affected_string = ", ".join(
                    map(
                        lambda module_version: " ".join(module_version),
                        scanner.affected(),
                    )
                )
                print("Known CVEs in %s:" % (affected_string,))
                output_cves(outfile, scanner.all_cves, include_details=args.verbose)

            # Use the number of files with known cves as error code
            # as requested by folk planning to automate use of this script.
            # If no files found, then the program exits cleanly.
            return scanner.files_with_cve

    # Enable multithread
    else:

        def worker():
            nvd = NVDSQLite(quiet=args.quiet)
            if args.update != "never":
                nvd.get_cvelist_if_stale()
            with nvd:
                scanner = Scanner(nvd, verbose=args.verbose)
                scanner.remove_skiplist(args.skips, args.quiet)
                while True:
                    scan_target = q.get()
                    if not scan_target:
                        q.task_done()
                        break
                    scanner.scan_file(scan_target)
                    q.task_done()
                cves.put(scanner.files_with_cve)

        # using queue
        q = queue.Queue()
        cves = queue.Queue()
        # Extract all files first, save the path to a list
        extractor = Extractor()
        file_list = []
        with extractor() as ectx:
            if os.path.isdir(args.directory):
                for filepath in walker([args.directory]):
                    extract_file(ectx, walker, args.extract, filepath, file_list)
            elif os.path.isfile(args.directory):
                extract_file(ectx, walker, args.extract, args.directory, file_list)
            binary_list = []

            pool = multiprocessing.Pool(multiprocessing.cpu_count() * 4)
            try:
                for i, file_is_binary in enumerate(pool.map(is_binary, file_list)):
                    if file_is_binary:
                        binary_list.append(file_list[i])

                # Get all of the binary files
                scanning_list = binary_list if binary_list else file_list
                if len(scanning_list) == 1:
                    return scan_files(scanning_list[0], vars(args))

                # create threads
                threads = []
                for i in range(multiprocessing.cpu_count() * 4):
                    t = threading.Thread(target=worker)
                    t.start()
                    threads.append(t)
                for scanning_target in scanning_list:
                    q.put(scanning_target)

                for i in range(multiprocessing.cpu_count() * 4):
                    q.put(None)

                # wait until all works done
                q.join()

                for t in threads:
                    t.join()

                cve_list = []

                while not cves.empty():
                    cve_list.append(cves.get())

                return cve_list

            finally:
                pool.terminate()
                pool.join()


if __name__ == "__main__":
    sys.exit(main())
