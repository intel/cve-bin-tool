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
import platform
import subprocess
import logging
import argparse
import textwrap
import threading
import pkg_resources
import multiprocessing
from collections import defaultdict

from .version import VERSION
from .util import DirWalk, inpath
from .extractor import Extractor
from .strings import Strings
from .file import is_binary
from .OutputEngine import OutputEngine

from .cvedb import CVEDB, OLD_CACHE_DIR
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

    def __init__(self, cvedb, checkers=None, logger=None):
        if logger is None:
            logger = LOGGER.getChild(self.__class__.__name__)
        # Load checkers if not given
        if checkers is None:
            checkers = self.load_checkers()
        self.cvedb = cvedb
        self.checkers = checkers
        self.logger = logger
        self.all_cves = defaultdict(dict)
        self.files_with_cve = 0
        # self.logger.info("Checkers loaded: %s" % (", ".join(self.checkers.keys())))

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
                    f"Docstring of {checker_name} checker does not define a vendor package pair"
                )
            checkers[checker_name] = (checker, vendor_package_pairs)
        return checkers

    @classmethod
    def available_checkers(cls):
        checkers = pkg_resources.iter_entry_points(cls.CHECKER_ENTRYPOINT)
        checker_list = [item.name for item in checkers]
        return checker_list

    def remove_skiplist(self, skips=None):
        # Take out any checkers that are on the skip list
        # (string of comma-delimited checker names)
        skiplist = skips.split(",") if skips else []
        for skipme in skiplist:
            if skipme in self.checkers:
                del self.checkers[skipme]
                self.logger.debug(f"Skipping checker: {skipme}")
            else:
                self.logger.error(f"Checker {skipme} is not a valid checker name")

    def print_checkers(self):
        self.logger.info(f'Checkers: {", ".join(self.checkers.keys())}')

    def get_cves(self, vendor_package_pairs, vers):
        """Returns a list of cves affecting a given version of a piece of software
        """
        cves = dict()

        # get all cves for each vendor_package_pair
        for vendor, package in vendor_package_pairs:
            cves.update(self.cvedb.get_cves(vendor, package, vers))

        return cves

    def scan_file(self, filename):
        """Scans a file to see if it contains any of the target libraries,
        and whether any of those contain CVEs"""

        self.logger.debug(f"Scanning file: {filename}")

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
                o = o.decode(sys.stdout.encoding)

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
            # do some magic so we can iterate over all results, even the ones that just return 1 hit
            if "is_or_contains" in result:
                results = [dict()]
                results[0] = result
            else:
                results = result

            for result in results:
                if "is_or_contains" in result:
                    modulename = result["modulename"]
                    version = "UNKNOWN"
                    if "version" in result and result["version"] != "UNKNOWN":
                        version = result["version"]
                    elif result["version"] == "UNKNOWN":
                        self.logger.warning(
                            f"{modulename} was detected with version UNKNOWN in file {filename}"
                        )
                    else:
                        self.logger.error(f"No version info for {modulename}")

                    if version != "UNKNOWN":
                        found_cves = self.get_cves(vendor_package_pairs, version)
                        if found_cves:
                            self.files_with_cve = self.files_with_cve + 1
                        self.all_cves[modulename][version] = found_cves
                        self.logger.info(
                            f'{filename} {result["is_or_contains"]} {modulename} {version}'
                        )
                        if found_cves.keys():
                            self.logger.info(f"Known CVEs in version {version}")
                            self.logger.info(", ".join(found_cves.keys()))

        self.logger.debug(f"Done scanning file: {filename}")
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
            LOGGER.warning(f"{filepath} is an archive. Pass -x option to auto-extract")
            return
        for filename in walker([ectx.extract(filepath)]):
            scan_and_or_extract_file(scanner, ectx, walker, should_extract, filename)


def extract_file(ectx, walker, should_extract, filepath, file_list):
    """ Extract files recursively if possible. """
    if ectx.can_extract(filepath):
        if not should_extract:
            file_list.append(filepath)
            LOGGER.warning(f"{filepath} is an archive. Pass -x option to auto-extract")
            return
        for filename in walker([ectx.extract(filepath)]):
            extract_file(ectx, walker, should_extract, filename, file_list)
    file_list.append(filepath)


def scan_files(scanning_file, args):
    cvedb = CVEDB()
    cvedb.open()
    if args["update"] != "never":
        cvedb.get_cvelist_if_stale()

    with cvedb:
        scanner = Scanner(cvedb)
        scanner.remove_skiplist(args["skips"])
        scanner.scan_file(scanning_file)
        return scanner.files_with_cve


def scan_files_unpack(unpacked):
    return scan_files(*unpacked)


def main(argv=None):
    """ Scan a binary file for certain open source libraries that may have CVEs """
    if argv is None:
        argv = sys.argv

    # Reset logger level to info
    LOGGER.setLevel(logging.INFO)

    parser = argparse.ArgumentParser(
        prog="cve-bin-tool",
        description=textwrap.dedent(
            """
            The CVE Binary Tool scans for a number of common, vulnerable open source
            components (openssl, libpng, libxml2, expat and a few others) to let you know
            if a given directory or binary file includes common libraries with known
            vulnerabilities.
            """
        ),
        epilog=textwrap.fill(
            f'Available checkers: {", ".join(Scanner.available_checkers())}'
        )
        + "\n\nPlease disclose issues responsibly!",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("directory", help="directory to scan")

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-q", "--quiet", action="store_true", help="suppress output"
    )
    output_group.add_argument(
        "-l",
        "--log",
        help="log level (default: info)",
        dest="log_level",
        action=LogAction,
        choices=["debug", "info", "warning", "error", "critical"],
    )
    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default=sys.stdout,
        help="provide output filename (default: output to stdout)",
    )
    output_group.add_argument(
        "-f",
        "--format",
        action="store",
        choices=["csv", "json", "console"],
        default="console",
        help="update output format (default: console)",
    )
    parser.add_argument(
        "-V", "--version", action="version", version=VERSION,
    )
    parser.add_argument(
        "-u",
        "--update",
        action="store",
        choices=["now", "daily", "never", "latest"],
        default="daily",
        help="update schedule for NVD database (default: daily)",
    )
    parser.add_argument(
        "-m", "--multithread", action="store_true", help="enable multithread"
    )
    parser.add_argument(
        "-x", "--extract", action="store_true", help="autoextract compressed files"
    )

    checker_group = parser.add_argument_group("Checkers")
    checker_group.add_argument(
        "-s",
        "--skips",
        dest="skips",
        action="store",
        type=str,
        help="comma-separated list of checkers to disable",
    )
    checker_group.add_argument(
        "-r",
        "--runs",
        dest="checkers",
        action="store",
        type=str,
        help="comma-separated list of checkers to enable",
    )

    if len(argv) <= 1:
        parser.print_help()
        return 0

    try:
        args = parser.parse_args(argv[1:])
    except SystemExit:
        # override default argparse exit(2) behaviour so positive numbers can indicate
        sys.exit(-2)

    if args.log_level:
        LOGGER.setLevel(args.log_level)

    if args.quiet:
        LOGGER.setLevel(logging.CRITICAL)

    if platform.system() != "Linux":
        warning_nolinux = """
                          **********************************************
                          Warning: this utility was developed for Linux.
                          You may need to install additional utilities
                          to use it on other operating systems.
                          **********************************************
                          """
        LOGGER.warning(warning_nolinux)

    if not os.path.isfile(args.directory) and not os.path.isdir(args.directory):
        LOGGER.error("Error: directory/file invalid")
        parser.print_usage()
        return -1

    exclude_folders = [".git"]
    walker = DirWalk(
        # pattern='*.*',
        # folder_include_pattern='*',
        folder_exclude_pattern=";".join(exclude_folders),
        # file_exclude_pattern=';'.join(exclude_files)
    ).walk

    # Connect to the database
    cvedb_orig = CVEDB()

    # if OLD_CACHE_DIR (from cvedb.py) exists, print warning
    if os.path.exists(OLD_CACHE_DIR):
        LOGGER.warning(
            f"Obsolete cache dir {OLD_CACHE_DIR} is no longer needed and can be removed."
        )

    # Clear data if -u now is set
    if args.update == "now":
        cvedb_orig.clear_cached_data()

    if args.update == "latest":
        cvedb_orig.refresh_cache_and_update_db()

    # update db if needed
    if args.update != "never":
        cvedb_orig.get_cvelist_if_stale()

    skips = ""
    if args.skips:
        skips = args.skips

    if args.checkers:
        checkers = args.checkers.split(",")
        skips = ",".join(
            map(
                lambda checker: checker.name,
                filter(
                    lambda checker: checker.name not in checkers,
                    pkg_resources.iter_entry_points("cve_bin_tool.checker"),
                ),
            )
        )

    # Single-thread mode
    if not args.multithread:
        # Close database when done
        cvedb = CVEDB()
        cvedb.open()
        with cvedb:
            extractor = Extractor()
            scanner = Scanner(cvedb)
            scanner.remove_skiplist(skips)
            LOGGER.info(scanner.print_checkers())

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

            LOGGER.info("")
            LOGGER.info("Overall CVE summary: ")
            LOGGER.info(
                f"There are {scanner.files_with_cve} files with known CVEs detected"
            )
            if scanner.files_with_cve > 0:
                affected_string = ", ".join(
                    map(
                        lambda module_version: "".join(str(module_version)),
                        scanner.affected(),
                    )
                )
                LOGGER.info(f"Known CVEs in {affected_string}:")

                # Creates a Object for OutputEngine
                output = OutputEngine(
                    modules=scanner.all_cves, filename=args.output_file
                )

                if not args.quiet or args.output_file != sys.stdout:
                    output.output_file(args.format)

            # Use the number of files with known cves as error code
            # as requested by folk planning to automate use of this script.
            # If no files found, then the program exits cleanly.
            return scanner.files_with_cve

    # Enable multithread
    else:

        def worker():
            cvedb = CVEDB()
            cvedb.open()
            with cvedb:
                scanner = Scanner(cvedb)
                scanner.remove_skiplist(skips)
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
