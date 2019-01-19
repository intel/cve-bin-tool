#!/usr/bin/python3
# pylint: disable=invalid-name

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
import re
import logging
import argparse
import pkg_resources
from collections import namedtuple

from .util import DirWalk
from .extractor import Extractor
from .NVDAutoUpdate import get_cvelist, NVDSQLite
from .log import LOGGER

Checker = namedtuple('Checker',
                     ['name', 'get_versions', 'vendor_product_pairs'])

class Scanner(object):
    """"Scans files for CVEs using CVE checkers"""

    CHECKER_ENTRYPOINT = 'cve_bin_tool.checker'

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
        self.logger.info('Checkers loaded: %s',
                         ', '.join(self.checkers.keys()))

    @staticmethod
    def vendor_package_pairs(docstring):
        """Generator yielding each instance of a vendor name, package name pair
        in a checkers docstring"""
        for line in docstring.split('\n'):
            if line.strip().startswith('VPkg:'):
                yield tuple(map(lambda x: x.strip(),
                                line.replace('VPkg:', '').split(',')))

    @classmethod
    def load_checkers(cls):
        """ Loads CVE checkers """
        checkers = dict(map(lambda checker: (checker.name, checker.load()),
                            pkg_resources.iter_entry_points(cls.CHECKER_ENTRYPOINT)))
        for checker_name, checker in checkers.items():
            vendor_package_pairs = list(cls.vendor_package_pairs(checker.__doc__))
            if not vendor_package_pairs:
                raise ValueError('Docstring of %r checker' % (checker_name) + \
                                 ' does not define a vendor package pair')
            checkers[checker_name] = (checker, vendor_package_pairs)
        return checkers

    def get_cves(self, vendor_package_pairs, vers):
        """Returns a list of cves affecting a given version of tiff
        """
        cves_by_version = dict()
        for row in self.nvd.get_cves(*vendor_package_pairs):
            for ver in [ver.strip() for ver in row.version.split(',')]:
                if not ver in cves_by_version:
                    cves_by_version[ver] = {}
                cves_by_version[ver][row.number] = row
        # `-` version is all versions are affected. Aka no patch
        grab_all = {}
        grab_all.update(cves_by_version.get('-', {}))
        grab_all.update(cves_by_version.get(vers, {}))
        return grab_all

    def scan_file(self, filename):
        """Scans a file to see if it contains any of the target libraries,
        and whether any of those contain CVEs"""

        self.logger.debug('Scanning file: %r', filename)

        # step 1: check if it's an ELF binary file
        o = subprocess.check_output(['file', filename])
        if sys.version_info.major == 3:
            o = o.decode('utf-8')

        if 'cannot open' in o:
            raise ValueError(o)

        if ("LSB shared" not in o) and ("LSB executable" not in o) and ("PE32 executable" not in o) and ("PE32+ executable" not in o) and ("Mach-O" not in o):
            return

        o = subprocess.check_output(["strings", filename])
        if sys.version_info.major == 3:
            o = o.decode('utf-8')
        lines = o.split("\n")

    #tko
        for checker_name, (get_version, vendor_package_pairs) in self.checkers.items():
            result = get_version(lines, filename)
            if "is_or_contains" in result:
                modulename, version = result["modulename"], result["version"]
                found_cves = self.get_cves(vendor_package_pairs, version)
                if len(found_cves.keys()):
                    self.files_with_cve = self.files_with_cve + 1
                if not modulename in self.all_cves:
                    self.all_cves[modulename] = {}
                self.all_cves[modulename][version] = found_cves
                if self.verbose:
                    print(filename, result["is_or_contains"], modulename,
                          version)
                    if len(found_cves.keys()):
                        print("Known CVEs in version " + version)
                        print(', '.join(found_cves.keys()))
        return self.all_cves

    def affected(self):
        """ Returns list of module name and version tuples identified from
        scan"""
        return [(modulename, version) \
                for modulename, versions in self.all_cves.items() \
                for version in versions.keys()]

class LogAction(argparse.Action):
    """ Argparse action for selecting logging level."""

    def __call__(self, parser, namespace, value, option_string=None):
        """ Turns string into logging level definition."""
        setattr(namespace, self.dest,
                getattr(logging, value.upper(), logging.WARNING))

def scan_and_or_extract_file(scanner, ectx, walker, should_extract, filepath):
    """ Runs extraction if possible and desired otherwise scans."""
    if ectx.can_extract(filepath):
        if not should_extract:
            print("%s is an archive. Pass " % (filepath,) + \
                  "-x option to auto-extract")
            return
        for filename in walker([ectx.extract(filepath)]):
            scan_and_or_extract_file(scanner, ectx, walker, should_extract,
                                     filename)
    else:
        scanner.scan_file(filepath)

def output_cves(outfile, modules, include_details=False):
    writer = csv.writer(outfile)
    for modulename, versions in modules.items():
        for version, cves in versions.items():
            for number, cve in cves.items():
                row = [modulename, version, cve.number, cve.severity]
                if include_details:
                    # TODO Include description in import from NVD jsons
                    # row.append(cve.description)
                    pass
                writer.writerow(row)

def main(argv=sys.argv, outfile=sys.stdout):
    """ Scan a binary file for certain open source libraries that may have CVEs """
    usage = """Usage: cve-binary-tools.py <path to directory>

    Possible output levels:
    -v (verbose): print scan results as they're found
       (regular): print only final summary
    -q (quiet):   suppress all output but exit with error
                  number indicating number of files with CVE

    Other options:
    -x (extract): Autoextract compressed files
    """

    if len(argv) <= 1:
        print(usage)
        return 0

    parser = argparse.ArgumentParser()
    parser.add_argument("directory",
                        help="directory to scan")
    parser.add_argument('-x', "--extract", action="store_true",
                        help="autoextract compressed files")
    parser.add_argument('-v', "--verbose", action="store_true",
                        help="details on found issues as script runs")
    parser.add_argument('-q', "--quiet", action="store_true",
                        help="suppress output")
    parser.add_argument('-l', "--log", help="log level", dest='log_level',
                        action=LogAction,
                        choices=['debug', 'info', 'warning', 'error', 'critical'])

    args = parser.parse_args(argv[1:])

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
        print(usage)
        return 0

    exclude_folders = ['.git']
    walker = DirWalk(
        #pattern='*.*',
        #folder_include_pattern='*',
        folder_exclude_pattern=';'.join(exclude_folders),
        #file_exclude_pattern=';'.join(exclude_files)
    ).walk

    # Update CVE database
    if not args.quiet:
        print("Connecting to NVD database and extracting the CVE list ... " + \
              "Please hold on.. This will take few minutes... ")
    nvd = NVDSQLite()
    nvd.get_cvelist_if_stale()

    # Close database when done
    with nvd:
        extractor = Extractor()
        scanner = Scanner(nvd, verbose=args.verbose)

        with extractor() as ectx:
            if os.path.isdir(args.directory):
                for filepath in walker([args.directory]):
                    scan_and_or_extract_file(scanner, ectx, walker,
                                             args.extract, filepath)
            elif os.path.isfile(args.directory):
                scan_and_or_extract_file(scanner, ectx, walker,
                                         args.extract, args.directory)

        if (not args.quiet) and scanner.files_with_cve > 0:
            print("")
            print("Overall CVE summary: ")
            print("There are", scanner.files_with_cve, "files with known CVEs detected")
            affected_string = ', '.join(map(lambda module_version:
                ' '.join(module_version), scanner.affected()))
            print("Known CVEs in %s:" % (affected_string,))
            output_cves(outfile, scanner.all_cves, include_details=args.verbose)

        # Use the number of files with known cves as error code
        # as requested by folk planning to automate use of this script.
        # If no files found, then the program exits cleanly.
        return scanner.files_with_cve


if __name__ == '__main__':
    sys.exit(main())

