import os
import subprocess
import sys

import pkg_resources

from .egg_updater import IS_DEVELOP, update_egg
from .error_handler import ErrorMode
from .extractor import Extractor
from .file import is_binary
from .log import LOGGER
from .strings import Strings
from .util import inpath, DirWalk, ProductInfo


class InvalidFileError(Exception):
    """ Filepath is invalid for scanning."""


class VersionScanner:
    """"Scans files for CVEs using CVE checkers"""

    CHECKER_ENTRYPOINT = "cve_bin_tool.checker"

    def __init__(
        self,
        should_extract=False,
        exclude_folders=[],
        checkers=None,
        logger=None,
        error_mode=ErrorMode.TruncTrace,
        score=0,
    ):
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        # Update egg if installed in development mode
        if IS_DEVELOP():
            self.logger.info("Updating egg_info")
            update_egg()

        # Load checkers if not given
        self.checkers = checkers or self.load_checkers()
        self.score = score
        self.total_scanned_files = 0
        self.exclude_folders = exclude_folders + [".git"]

        self.walker = DirWalk(
            folder_exclude_pattern=";".join(
                exclude if exclude.endswith("*") else exclude + "*"
                for exclude in exclude_folders
            )
        ).walk
        self.should_extract = should_extract
        self.file_stack = []
        self.error_mode = error_mode
        # self.logger.info("Checkers loaded: %s" % (", ".join(self.checkers.keys())))

    @classmethod
    def load_checkers(cls):
        """ Loads CVE checkers """
        checkers = dict(
            map(
                lambda checker: (checker.name, checker.load()),
                pkg_resources.iter_entry_points(cls.CHECKER_ENTRYPOINT),
            )
        )
        return checkers

    @classmethod
    def available_checkers(cls):
        checkers = pkg_resources.iter_entry_points(cls.CHECKER_ENTRYPOINT)
        checker_list = [item.name for item in checkers]
        return checker_list

    def remove_skiplist(self, skips):
        # Take out any checkers that are on the skip list
        # (string of comma-delimited checker names)
        skiplist = skips
        for skipme in skiplist:
            if skipme in self.checkers:
                del self.checkers[skipme]
                self.logger.debug(f"Skipping checker: {skipme}")
            else:
                self.logger.error(f"Checker {skipme} is not a valid checker name")

    def print_checkers(self):
        self.logger.info(f'Checkers: {", ".join(self.checkers.keys())}')

    def scan_file(self, filename):
        """Scans a file to see if it contains any of the target libraries,
        and whether any of those contain CVEs"""

        self.logger.debug(f"Scanning file: {filename}")
        self.total_scanned_files += 1

        # Do not try to scan symlinks
        if os.path.islink(filename):
            return None

        # Ensure filename is a file
        if not os.path.isfile(filename):
            self.logger.warning(f"Invalid file {filename} cannot be scanned")
            return None

        # step 1: check if it's an ELF binary file
        if inpath("file"):
            # use system file if available (for performance reasons)
            o = subprocess.check_output(["file", filename])
            o = o.decode(sys.stdout.encoding)

            if "cannot open" in o:
                self.logger.warning(f"Unopenable file {filename} cannot be scanned")
                return None

            if (
                ("LSB " not in o)
                and ("LSB shared" not in o)
                and ("LSB executable" not in o)
                and ("PE32 executable" not in o)
                and ("PE32+ executable" not in o)
                and ("Mach-O" not in o)
            ):
                return None
        # otherwise use python implementation of file
        elif not is_binary(filename):
            return None
        # parse binary file's strings
        if inpath("strings"):
            # use "strings" on system if available (for performance)
            o = subprocess.check_output(["strings", filename])
            lines = o.decode("utf-8").splitlines()
        else:
            # Otherwise, use python implementation
            s = Strings(filename)
            lines = s.parse()

        # tko
        for (dummy_checker_name, checker) in self.checkers.items():
            checker = checker()
            result = checker.get_version(lines, filename)
            # do some magic so we can iterate over all results, even the ones that just return 1 hit
            if "is_or_contains" in result:
                results = [dict()]
                results[0] = result
            else:
                results = result

            for result in results:
                if "is_or_contains" in result:
                    version = "UNKNOWN"
                    if "version" in result and result["version"] != "UNKNOWN":
                        version = result["version"]
                    elif result["version"] == "UNKNOWN":
                        file_path = "".join(self.file_stack)
                        self.logger.warning(
                            f"{dummy_checker_name} was detected with version UNKNOWN in file {file_path}"
                        )
                    else:
                        self.logger.error(f"No version info for {dummy_checker_name}")

                    if version != "UNKNOWN":
                        file_path = "".join(self.file_stack)
                        self.logger.info(
                            f'{file_path} {result["is_or_contains"]} {dummy_checker_name} {version}'
                        )
                        for vendor, product in checker.VENDOR_PRODUCT:
                            yield ProductInfo(vendor, product, version), file_path

        self.logger.debug(f"Done scanning file: {filename}")

    @staticmethod
    def clean_file_path(filepath):
        """Returns a cleaner filepath by removing temp path from filepath"""

        # we'll recieve a filepath similar to
        # /temp/anything/extractable_filename.extracted/folders/inside/file
        # We'll return /folders/inside/file to be scanned

        # start_point is the point from we want to start trimming
        # len("extracted") = 9
        start_point = filepath.find("extracted") + 9
        return filepath[start_point:]

    def scan_and_or_extract_file(self, ectx, filepath):
        """ Runs extraction if possible and desired otherwise scans."""
        # Scan the file
        yield from self.scan_file(filepath)
        # Attempt to extract the file and scan the contents
        if ectx.can_extract(filepath):
            if not self.should_extract:
                LOGGER.warning(
                    f"{filepath} is an archive. Pass -x option to auto-extract"
                )
                return None
            for filename in self.walker([ectx.extract(filepath)]):
                clean_path = self.clean_file_path(filename)
                self.file_stack.append(f" contains {clean_path}")
                yield from self.scan_and_or_extract_file(ectx, filename)
                self.file_stack.pop()

    def recursive_scan(self, scan_path):
        with Extractor(logger=self.logger, error_mode=self.error_mode) as ectx:
            if os.path.isdir(scan_path):
                for filepath in self.walker([scan_path]):
                    self.file_stack.append(filepath)
                    yield from self.scan_and_or_extract_file(ectx, filepath)
                    self.file_stack.pop()
            elif os.path.isfile(scan_path):
                self.file_stack.append(scan_path)
                yield from self.scan_and_or_extract_file(ectx, scan_path)
                self.file_stack.pop()
