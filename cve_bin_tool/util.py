# pylint: disable=too-many-arguments
""" Utility classes for the CVE Binary Tool """
import os
import re
import sys
import fnmatch


def regex_find(lines, *args):
    """Search a set of lines to find a match for the given regex
    """
    new_guess = ""
    patterns = [re.compile(regex) for regex in args]

    for line in lines:
        for pattern in patterns:
            match = pattern.search(line)
            if match:
                new_guess2 = match.group(1).strip()
                if len(new_guess2) > len(new_guess):
                    new_guess = new_guess2
    if new_guess != "":
        return new_guess.replace("_", ".")
    else:
        return "UNKNOWN"


def inpath(binary):
    """ Check to see if something is available in the path.
    Used to check if dependencies are installed before use. """
    if sys.platform == "win32":
        return any(
            list(
                map(
                    lambda dirname: os.path.isfile(
                        os.path.join(dirname, binary + ".exe")
                    ),
                    os.environ.get("PATH", "").split(";"),
                )
            )
        )
    return any(
        list(
            map(
                lambda dirname: os.path.isfile(os.path.join(dirname, binary)),
                os.environ.get("PATH", "").split(":"),
            )
        )
    )


class DirWalk:
    """
    for filename in DirWalk('*.c').walk(roots):
        do a thing with the c-files in the roots directories
    """

    def __init__(
        self,
        pattern="*",
        folder_include_pattern="*",
        folder_exclude_pattern=".git",
        file_exclude_pattern="",
        yield_files=True,
        yield_folders=False,
    ):
        """
        Generator for walking the file system and filtering the results.
        """
        self.pattern = pattern
        self.folder_include_pattern = folder_include_pattern
        self.folder_exclude_pattern = folder_exclude_pattern
        self.file_exclude_pattern = file_exclude_pattern
        self.yield_files = yield_files
        self.yield_folders = yield_folders

    def walk(self, roots=None):
        """ Walk the directory looking for files matching the pattern """
        if roots is None:
            roots = []
        for root in roots:
            for dirpath, dirnames, filenames in os.walk(root):
                # Filters
                filenames[:] = [
                    i
                    for i in filenames
                    if self.pattern_match(i, self.pattern)
                    and not self.pattern_match(i, self.file_exclude_pattern)
                ]
                dirnames[:] = [
                    i
                    for i in dirnames
                    if self.pattern_match(i, self.folder_include_pattern)
                    and not self.pattern_match(i, self.folder_exclude_pattern)
                ]
                # Yields
                if self.yield_files:
                    for filename in filenames:
                        yield os.path.normpath(os.path.join(dirpath, filename))
                if self.yield_folders:
                    for dirname in dirnames:
                        yield os.path.normpath(os.path.join(dirpath, dirname))

    @staticmethod
    def pattern_match(text, patterns):
        """ Match filename patterns """
        if not patterns:
            return False
        for pattern in patterns.split(";"):
            if fnmatch.fnmatch(text, pattern):
                return True
        return False
