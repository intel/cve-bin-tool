# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from cve_bin_tool.parsers.dart import DartParser
from cve_bin_tool.parsers.go import GoParser
from cve_bin_tool.parsers.java import JavaParser
from cve_bin_tool.parsers.javascript import JavascriptParser
from cve_bin_tool.parsers.perl import PerlParser
from cve_bin_tool.parsers.php import PhpParser
from cve_bin_tool.parsers.python import PythonParser, PythonRequirementsParser
from cve_bin_tool.parsers.r import RParser
from cve_bin_tool.parsers.ruby import RubyParser
from cve_bin_tool.parsers.rust import RustParser
from cve_bin_tool.parsers.swift import SwiftParser

valid_files = {
    "pom.xml": JavaParser,
    "package-lock.json": JavascriptParser,
    "Cargo.lock": RustParser,
    "renv.lock": RParser,
    "requirements.txt": PythonRequirementsParser,
    "go.mod": GoParser,
    "PKG-INFO: ": PythonParser,
    "METADATA: ": PythonParser,
    "Gemfile.lock": RubyParser,
    "Package.resolved": SwiftParser,
    "composer.lock": PhpParser,
    "cpanfile": PerlParser,
    "pubspec.lock": DartParser,
}


def parse(filename, output, cve_db, logger):
    """
    Parses the given filename using the appropriate parser.
    """
    for file in list(valid_files.keys()):
        if file in output:
            parser = valid_files[file](cve_db, logger)
    yield from parser.run_checker(filename)
