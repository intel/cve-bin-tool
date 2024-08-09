from __future__ import annotations

import atexit
import contextlib
import pathlib
import re
import tempfile
import unittest

from packageurl import PackageURL

from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.log import LOGGER
from cve_bin_tool.parsers.dart import DartParser
from cve_bin_tool.parsers.env import EnvParser
from cve_bin_tool.parsers.go import GoParser
from cve_bin_tool.parsers.java import JavaParser
from cve_bin_tool.parsers.javascript import JavascriptParser
from cve_bin_tool.parsers.parse import valid_files as actual_valid_files
from cve_bin_tool.parsers.perl import PerlParser
from cve_bin_tool.parsers.php import PhpParser
from cve_bin_tool.parsers.python import PythonParser, PythonRequirementsParser
from cve_bin_tool.parsers.r import RParser
from cve_bin_tool.parsers.ruby import RubyParser
from cve_bin_tool.parsers.rust import RustParser
from cve_bin_tool.parsers.swift import SwiftParser
from cve_bin_tool.util import ProductInfo, ScanInfo

cve_db = CVEDB()
logger = LOGGER.getChild(__name__)

stack = contextlib.ExitStack().__enter__()
tmpdir = stack.enter_context(
    tempfile.TemporaryDirectory(prefix="cve-bin-tool-TEST_ENV")
)
atexit.register(lambda: stack.__exit__(None, None, None))

EXPECTED_VALID_FILES = {
    "pom.xml": [JavaParser],
    "package-lock.json": [JavascriptParser],
    "yarn.lock": [JavascriptParser],
    "Cargo.lock": [RustParser],
    "renv.lock": [RParser],
    "requirements.txt": [PythonRequirementsParser],
    "go.mod": [GoParser],
    "PKG-INFO: ": [PythonParser],
    "METADATA: ": [PythonParser],
    "Gemfile.lock": [RubyParser],
    "Package.resolved": [SwiftParser],
    "composer.lock": [PhpParser],
    "cpanfile": [PerlParser],
    "pubspec.lock": [DartParser],
}

PARSER_ENV_TEST_0001_ENV_CONTENTS = (
    pathlib.Path(__file__).parent.joinpath("parser_env_test_0001.env").read_text()
)


class TestParsers(unittest.TestCase):
    maxDiff = None

    def test_parser_match_filenames_results_in_correct_valid_files(self):
        for detection in EXPECTED_VALID_FILES.keys():
            self.assertIn(
                detection,
                actual_valid_files,
                "Expected registered file type {detection!r} not found in loaded file type list",
            )
            for plugin in EXPECTED_VALID_FILES[detection]:
                self.assertIn(
                    plugin,
                    actual_valid_files[detection],
                    "Expected registered file type {detection!r} is missing Parser class {plugin!r}",
                )

    def test_parser_env_test_0001(self):
        file_path = pathlib.Path(tmpdir, ".env").resolve()
        file_path.write_text(PARSER_ENV_TEST_0001_ENV_CONTENTS)
        env_parser = EnvParser(cve_db, logger)
        results = list(env_parser.run_checker(file_path))
        self.assertListEqual(
            results,
            [
                ScanInfo(
                    product_info=ProductInfo(
                        vendor="myvendor",
                        product="myproduct",
                        version="v0.0.0.dev-15abff2d529396937e18c657ecee1ed224842000",
                        # TODO location?
                        location="/usr/local/bin/product",
                        # TODO purl
                        purl=PackageURL(
                            type="ad-hoc",
                            namespace="myvendor",
                            name=re.sub(r"[^a-zA-Z0-9._-]", "", "myproduct").lower(),
                            version="v0.0.0.dev-15abff2d529396937e18c657ecee1ed224842000",
                            qualifiers={},
                            subpath=None,
                        ),
                    ),
                    file_path=file_path,
                )
            ],
        )
