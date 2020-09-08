"""
CVE-bin-tool OutputEngine tests
"""
import csv
import json
import logging
import os
import tempfile
import unittest

from rich.console import Console

from cve_bin_tool.output_engine import OutputEngine, output_csv, output_json
from cve_bin_tool.output_engine.console import output_console
from cve_bin_tool.output_engine.util import format_output
from cve_bin_tool.util import ProductInfo, CVEData, CVE


class TestOutputEngine(unittest.TestCase):
    """ Test the OutputEngine class functions """

    MOCK_OUTPUT = {
        ProductInfo("vendorname0", "productname0", "1.0"): CVEData(
            cves=[CVE("CVE-1234-1234", "MEDIUM"), CVE("CVE-1234-9876", "LOW")],
            paths={""},
        ),
        ProductInfo("vendorname0", "productname0", "2.8.6"): CVEData(
            cves=[CVE("CVE-1234-1111", "LOW")], paths={""}
        ),
        ProductInfo("vendorname1", "productname1", "3.2.1.0"): CVEData(
            cves=[CVE("CVE-1234-5678", "HIGH")], paths={""}
        ),
    }

    FORMATTED_OUTPUT = [
        {
            "vendor": "vendorname0",
            "product": "productname0",
            "version": "1.0",
            "cve_number": "CVE-1234-1234",
            "severity": "MEDIUM",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
        {
            "vendor": "vendorname0",
            "product": "productname0",
            "version": "1.0",
            "cve_number": "CVE-1234-9876",
            "severity": "LOW",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
        {
            "vendor": "vendorname0",
            "product": "productname0",
            "version": "2.8.6",
            "cve_number": "CVE-1234-1111",
            "severity": "LOW",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
        {
            "vendor": "vendorname1",
            "product": "productname1",
            "version": "3.2.1.0",
            "cve_number": "CVE-1234-5678",
            "severity": "HIGH",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
    ]

    def setUp(self) -> None:
        self.output_engine = OutputEngine(
            all_cve_data=self.MOCK_OUTPUT, scanned_dir="", filename="", themes_dir=""
        )
        self.mock_file = tempfile.NamedTemporaryFile("w+", encoding="utf-8")

    def tearDown(self) -> None:
        self.mock_file.close()

    def test_formatted_output(self):
        """ Test reformatting products """
        self.assertEqual(format_output(self.MOCK_OUTPUT), self.FORMATTED_OUTPUT)

    def test_output_json(self):
        """ Test formatting output as JSON """
        output_json(self.MOCK_OUTPUT, self.mock_file)
        self.mock_file.seek(0)  # reset file position
        self.assertEqual(json.load(self.mock_file), self.FORMATTED_OUTPUT)

    def test_output_csv(self):
        """ Test formatting output as CSV """
        output_csv(self.MOCK_OUTPUT, self.mock_file)
        self.mock_file.seek(0)  # reset file position
        reader = csv.DictReader(self.mock_file)
        expected_value = [dict(x) for x in reader]
        self.assertEqual(expected_value, self.FORMATTED_OUTPUT)

    def test_output_console(self):
        """Test Formatting Output as console"""

        console = Console(file=self.mock_file)
        output_console(self.MOCK_OUTPUT, console=console)

        expected_output = "│ vendorname0 │ productname0 │ 1.0     │ CVE-1234-1234 │ MEDIUM   │\n│ vendorname0 │ productname0 │ 1.0     │ CVE-1234-9876 │ LOW      │\n│ vendorname0 │ productname0 │ 2.8.6   │ CVE-1234-1111 │ LOW      │\n│ vendorname1 │ productname1 │ 3.2.1.0 │ CVE-1234-5678 │ HIGH     │\n└─────────────┴──────────────┴─────────┴───────────────┴──────────┘\n"
        self.mock_file.seek(0)  # reset file position
        result = self.mock_file.read()
        self.assertIn(expected_output, result)

    def test_output_file(self):
        """Test file generation logic in output_file"""
        logger = logging.getLogger()

        with self.assertLogs(logger, logging.INFO) as cm:
            self.output_engine.output_file(output_type="json")

        contains_filename = False
        contains_msg = False

        filename = self.output_engine.filename

        if os.path.isfile(filename):
            contains_filename = True

        if "Output stored at" in cm.output[0]:
            contains_msg = True

        # reset everything back
        os.remove(filename)
        self.output_engine.filename = ""

        self.assertEqual(contains_filename, True)
        self.assertEqual(contains_msg, True)

    def test_output_file_filename_already_exists(self):
        """Tests output_file when filename already exist"""

        # update the filename in output_engine
        self.output_engine.filename = "testfile.csv"

        # create a file with the same name as output_engine.filename
        with open("testfile.csv", "w") as f:
            f.write("testing")

        logger = logging.getLogger()

        # setup the context manager
        with self.assertLogs(logger, logging.INFO) as cm:
            self.output_engine.output_file(output_type="csv")

        # logs to check in cm
        msg_generate_filename = (
            "Generating a new filename with Default Naming Convention"
        )
        msg_failed_to_write = "Failed to write at 'testfile.csv'. File already exists"

        # flags for logs
        contains_fail2write = False
        contains_gen_file = False

        # check if the logger contains msg
        for log in cm.output:
            if msg_generate_filename in log:
                contains_gen_file = True
            elif msg_failed_to_write in log:
                contains_fail2write = True

        # remove the generated files and reset updated variables
        os.remove("testfile.csv")
        os.remove(self.output_engine.filename)
        self.output_engine.filename = ""

        # assert
        self.assertEqual(contains_gen_file, True)
        self.assertEqual(contains_fail2write, True)

    def test_output_file_incorrect_filename(self):
        """Tests filenames that are incorrect or are not accessible"""

        # update the filename in output_engine
        self.output_engine.filename = "/not/a/good_filename"

        logger = logging.getLogger()

        # setup the context manager
        with self.assertLogs(logger, logging.INFO) as cm:
            self.output_engine.output_file(output_type="csv")

        # log to check
        msg_switch_back = "Switching Back to Default Naming Convention"

        # flags
        contains_sb = False

        for log in cm.output:
            if msg_switch_back in log:
                contains_sb = True

        # remove the generated files and reset updated variables
        os.remove(self.output_engine.filename)
        self.output_engine.filename = ""

        # assert
        self.assertEqual(contains_sb, True)
