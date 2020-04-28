"""
CVE-bin-tool OutputEngine tests
"""
import unittest
import tempfile
import json
import csv
import sys
import os
import logging

from cve_bin_tool.OutputEngine import OutputEngine


class TestOutputEngine(unittest.TestCase):
    """ Test the OutputEngine class functions """

    MOCK_OUTPUT = {
        "modulename0": {
            "1.0": {"CVE-1234-1234": "MEDIUM", "CVE-1234-9876": "LOW"},
            "2.8.6": {"CVE-1234-1111": "LOW"},
        },
        "modulename1": {"3.2.1.0": {"CVE-1234-5678": "HIGH"}},
    }
    FORMATTED_OUTPUT = [
        {
            "package": "modulename0",
            "version": "1.0",
            "cve_number": "CVE-1234-1234",
            "severity": "MEDIUM",
        },
        {
            "package": "modulename0",
            "version": "1.0",
            "cve_number": "CVE-1234-9876",
            "severity": "LOW",
        },
        {
            "package": "modulename0",
            "version": "2.8.6",
            "cve_number": "CVE-1234-1111",
            "severity": "LOW",
        },
        {
            "package": "modulename1",
            "version": "3.2.1.0",
            "cve_number": "CVE-1234-5678",
            "severity": "HIGH",
        },
    ]

    def setUp(self) -> None:
        self.output_engine = OutputEngine(modules=self.MOCK_OUTPUT)
        self.mock_file = tempfile.NamedTemporaryFile("w+")

    def tearDown(self) -> None:
        self.mock_file.close()

    def test_formatted_output(self):
        """ Test reformatting modules """
        self.assertEqual(self.output_engine.formatted_output, self.FORMATTED_OUTPUT)

    def test_output_json(self):
        """ Test formatting output as JSON """
        self.output_engine.output_json(self.mock_file)
        self.mock_file.seek(0)  # reset file position
        self.assertEqual(json.load(self.mock_file), self.FORMATTED_OUTPUT)

    def test_output_csv(self):
        """ Test formatting output as CSV """
        self.output_engine.output_csv(self.mock_file)
        self.mock_file.seek(0)  # reset file position
        reader = csv.DictReader(self.mock_file)
        self.assertEqual(list(reader), self.FORMATTED_OUTPUT)

    def test_output_console(self):
        """Test Formatting Output as console"""

        # list of mock modules having length greater than the current Respective Max Length
        mock_module_names = [
            "ABCDEFGHIJKLMNOPQRS",
            "ABCDEFGHIJKLMNOPQR",
            "ABCDEFGHIJKLMNOPQ",
            "ABCDEFGHIJKLMNOP",
            "ABCDEFGHIJKLMNO",
            "ABCDEFGHIJKLMN",
            "glibc",
            "I'm a different module",
        ]

        # generate output
        for name in mock_module_names:
            self.output_engine.write_console(
                name, "0.0.1", "CVE-2018-12381", "HIGH", self.mock_file
            )

        # expected output
        output_modules = """| ABCDEFGHIJKLMNO... | 0.0.1     | CVE-2018-12381     | HIGH      |
+--------------------+-----------+--------------------+-----------+
| ABCDEFGHIJKLMNO... | 0.0.1     | CVE-2018-12381     | HIGH      |
+--------------------+-----------+--------------------+-----------+
| ABCDEFGHIJKLMNO... | 0.0.1     | CVE-2018-12381     | HIGH      |
+--------------------+-----------+--------------------+-----------+
| ABCDEFGHIJKLMNO... | 0.0.1     | CVE-2018-12381     | HIGH      |
+--------------------+-----------+--------------------+-----------+
| ABCDEFGHIJKLMNO    | 0.0.1     | CVE-2018-12381     | HIGH      |
+--------------------+-----------+--------------------+-----------+
| ABCDEFGHIJKLMN     | 0.0.1     | CVE-2018-12381     | HIGH      |
+--------------------+-----------+--------------------+-----------+
| glibc              | 0.0.1     | CVE-2018-12381     | HIGH      |
+--------------------+-----------+--------------------+-----------+
| I'm a different... | 0.0.1     | CVE-2018-12381     | HIGH      |
+--------------------+-----------+--------------------+-----------+
"""
        self.mock_file.seek(0)  # reset file position
        self.assertEqual(output_modules, self.mock_file.read())

    def test_output_file(self):
        """Test file generation logic in output_file"""
        logger = logging.getLogger()

        with self.assertLogs(logger, logging.INFO) as cm:
            self.output_engine.output_file(output_type="json")

        contains_filename = False
        contains_msg = False

        filename = self.output_engine.filename

        file_list = os.listdir(os.getcwd())
        for file_ in file_list:
            if filename == file_:
                contains_filename = True

        if "Output stored at" in cm.output[0]:
            contains_msg = True

        self.assertEqual(contains_filename, True)
        self.assertEqual(contains_msg, True)

        # reset everything back
        os.remove(filename)
        self.output_engine.filename = None

    def test_output_file_filename_already_exists(self):
        """Tests output_file when filename already exist"""

        # update the filename in output_engine
        self.output_engine.filename = "testfile"

        # create a file with the same name as output_engine.filename
        with open("testfile", "w") as f:
            f.write("testing")

        logger = logging.getLogger()

        # setup the context manager
        with self.assertLogs(logger, logging.INFO) as cm:
            self.output_engine.output_file(output_type="csv")

        # logs to check in cm
        msg_generate_filename = (
            "Generating a new filename with Default Naming Convention"
        )
        msg_failed_to_write = "Failed to write at 'testfile'. File already exists"

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
        os.remove("testfile")
        os.remove(self.output_engine.filename)
        self.output_engine.filename = None

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
        self.output_engine.filename = None

        # assert
        self.assertEqual(contains_sb, True)
