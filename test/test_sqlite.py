# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from unittest.mock import Mock, patch

from cve_bin_tool.checkers.sqlite import get_version_map


class TestGetVersionMap(unittest.TestCase):
    """Test case for the get_version_map function."""

    def setUp(self):
        """Set up the test case by initializing the necessary variables and data."""

        self.mock_html = """
                <html>
                  <head></head>
                    <body>
                    <a name="version_3_44_2"></a>
                    <h3>2023-11-24 (3.44.2)</h3><p><ol class='lessindent'>
                    <p><b>Hashes:</b>
                    <li>SQLITE_SOURCE_ID: 2023-11-24 11:41:44 ebead0e7230cd33bcec9f95d2183069565b9e709bf745c9b5db65cc0cbf92c0f
                    <li>SHA3-256 for sqlite3.c: bd70b012e2d1b3efa132d905224cd0ab476a69b892f8c6b21135756ec7ffbb13
                    </ol></p>

                    <a name="version_3_44_1"></a>
                    <h3>2023-11-22 (3.44.1)</h3><p><ol class='lessindent'>
                    <p><b>Hashes:</b>
                    <li>SQLITE_SOURCE_ID: 2023-11-22 14:18:12 d295f48e8f367b066b881780c98bdf980a1d550397d5ba0b0e49842c95b3e8b4
                    <li>SHA3-256 for sqlite3.c: e359dc502a73f3a8ad8e976a51231134d25cb93ad557a724dd92fe0c5897113a
                    </ol></p>

                    <a name="version_3_44_0"></a>
                    <h3>2023-11-01 (3.44.0)</h3><p><ol class='lessindent'>
                    <p><b>Hashes:</b>
                    <li>SQLITE_SOURCE_ID: 2023-11-01 11:23:50 17129ba1ff7f0daf37100ee82d507aef7827cf38de1866e2633096ae6ad8130
                    <li>SHA3-256 for sqlite3.c: d9e6530096136067644b1cb2057b3b0fa51070df99ec61971f73c9ba6aa9a36e
                    </body>
                </html>
                """
        self.expected_version_map = [
            [
                "3.44.2",
                "2023-11-24 11:41:44 ebead0e7230cd33bcec9f95d2183069565b9e709bf745c9b5db65cc0cbf92c0f",
            ],
            [
                "3.44.1",
                "2023-11-22 14:18:12 d295f48e8f367b066b881780c98bdf980a1d550397d5ba0b0e49842c95b3e8b4",
            ],
            [
                "3.44.0",
                "2023-11-01 11:23:50 17129ba1ff7f0daf37100ee82d507aef7827cf38de1866e2633096ae6ad8130",
            ],
        ]

    @patch("requests.get")
    def test_get_version_map(self, mock_requests_get):
        """Test get_version_map function with a mock response."""
        mock_response = Mock()
        mock_response.text = self.mock_html
        mock_requests_get.return_value = mock_response

        version_map = get_version_map()
        self.assertEqual(version_map, self.expected_version_map)
