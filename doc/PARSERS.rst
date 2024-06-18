Adding a new parser to cve-bin-tool
===================================

Overview
--------

Parsers enhance ``cve-bin-tool`` by helping it discover vulnerabilities for
different file types and manifest formats.

Parsers
-------

The following parsers have been added to the project:

- **DartParser**
- **GoParser**
- **JavaParser**
- **JavascriptParser**
- **PerlParser**
- **PhpParser**
- **PythonParser**
- **PythonRequirementsParser**
- **RParser**
- **RubyParser**
- **RustParser**
- **SwiftParser**
- **BanditParser**

Usage
-----

To utilize these parsers, ensure that your project includes the following imports:

.. code-block:: python

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
    from cve_bin_tool.parsers.bandit import BanditParser

Setting Up a New Package and Entry Point
----------------------------------------

To implement a new parser plugin follow these steps:

1. Create the Parser Class
^^^^^^^^^^^^^^^^^^^^^^^^^^

First, create the parser class. This class should be located in the appropriate directory within your project. For example, you might place it in ``cve_bin_tool_parser_env/env.py``.

.. literalinclude:: /../cve_bin_tool/parsers/env.py

2. Set Up ``setup.py``
^^^^^^^^^^^^^^^^^^^^^^

Next, configure the ``setup.py`` file boilerplate.

.. literalinclude:: /../example/oot-parser/setup.py

3. Set Up ``setup.cfg``
^^^^^^^^^^^^^^^^^^^^^^^

Next, configure the ``setup.cfg`` file to include your new parser as an entry point. This allows the parser to be dynamically discovered and used by the project.

.. literalinclude:: /../example/oot-parser/setup_env.cfg

4. Create ``entry_points.txt``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You may also need to configure an ``entry_points.txt`` file if your project uses it to manage entry points.

.. literalinclude:: /../example/oot-parser/entry_points_env.txt

5. Install your plugin
^^^^^^^^^^^^^^^^^^^^^^

You need to activate your virtualenv before installing if you set one up.

.. code-block:: console

    $ touch cve_bin_tool_parser_env/__init__.py
    $ git init
    $ python -m pip install -e .

6. Populate the to-be-parsed file
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In this example we implemented the ``EnvParser`` which is the standard
``/etc/environment`` style format, let's save the following as ``.env``.

.. literalinclude:: /../test/parser_env_test_0001.env

7. Run ``cve-bin-tool`` and see your plugin's findings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Let's test that our defined CVE comes up by scanning a ``.env`` file.

.. code-block:: console

    $ cve-bin-tool --log debug .env

Advanced Example: Ad-Hoc CVEs
-----------------------------

For more information see: https://github.com/ossf/wg-vulnerability-disclosures/issues/94

1. Create the Parser Class
^^^^^^^^^^^^^^^^^^^^^^^^^^

First, create the parser class. This class should be located in the appropriate directory within your project. For example, you might place it in ``cve_bin_tool_parser_static_analysis_bandit/static_analysis_bandit.py``.

.. literalinclude:: /../example/oot-parser/cve_bin_tool_parser_static_analysis_bandit/static_analysis_bandit.py

2. Set Up ``setup.py``
^^^^^^^^^^^^^^^^^^^^^^

Next, configure the ``setup.py`` file boilerplate.

.. literalinclude:: /../example/oot-parser/setup.py

3. Set Up ``setup.cfg``
^^^^^^^^^^^^^^^^^^^^^^^

Next, configure the ``setup.cfg`` file to include your new parser as an entry point. This allows the parser to be dynamically discovered and used by the project.

.. literalinclude:: /../example/oot-parser/setup.cfg

4. Create ``entry_points.txt``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You may also need to configure an ``entry_points.txt`` file if your project uses it to manage entry points.

.. literalinclude:: /../example/oot-parser/entry_points.txt

5. Install your plugin
^^^^^^^^^^^^^^^^^^^^^^

You need to activate your virtualenv before installing if you set one up.

.. code-block:: console

    $ touch cve_bin_tool_parser_static_analysis_bandit/__init__.py
    $ git init
    $ python -m pip install -e .

6. Run ``cve-bin-tool``
^^^^^^^^^^^^^^^^^^^^^^^

In this example we implemented the ``BanditParser`` which is a static
analysis tool for Python files. We'll test that it loads by scanning
a ``.py`` file.

.. code-block:: console

    $ cve-bin-tool --format json --detail -- cve_bin_tool_parser_static_analysis_bandit/static_analysis_bandit.py

7. View Findings
^^^^^^^^^^^^^^^^

Let's view our two findings, we need to decode the JSON stored in the
description which will be an object describing the bug.

.. code-block:: console

    $ cat output.cve-bin-tool.*.json | jq '.[] | .description = (.description | fromjson)'

.. code-block:: json

    {
        "vendor": "username:alice:platform:example.com",
        "product": "filepath:example/oot-parser/cve_bin_tool_parser_static_analysis_bandit/static_analysis_bandit.py",
        "version": "v0.0.0.dev-SomeShaValue-N-Other-Branches-Workload-ID-Scan-Number-2d8852cf-ebfd-4495-97e2-2ce23e4e557d",
        "location": 11,
        "cve_number": "CVE-0001-urn:ietf:params:scitt:statement:sha-256:base64url:5i6UeRzg1...0...qnGmr1o",
        "severity": "LOW",
        "score": "unknown",
        "source": "SCITT_URN_FOR_MANIFEST_OF_EXECUTED_WORKFLOW_WITH_SARIF_OUTPUTS_DEREFERENCEABLE",
        "cvss_version": "3",
        "cvss_vector": "unknown",
        "paths": "example/oot-parser/cve_bin_tool_parser_static_analysis_bandit/static_analysis_bandit.py",
        "remarks": "NewFound",
        "comments": "",
        "description": {
          "code": "10 import re\n11 import subprocess\n12 import sys\n",
          "col_offset": 0,
          "end_col_offset": 17,
          "filename": "/home/alice/Documents/python/cve-bin-tool/example/oot-parser/cve_bin_tool_parser_static_analysis_bandit/static_analysis_bandit.py",
          "issue_confidence": "HIGH",
          "issue_cwe": {
            "id": 78,
            "link": "https://cwe.mitre.org/data/definitions/78.html"
          },
          "issue_severity": "LOW",
          "issue_text": "Consider possible security implications associated with the subprocess module.",
          "line_number": 11,
          "line_range": [
            11
          ],
          "more_info": "https://bandit.readthedocs.io/en/1.7.8/blacklists/blacklist_imports.html#b404-import-subprocess",
          "test_id": "B404",
          "test_name": "blacklist"
        }
      }

.. code-block:: json

      {
        "vendor": "username:alice:platform:example.com",
        "product": "filepath:example/oot-parser/cve_bin_tool_parser_static_analysis_bandit/static_analysis_bandit.py",
        "version": "v0.0.0.dev-SomeShaValue-N-Other-Branches-Workload-ID-Scan-Number-2d8852cf-ebfd-4495-97e2-2ce23e4e557d",
        "location": 11,
        "cve_number": "CVE-0001-urn:ietf:params:scitt:statement:sha-256:base64url:5i6UeRzg1...1...qnGmr1o",
        "severity": "LOW",
        "score": "unknown",
        "source": "SCITT_URN_FOR_MANIFEST_OF_EXECUTED_WORKFLOW_WITH_SARIF_OUTPUTS_DEREFERENCEABLE",
        "cvss_version": "3",
        "cvss_vector": "unknown",
        "paths": "example/oot-parser/cve_bin_tool_parser_static_analysis_bandit/static_analysis_bandit.py",
        "remarks": "NewFound",
        "comments": "",
        "description": {
          "code": "118         try:\n119             stdout = subprocess.check_output(\n120                 cmd,\n121             )\n122         except subprocess.CalledProcessError as error:\n",
          "col_offset": 21,
          "end_col_offset": 13,
          "filename": "/home/alice/Documents/python/cve-bin-tool/example/oot-parser/cve_bin_tool_parser_static_analysis_bandit/static_analysis_bandit.py",
          "issue_confidence": "HIGH",
          "issue_cwe": {
            "id": 78,
            "link": "https://cwe.mitre.org/data/definitions/78.html"
          },
          "issue_severity": "LOW",
          "issue_text": "subprocess call - check for execution of untrusted input.",
          "line_number": 119,
          "line_range": [
            119,
            120,
            121
          ],
          "more_info": "https://bandit.readthedocs.io/en/1.7.8/plugins/b603_subprocess_without_shell_equals_true.html",
          "test_id": "B603",
          "test_name": "subprocess_without_shell_equals_true"
        }
      }

Test Implementation
-------------------

A new test class `TestParsers` has been introduced to verify that the expected file types are correctly mapped to their respective parsers. The test ensures that the actual valid files match the expected valid files.

Test Method
^^^^^^^^^^^

- `test_parser_match_filenames_results_in_correct_valid_files`: This test compares the `EXPECTED_VALID_FILES` dictionary with the `actual_valid_files` dictionary imported from `cve_bin_tool.parsers.parse`. If there is any discrepancy between the two, the test will fail, indicating that the loaded file types do not match the expected registered file types.
