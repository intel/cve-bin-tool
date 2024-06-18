import site
import sys

import setuptools

# See https://github.com/pypa/pip/issues/7953
site.ENABLE_USER_SITE = "--user" in sys.argv[1:]

setuptools.setup(use_scm_version=True)
