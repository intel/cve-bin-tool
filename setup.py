import ast
import os
from io import open
from setuptools import find_packages, setup

with open('README.md', 'r', encoding='utf-8') as f:
    readme = f.read()

setup(
    name='cve-bin-tool',
    version='0.2.0',
    description='CVE Binary Checker Tool',
    long_description=readme,
    author='Terri Oda',
    author_email='terri.oda@intel.com',
    maintainer='Terri Oda',
    maintainer_email='terri.oda@intel.com',
    url='https://github.com/intel/cve-bin-tool',
    license='GPLv3',
    keywords=[
        'security',
        'tools',
        'CVE',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
    ],
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'cve-bin-tool = cve_bin_tool.cli:main',
        ],
        'cve_bin_tool.checker': [
            '%s = cve_bin_tool.checkers.%s:get_version' \
                    % tuple((2 * [filename.replace('.py', '')])) \
            for filename in \
            os.listdir(os.path.join(os.path.abspath(os.path.dirname(__file__)),
                'cve_bin_tool', 'checkers')) \
                if filename[::-1].startswith('yp.') and \
                not '__init__' in filename
        ],
    },
)
