# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import ast
import os

# -- Project information -----------------------------------------------------
with open(os.path.join(os.path.abspath(".."), "cve_bin_tool", "version.py")) as f:
    for line in f:
        if line.startswith("VERSION"):
            VERSION = ast.literal_eval(line.strip().split("=")[-1].strip())
            break

project = "CVE Binary Tool"
copyright = "2021, Intel Corporation"
author = "Terri Oda"

# The full version, including alpha/beta/rc tags
release = VERSION


# -- General configuration ---------------------------------------------------

source_parsers = {
    ".md": "recommonmark.parser.CommonMarkParser",
}

source_suffix = [".rst", ".md"]

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = ["sphinx_markdown_tables", "myst_parser"]

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# This forces MyST-Parser to generate heading anchors up to depth 6 according
# to GitHub rules. Note that setting this to None (max depth) won't work
# https://github.com/executablebooks/MyST-Parser/blob/a28e9b779d76602e63c20be78bed833f52381daa/docs/syntax/optional.md?plain=1#L470
myst_heading_anchors = 6


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "alabaster"

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
# html_static_path = ["_static"]
