# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import os
import re
import sys

if sys.version_info >= (3, 10):
    from importlib import metadata as importlib_metadata
else:
    import importlib_metadata
if sys.version_info >= (3, 9):
    import importlib.resources as resources
else:
    import importlib_resources as resources

from cve_bin_tool.parsers import Parser

PARSERS_ENTRYPOINT = "cve_bin_tool.parsers"


def enumerate_builtin_parsers():
    """Reads the files in cve_bin_tool/parsers/ to auto determine list"""
    parsers = {}
    for path in resources.files("cve_bin_tool.parsers").iterdir():
        if path.suffix != ".py" or path.stem in ("__init__", "parser"):
            continue
        contents = path.read_text()
        for re_match in re.finditer(r"^class (\w+)", contents, re.MULTILINE):
            parser_cls_name = re_match[1]
            parsers[".".join([path.stem, parser_cls_name])] = ":".join(
                [
                    str(path.relative_to(path.parents[2]).with_suffix("")).replace(
                        os.path.sep, "."
                    ),
                    parser_cls_name,
                ],
            )
    return parsers


BUILTIN_PARSERS = {
    parser_entry_point_name: importlib_metadata.EntryPoint(
        parser_entry_point_name,
        entry_point_path,
        "cve_bin_tool.parsers",
    )
    for (
        parser_entry_point_name,
        entry_point_path,
    ) in enumerate_builtin_parsers().items()
}


def load_valid_files() -> dict[str, list[type[Parser]]]:
    """Loads file parsers"""
    valid_files: dict[str, list[type[Parser]]] = {}

    for entrypoint in [
        *BUILTIN_PARSERS.values(),
        *importlib_metadata.entry_points().select(
            group=PARSERS_ENTRYPOINT,
        ),
    ]:
        parser_cls = entrypoint.load()
        for match_filename in getattr(parser_cls, "PARSER_MATCH_FILENAMES", []):
            valid_files.setdefault(match_filename, [])
            valid_files[match_filename].append(parser_cls)
    for match_filename in valid_files:
        valid_files[match_filename] = list(set(valid_files[match_filename]))
    return valid_files


valid_files = load_valid_files()


def identify_parsers() -> list:
    """Reports names of parsers"""
    parsers = []
    for i in BUILTIN_PARSERS.items():
        parser = i[0].split(".")[0]
        if parser not in parsers:
            parsers.append(parser)
    return parsers


available_parsers = identify_parsers()


def parse(filename, output, cve_db, logger):
    """
    Parses the given filename using the appropriate parser.
    """
    parsers = []
    for file in list(valid_files.keys()):
        if file in output:
            for valid_file_parser in valid_files[file]:
                parsers.append(valid_file_parser(cve_db, logger))
    for parser in parsers:
        yield from parser.run_checker(filename)
