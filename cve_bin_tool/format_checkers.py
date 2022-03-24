# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""To reformat checkers table when cve_bin_tool/checkers/__init__.py is updated."""

import os
import re

from cve_bin_tool import checkers

CHECKERS_TABLE_SIZE = 7


def reshape_list(checkers):
    """Reshape the list of checkers to a 2D-List for printing the table"""
    return [
        checkers[index : (index + CHECKERS_TABLE_SIZE)]
        for index in range(0, len(checkers), CHECKERS_TABLE_SIZE)
    ]


def max_checker_length(checkers):
    """Returns a list of max length of each column"""
    checkers[-1].extend([""] * (CHECKERS_TABLE_SIZE - len(checkers[-1])))

    size_list = [0] * CHECKERS_TABLE_SIZE

    for row in range(CHECKERS_TABLE_SIZE):
        for index in range(len(checkers)):
            checker = checkers[index][row]
            if len(checker) > size_list[row]:
                size_list[row] = len(checker)
    return size_list


def reformat_checkers(checkers, size_array):
    """Returns a markdown based table string for checkers"""
    checkers.insert(0, [""] * CHECKERS_TABLE_SIZE)
    checkers[0][CHECKERS_TABLE_SIZE // 2] = "Available checkers"

    markdown = "| "

    for row in checkers[0]:
        markdown += f" {row} |"
    markdown += "\n"

    markdown += "|"
    for index in range(len(checkers[0])):
        markdown += f"{'-'*size_array[index]} |"
    markdown += "\n"

    for row in checkers[1:]:
        markdown += "| "
        for checker in row:
            markdown += f"{checker} |"
        markdown += "\n"

    return markdown


def update_checker_table(file_path, markdown):
    """Updates README.md and MANUAL.md with the new checker table"""
    lines = []
    start_index, end_index = None, None

    with open(file_path) as f:
        for index, line in enumerate(f):
            if "CHECKERS TABLE BEGIN" in line:
                start_index = index
            elif "CHECKERS TABLE END" in line:
                end_index = index
            lines.append(line)

    lines = lines[: start_index + 1] + [markdown] + lines[end_index:]

    with open(file_path, "w") as f:
        f.writelines(lines)


def update_allowed_words(checkers_array: list[str]) -> None:
    """Updates the allow.txt file with the new checkers"""
    file_path = os.path.join(
        os.path.abspath("."), ".github", "actions", "spelling", "allow.txt"
    )

    checkers_words = re.findall(r"[^0-9_]+", "_".join(checkers_array))
    fileObj = open(file_path)
    words = fileObj.read().splitlines()
    fileObj.close()

    for checker in checkers_words:
        if checker not in words:
            words.append(checker)

    words = sorted(words, key=str.casefold)

    fileObj = open(file_path, "w+")
    fileObj.writelines("\n".join(words))
    fileObj.close()


if __name__ == "__main__":
    checkers_array = list(set(checkers.__all__) - {"Checker", "VendorProductPair"})
    checkers_array.sort()
    update_allowed_words(checkers_array)
    checkers_array = reshape_list(checkers_array)
    shape_list = max_checker_length(checkers_array)
    checkers_markdown = reformat_checkers(checkers_array, shape_list)
    update_checker_table(
        file_path=os.path.join(os.path.abspath("."), "README.md"),
        markdown=checkers_markdown,
    )
    update_checker_table(
        file_path=os.path.join(os.path.abspath("."), "doc", "MANUAL.md"),
        markdown=checkers_markdown,
    )
