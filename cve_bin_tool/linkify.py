# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from rich.style import Style
from rich.text import Text, TextType

RE_CVE = r"CVE\-\d{4}\-\d+"


def linkify_cve(text_str: TextType) -> Text:
    """Apply a link to anything that looks like a CVE."""

    def make_link(cve: str) -> Style:
        return Style(link=f"https://nvd.nist.gov/vuln/detail/{cve}")

    text = Text.from_markup(text_str) if isinstance(text_str, str) else text_str
    text.highlight_regex(RE_CVE, style=make_link)
    return text
