# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from rich.theme import Theme

# Rich theme to colorize in the terminal
cve_theme = Theme(
    {
        "critical": "red",
        "high": "blue",
        "medium": "yellow",
        "low": "green",
        "unknown": "white",
    }
)
