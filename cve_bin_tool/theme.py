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
