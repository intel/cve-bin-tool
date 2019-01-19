#!/usr/bin/python3

"""
CVE checker for node.js

References:
http://www.cvedetails.com/vulnerability-list/vendor_id-12113/Nodejs.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=12113&product_id=0&version_id=&orderby=3&cvssscoremin=0
"""
import re

def guess_node_version_from_content(lines):
    """Guesses the node version from the file contents
    """
    new_guess = ""
    pattern1 = re.compile(r"https\:\/\/nodejs.org\/download\/release\/v([0-9]+\.[0-9]+\.[0-9]+)\/")
    pattern2 = re.compile(r"node v([0-9]+\.[0-9]+\.[0-9]+)")

    for line in lines:
        match = pattern1.search(line)
        if match:
            new_guess2 = match.group(1).strip()
            if len(new_guess2) > len(new_guess):
                new_guess = new_guess2
        match = pattern2.search(line)
        if match:
            new_guess2 = match.group(1).strip()
            if len(new_guess2) > len(new_guess):
                new_guess = new_guess2

    return new_guess

def guess_contains_node(lines):
    """Tries to determine if a file includes node
    """
    for line in lines:
        if "https://nodejs.org/download/release/v" in line:
            return 1
        if "(0) == (uv_async_init(uv_default_loop(), &dispatch_debug_messages_async, DispatchDebugMessagesAsyncCallback))" in line:
            return 1
        if "Documentation can be found at http://nodejs.org/" in line:
            return 1
    return 0

def get_version(lines, filename):
    """returns version information for node as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be node if node is found (and blank otherwise)
    is_or_contains idicates if the file is a copy of node or contains one
    version gives the actual version number

    VPkg: nodejs, node.js
    """
    version_info = dict()
    if "bin/node" in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_node(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "node"
        version_info["version"] = guess_node_version_from_content(lines)

    return version_info

