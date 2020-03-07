#!/usr/bin/python3
import os

"""
CVE checker for openssh

References:
https://www.cvedetails.com/product/585/Openbsd-Openssh.html?vendor_id=97
"""
import re


def get_version(lines, filename):
    """
    Get the version and return it for OpenSSH server or client

    VPkg: openbsd, openssh
    """
    regex = re.compile(r"OpenSSH_([0-9]+\.[0-9]+[0-9a-z\s]*)")
    version_info = dict()
    version_info["version"] = "UNKNOWN"

    # determine version
    for l in lines:
        if regex.match(l):
            version_info["version"] = regex.match(l).groups()[0]
            break  # The binary seems to contain many version strings and the
            # first one matches the binary in question

    for modulename, binary_names in (
        {
            "openssh-server": ["sshd"],
            "openssh-client": [
                "scp",
                "sftp",
                "ssh-add",
                "ssh-agent",
                "ssh-argv0",
                "ssh-copy-id",
                "ssh-keygen",
                "ssh-keyscan",
                "ssh",
                "slogin",
            ],
        }
    ).items():
        for check in binary_names:
            if check in os.path.split(filename)[-1]:
                version_info["is_or_contains"] = "is"
                version_info["modulename"] = modulename
                return version_info

    if version_info["version"] != "UNKNOWN":
        version_info["is_or_contains"] = "contains"
        version_info["modulename"] = "openssh"
        # "openssh" because cannot check for client or server
        return version_info
    return {}
