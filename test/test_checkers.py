#!python

import pytest
import pkg_resources


class TestCheckers:
    """Run a series of tests directly against individual checkers.
    This is a companion to the tests in TestScanner."""

    @pytest.mark.parametrize(
        "checker_name, file_name, expected_result",
        [
            ("bluez", "libbluetooth.so.4", "bluetoothctl"),
            ("curl", "libcurl.so.4", "curl"),
            ("openssh", "scp", "openssh-client"),
            ("openssh", "sftp", "openssh-client"),
            ("openssh", "ssh", "openssh-client"),
            ("openssh", "ssh-add", "openssh-client"),
            ("openssh", "ssh-agent", "openssh-client"),
            ("openssh", "ssh-argv0", "openssh-client"),
            ("openssh", "ssh-copy-id", "openssh-client"),
            ("openssh", "ssh-keygen", "openssh-client"),
            ("openssh", "ssh-keyscan", "openssh-client"),
            ("openssh", "slogin", "openssh-client"),
            ("openssh", "sshd", "openssh-server"),
            ("python", "python", "python"),
            ("python", "python2.7", "python"),
            ("python", "python3.8", "python"),
            ("ncurses", "libncurses.so", "ncurses"),
            # ("python", "python3.9", "python"),
        ],
    )
    def test_filename_is(self, checker_name, file_name, expected_result):
        """ Test a checker's filename detection"""
        checkers = pkg_resources.iter_entry_points("cve_bin_tool.checker")
        for checker in checkers:
            if checker.name == checker_name:
                get_version = checker.load()

                result = get_version([""], file_name)
                assert result["is_or_contains"] == "is"
                assert result["modulename"] == expected_result
