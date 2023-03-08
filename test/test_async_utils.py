# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE-bin-tool async util tests
"""
from __future__ import annotations

import dataclasses
import subprocess
import unittest.mock
from collections.abc import Coroutine

import pytest

from cve_bin_tool.async_utils import aio_run_command


@dataclasses.dataclass
class FakeProcess:
    returncode: int

    async def communicate(self) -> tuple[bytes, bytes]:
        return b"", b""


def mkexec(returncode: int) -> callable[..., Coroutine[None, None, FakeProcess]]:
    async def return_fake_process(*args, **kwargs) -> FakeProcess:
        return FakeProcess(returncode=returncode)

    return return_fake_process


@pytest.mark.asyncio
async def test_aio_run_command_success():
    with unittest.mock.patch("asyncio.create_subprocess_exec", new=mkexec(0)):
        await aio_run_command(("echo", "hello"))


@pytest.mark.asyncio
async def test_aio_run_command_returncode_non_zero():
    with unittest.mock.patch("asyncio.create_subprocess_exec", new=mkexec(1)):
        with pytest.raises(subprocess.CalledProcessError):
            await aio_run_command(("echo", "hello"), process_can_fail=False)
