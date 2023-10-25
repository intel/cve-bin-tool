# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

# This file also includes the RateLimiter function with the following license:
#
#    Copyright 2018 Quentin Pradet
#
#    Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

#    The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

#    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE."


""" Utility classes for the CVE Binary Tool """

from __future__ import annotations

import asyncio
import glob
import gzip
import itertools
import os
import shutil
import subprocess
import sys
import tempfile
import time
from functools import partial, wraps

from cve_bin_tool.util import inpath


def async_wrap(func):
    """
    Wrapper to use synchronous functions in asynchronous context.
    """

    @wraps(func)
    async def run(*args, loop=None, executor=None, **kwargs):
        """
        Takes a synchronous function and executes it using specified executor.

        Parameters :
            loop (optional, event loop): Event loop to be used.
            executor (optional, executor): Executor for calling the synchronous function in.
        """
        if loop is None:
            loop = asyncio.get_event_loop()
        pfunc = partial(func, *args, **kwargs)
        return await loop.run_in_executor(executor, pfunc)

    return run


def get_event_loop():
    """
    Gets or creates an event loop.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    if sys.platform.startswith("win"):
        if isinstance(loop, asyncio.SelectorEventLoop):
            loop = asyncio.ProactorEventLoop()
            asyncio.set_event_loop(loop)
    return loop


def run_coroutine(coro):
    """
    Runs an asynchronous coroutine and returns its result.
    """
    loop = get_event_loop()
    aws = asyncio.ensure_future(coro, loop=loop)
    result = loop.run_until_complete(aws)
    return result


async def aio_run_command(args, process_can_fail=True):
    """
    Asynchronously run a command in a subprocess and return its output, error and return code

    Parameters :
        process_can_fail (Optional, bool) : If False, non-zero return codes result in errors.

    Returns :
        stdout: The output of the subprocess.
        stderr: The error of the subprocess.
        returncode: The returncode of the subprocess
    """
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0 and not process_can_fail:
        raise subprocess.CalledProcessError(
            args, process.returncode, output=stdout, stderr=stderr
        )
    return stdout, stderr, process.returncode  # binary encoded


class ChangeDirContext:
    """
    Allows temporary changes in the current working directory.
    Manages context to allow going to destination directory and return back to original.
    """

    def __init__(self, destination_dir):
        self.current_dir = os.getcwd()
        self.destination_dir = destination_dir

    async def __aenter__(self):
        """
        Changes into specified destination directory.
        """
        os.chdir(self.destination_dir)

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """
        Revert changes to return to current working directory.
        """
        os.chdir(self.current_dir)


class FileIO:
    """
    Provides asynchronous methods for file operations
    """

    _open = async_wrap(open)
    _name_idx: int | None = 0
    _mode_idx = 1
    _mode = "r"

    def __init__(self, *args, **kwargs):
        # Do some trick to get exact filename and mode regardless of args or kwargs
        flatargs = list(itertools.chain(args, kwargs.values()))
        if (
            self.__class__._name_idx is not None
            and len(flatargs) > self.__class__._name_idx
        ):
            self.name = flatargs[self.__class__._name_idx]
        if (
            self.__class__._mode_idx is not None
            and len(flatargs) > self.__class__._mode_idx
        ):
            self._mode = flatargs[self.__class__._mode_idx]
        self._args = args
        self._kwargs = kwargs
        self._file = None

    async def __call__(self):
        """Convenience method to allow call like following:
        f = await FileIO("some file path", "r")()
        Note: We can't make async __init__
        """
        return await self.open()

    async def open(self):
        """
        Opens the file asynchronously.
        """
        file = await self.__class__._open(*self._args, **self._kwargs)
        self._file = file
        self._setup()
        return self

    def _setup(self):
        """
        Sets up the file object with asynchronous methods.
        """
        if not self._file:
            raise RuntimeError("Invalid Use: Call open() before calling _setup()")
        common_async_attrs = {
            "close",
            "flush",
            "isatty",
            "read",
            "readline",
            "readlines",
            "seek",
            "tell",
            "truncate",
            "write",
            "writelines",
        }
        common_sync_attrs = {
            "detach",
            "fileno",
            "readable",
            "writable",
            "seekable",
            "closed",
            "mode",
            "name",
        }
        strings_sync_attrs = {
            "buffer",
            "encoding",
            "errors",
            "line_buffering",
            "newlines",
        }
        bytes_async_attrs = {"readinto", "readinto1", "read1"}
        bytes_sync_attrs = {"raw"}
        if "b" in self._mode:
            async_attrs = common_async_attrs | bytes_async_attrs
            sync_attrs = common_sync_attrs | bytes_sync_attrs
        else:
            async_attrs = common_async_attrs
            sync_attrs = common_sync_attrs | strings_sync_attrs
        [
            setattr(self, attr, async_wrap(getattr(self._file, attr)))
            for attr in async_attrs
            if hasattr(self._file, attr)
        ]
        [
            setattr(self, attr, getattr(self._file, attr))
            for attr in sync_attrs
            if hasattr(self._file, attr)
        ]

    async def __aenter__(self):
        """
        Enters the asynchronous context.
        """
        return await self.open()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """
        Exits the asynchronous context.
        """
        return await self.close()

    async def __anext__(self):
        """
        Retrieves next line from the file asynchronously.
        """
        line = await self.readline()
        if line:
            return line
        else:
            raise StopAsyncIteration

    def __aiter__(self):
        """
        Returns an asynchronous iterator for the file.
        """
        return self


class TemporaryFile(FileIO):
    """
    Asynchronous temporary FileIO wrapper.
    """

    _open = async_wrap(tempfile.TemporaryFile)
    _name_idx: int | None = None
    _mode_idx = 0
    _mode = "w+b"

    def _setup(self):
        """
        Sets up the temporary file.
        """
        super()._setup()
        self.name = self._file.name


class NamedTemporaryFile(TemporaryFile):
    """
    Asynchronous Named Temporary File I/O Wrapper.
    """

    _open = async_wrap(tempfile.NamedTemporaryFile)


class SpooledTemporaryFile(TemporaryFile):
    """
    Asynchronous Spooled Temporary File I/O Wrapper.
    """

    _open = async_wrap(tempfile.SpooledTemporaryFile)
    _mode_idx = 1


class GzipFile(FileIO):
    """
    Asynchronous Gzip File I/O Wrapper.
    """

    _open = async_wrap(gzip.GzipFile)


class RateLimiter:
    """Rate limits an HTTP client that would make get() and post() calls.
    Calls are rate-limited by host.
    https://quentin.pradet.me/blog/how-do-you-rate-limit-calls-with-aiohttp.html
    This class is not thread-safe.

    Copyright 2018 Quentin Pradet
    See license at top of file.
    """

    RATE = 10
    MAX_TOKENS = 10

    def __init__(self, client):
        self.client = client
        self.tokens = self.MAX_TOKENS
        self.updated_at = time.monotonic()

    async def get(self, *args, **kwargs):
        """
        Waits for a token then performs a get request."""
        await self.wait_for_token()
        return self.client.get(*args, **kwargs)

    async def wait_for_token(self):
        """
        Waits for a token to be available.
        """
        while self.tokens < 1:
            self.add_new_tokens()
            await asyncio.sleep(0.1)
        self.tokens -= 1

    def add_new_tokens(self):
        """
        Add new tokens if needed. Updates token count as required.
        """
        now = time.monotonic()
        time_since_update = now - self.updated_at
        new_tokens = time_since_update * self.RATE
        if self.tokens + new_tokens >= 1:
            self.tokens = min(self.tokens + new_tokens, self.MAX_TOKENS)
            self.updated_at = now

    async def close(self):
        """
        Closes the client connection.
        """
        await self.client.close()


aio_rmdir = async_wrap(shutil.rmtree)
aio_rmfile = async_wrap(os.remove)
aio_unpack_archive = async_wrap(shutil.unpack_archive)
aio_glob = async_wrap(glob.glob)
aio_mkdtemp = async_wrap(tempfile.mkdtemp)
aio_makedirs = async_wrap(os.makedirs)
aio_inpath = async_wrap(inpath)
