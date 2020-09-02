"""
To determine if a file is executable we read the first few bytes of a file and
check it against various signatures for different executable file formats.
"""
import inspect
import sys

from .async_utils import FileIO, run_coroutine


async def aio_is_binary(filename):
    """Read the magic bytes from a file and determine if it is an executable
    binary."""
    signature = await read_signature(filename)
    for name, method in inspect.getmembers(
        sys.modules[__name__], predicate=inspect.isfunction
    ):
        if name.startswith("check_"):
            if method(filename, signature):
                return True
    return False


def is_binary(filename):
    return run_coroutine(aio_is_binary(filename))


async def read_signature(filename, length=4):
    """ Read the signature, first length bytes, from filename."""
    async with FileIO(filename, "rb") as file_handle:
        return await file_handle.read(length)


def check_elf(_filename, signature):
    """ Check for an ELF signature."""
    return signature == b"\x7f\x45\x4c\x46"


def check_pe(_filename, signature):
    """ Check for windows/dos PE signature, aka 0x5a4d."""
    return signature[:4] == b"\x4d\x5a"


def check_fake_test(_filename, signature):
    """ check for fake tests under windows."""
    return signature == b"MZ\x90\x00"
