# -*- coding: utf-8 -*-
#
# Copyright (c) the purl authors
# SPDX-License-Identifier: MIT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Visit https://github.com/package-url/packageurl-python for support and
# download.

import string
from collections import namedtuple
from typing import TYPE_CHECKING
from typing import Any
from typing import AnyStr
from typing import Dict
from typing import Optional
from typing import Tuple
from typing import Union
from typing import overload
from urllib.parse import quote as _percent_quote
from urllib.parse import unquote as _percent_unquote
from urllib.parse import urlsplit as _urlsplit

if TYPE_CHECKING:
    from collections.abc import Callable
    from collections.abc import Iterable

    from typing_extensions import Literal

# Python 3
basestring = (
    bytes,
    str,
)  # NOQA

"""
A purl (aka. Package URL) implementation as specified at:
https://github.com/package-url/purl-spec
"""


def quote(s: AnyStr) -> str:
    """
    Return a percent-encoded unicode string, except for colon :, given an `s`
    byte or unicode string.
    """
    if isinstance(s, str):
        s_bytes = s.encode("utf-8")
    else:
        s_bytes = s
    quoted = _percent_quote(s_bytes)
    if not isinstance(quoted, str):
        quoted = quoted.decode("utf-8")
    quoted = quoted.replace("%3A", ":")
    return quoted


def unquote(s: AnyStr) -> str:
    """
    Return a percent-decoded unicode string, given an `s` byte or unicode
    string.
    """
    unquoted = _percent_unquote(s)  # type:ignore[arg-type]  # typeshed is incorrect here
    if not isinstance(unquoted, str):
        unquoted = unquoted.decode("utf-8")
    return unquoted


@overload
def get_quoter(encode: bool = True) -> "Callable[[AnyStr], str]": ...


@overload
def get_quoter(encode: None) -> "Callable[[str], str]": ...


def get_quoter(
    encode: Optional[bool] = True,
) -> "Union[Callable[[AnyStr], str], Callable[[str], str]]":
    """
    Return quoting callable given an `encode` tri-boolean (True, False or None)
    """
    if encode is True:
        return quote
    elif encode is False:
        return unquote
    elif encode is None:
        return lambda x: x


def normalize_type(type: Optional[AnyStr], encode: Optional[bool] = True) -> Optional[str]:  # NOQA
    if not type:
        return None
    if not isinstance(type, str):
        type_str = type.decode("utf-8")  # NOQA
    else:
        type_str = type

    quoter = get_quoter(encode)
    type_str = quoter(type_str)  # NOQA
    return type_str.strip().lower() or None


def normalize_namespace(
    namespace: Optional[AnyStr], ptype: Optional[str], encode: Optional[bool] = True
) -> Optional[str]:  # NOQA
    if not namespace:
        return None
    if not isinstance(namespace, str):
        namespace_str = namespace.decode("utf-8")
    else:
        namespace_str = namespace

    namespace_str = namespace_str.strip().strip("/")
    if ptype in ("bitbucket", "github", "pypi", "gitlab"):
        namespace_str = namespace_str.lower()
    segments = [seg for seg in namespace_str.split("/") if seg.strip()]
    segments_quoted = map(get_quoter(encode), segments)
    return "/".join(segments_quoted) or None


def normalize_name(
    name: Optional[AnyStr], ptype: Optional[str], encode: Optional[bool] = True
) -> Optional[str]:  # NOQA
    if not name:
        return None
    if not isinstance(name, str):
        name_str = name.decode("utf-8")
    else:
        name_str = name

    quoter = get_quoter(encode)
    name_str = quoter(name_str)
    name_str = name_str.strip().strip("/")
    if ptype in ("bitbucket", "github", "pypi", "gitlab"):
        name_str = name_str.lower()
    if ptype == "pypi":
        name_str = name_str.replace("_", "-")
    return name_str or None


def normalize_version(
    version: Optional[AnyStr], encode: Optional[bool] = True
) -> Optional[str]:  # NOQA
    if not version:
        return None
    if not isinstance(version, str):
        version_str = version.decode("utf-8")
    else:
        version_str = version

    quoter = get_quoter(encode)
    version_str = quoter(version_str.strip())
    return version_str or None


@overload
def normalize_qualifiers(
    qualifiers: Union[AnyStr, Dict[str, str], None], encode: "Literal[True]" = ...
) -> Optional[str]: ...


@overload
def normalize_qualifiers(
    qualifiers: Union[AnyStr, Dict[str, str], None], encode: "Optional[Literal[False]]"
) -> Optional[Dict[str, str]]: ...


@overload
def normalize_qualifiers(
    qualifiers: Union[AnyStr, Dict[str, str], None], encode: Optional[bool] = ...
) -> Union[str, Dict[str, str], None]: ...


def normalize_qualifiers(
    qualifiers: Union[AnyStr, Dict[str, str], None], encode: Optional[bool] = True
) -> Union[str, Dict[str, str], None]:  # NOQA
    """
    Return normalized `qualifiers` as a mapping (or as a string if `encode` is
    True). The `qualifiers` arg is either a mapping or a string.
    Always return a mapping if decode is True (and never None).
    Raise ValueError on errors.
    """
    if not qualifiers:
        return None if encode else dict()

    if isinstance(qualifiers, basestring):
        if not isinstance(qualifiers, str):
            qualifiers_str = qualifiers.decode("utf-8")
        else:
            qualifiers_str = qualifiers
        # decode string to list of tuples
        qualifiers_list = qualifiers_str.split("&")
        if not all("=" in kv for kv in qualifiers_list):
            raise ValueError(
                f"Invalid qualifier. Must be a string of key=value pairs:{repr(qualifiers_list)}"
            )
        qualifiers_parts = [kv.partition("=") for kv in qualifiers_list]
        qualifiers_pairs: "Iterable[Tuple[str, str]]" = [(k, v) for k, _, v in qualifiers_parts]
    elif isinstance(qualifiers, dict):
        qualifiers_pairs = qualifiers.items()
    else:
        raise ValueError(f"Invalid qualifier. Must be a string or dict:{repr(qualifiers)}")

    quoter = get_quoter(encode)
    qualifiers_map = {
        k.strip().lower(): quoter(v)
        for k, v in qualifiers_pairs
        if k and k.strip() and v and v.strip()
    }

    valid_chars = string.ascii_letters + string.digits + ".-_"
    for key in qualifiers_map:
        if not key:
            raise ValueError("A qualifier key cannot be empty")

        if "%" in key:
            raise ValueError(f"A qualifier key cannot be percent encoded: {repr(key)}")

        if " " in key:
            raise ValueError(f"A qualifier key cannot contain spaces: {repr(key)}")

        if not all(c in valid_chars for c in key):
            raise ValueError(
                f"A qualifier key must be composed only of ASCII letters and numbers"
                f"period, dash and underscore: {repr(key)}"
            )

        if key[0] in string.digits:
            raise ValueError(f"A qualifier key cannot start with a number: {repr(key)}")

    qualifiers_map = dict(sorted(qualifiers_map.items()))
    if encode:
        qualifiers_list = [f"{key}={value}" for key, value in qualifiers_map.items()]
        qualifiers_str = "&".join(qualifiers_list)
        return qualifiers_str or None
    else:
        return qualifiers_map


def normalize_subpath(
    subpath: Optional[AnyStr], encode: Optional[bool] = True
) -> Optional[str]:  # NOQA
    if not subpath:
        return None
    if not isinstance(subpath, str):
        subpath_str = subpath.decode("utf-8")
    else:
        subpath_str = subpath

    quoter = get_quoter(encode)
    segments = subpath_str.split("/")
    segments = [quoter(s) for s in segments if s.strip() and s not in (".", "..")]
    subpath_str = "/".join(segments)
    return subpath_str or None


@overload
def normalize(
    type: Optional[AnyStr],
    namespace: Optional[AnyStr],
    name: Optional[AnyStr],
    version: Optional[AnyStr],
    qualifiers: Union[AnyStr, Dict[str, str], None],
    subpath: Optional[AnyStr],
    encode: "Literal[True]" = ...,
) -> Tuple[str, Optional[str], str, Optional[str], Optional[str], Optional[str]]: ...


@overload
def normalize(
    type: Optional[AnyStr],
    namespace: Optional[AnyStr],
    name: Optional[AnyStr],
    version: Optional[AnyStr],
    qualifiers: Union[AnyStr, Dict[str, str], None],
    subpath: Optional[AnyStr],
    encode: "Optional[Literal[False]]",
) -> Tuple[str, Optional[str], str, Optional[str], Optional[Dict[str, str]], Optional[str]]: ...


@overload
def normalize(
    type: Optional[AnyStr],
    namespace: Optional[AnyStr],
    name: Optional[AnyStr],
    version: Optional[AnyStr],
    qualifiers: Union[AnyStr, Dict[str, str], None],
    subpath: Optional[AnyStr],
    encode: Optional[bool] = ...,
) -> Tuple[
    str, Optional[str], str, Optional[str], Union[str, Dict[str, str], None], Optional[str]
]: ...


def normalize(
    type: Optional[AnyStr],
    namespace: Optional[AnyStr],
    name: Optional[AnyStr],
    version: Optional[AnyStr],
    qualifiers: Union[AnyStr, Dict[str, str], None],
    subpath: Optional[AnyStr],
    encode: Optional[bool] = True,
) -> Tuple[
    Optional[str],
    Optional[str],
    Optional[str],
    Optional[str],
    Union[str, Dict[str, str], None],
    Optional[str],
]:  # NOQA
    """
    Return normalized purl components
    """
    type_norm = normalize_type(type, encode)  # NOQA
    namespace_norm = normalize_namespace(namespace, type_norm, encode)
    name_norm = normalize_name(name, type_norm, encode)
    version_norm = normalize_version(version, encode)
    qualifiers_norm = normalize_qualifiers(qualifiers, encode)
    subpath_norm = normalize_subpath(subpath, encode)
    return type_norm, namespace_norm, name_norm, version_norm, qualifiers_norm, subpath_norm


class PackageURL(
    namedtuple("PackageURL", ("type", "namespace", "name", "version", "qualifiers", "subpath"))
):
    """
    A purl is a package URL as defined at
    https://github.com/package-url/purl-spec
    """

    name: str
    namespace: Optional[str]
    qualifiers: Union[str, Dict[str, str], None]
    subpath: Optional[str]
    type: str
    version: Optional[str]

    def __new__(
        self,
        type: Optional[AnyStr] = None,
        namespace: Optional[AnyStr] = None,
        name: Optional[AnyStr] = None,  # NOQA
        version: Optional[AnyStr] = None,
        qualifiers: Union[AnyStr, Dict[str, str], None] = None,
        subpath: Optional[AnyStr] = None,
    ) -> "PackageURL":  # this should be 'Self' https://github.com/python/mypy/pull/13133
        required = dict(type=type, name=name)
        for key, value in required.items():
            if value:
                continue
            raise ValueError(f"Invalid purl: {key} is a required argument.")

        strings = dict(
            type=type,
            namespace=namespace,
            name=name,
            version=version,
            subpath=subpath,
        )

        for key, value in strings.items():
            if value and isinstance(value, basestring) or not value:
                continue
            raise ValueError(f"Invalid purl: {key} argument must be a string: {repr(value)}.")

        if qualifiers and not isinstance(
            qualifiers,
            (
                basestring,
                dict,
            ),
        ):
            raise ValueError(
                f"Invalid purl: qualifiers argument must be a dict or a string: {repr(qualifiers)}."
            )

        (
            type_norm,
            namespace_norm,
            name_norm,
            version_norm,
            qualifiers_norm,
            subpath_norm,
        ) = normalize(  # NOQA
            type, namespace, name, version, qualifiers, subpath, encode=None
        )

        return super().__new__(
            PackageURL,
            type=type_norm,
            namespace=namespace_norm,
            name=name_norm,
            version=version_norm,
            qualifiers=qualifiers_norm,
            subpath=subpath_norm,
        )

    def __str__(self, *args: Any, **kwargs: Any) -> str:
        return self.to_string()

    def __hash__(self) -> int:
        return hash(self.to_string())

    def to_dict(self, encode: Optional[bool] = False, empty: Any = None) -> Dict[str, Any]:
        """
        Return an ordered dict of purl components as {key: value}.
        If `encode` is True, then "qualifiers" are encoded as a normalized
        string. Otherwise, qualifiers is a mapping.
        You can provide a value for `empty` to be used in place of default None.
        """
        data = self._asdict()
        if encode:
            data["qualifiers"] = normalize_qualifiers(self.qualifiers, encode=encode)

        for field, value in data.items():
            data[field] = value or empty

        return data

    def to_string(self) -> str:
        """
        Return a purl string built from components.
        """
        type, namespace, name, version, qualifiers, subpath = normalize(  # NOQA
            self.type,
            self.namespace,
            self.name,
            self.version,
            self.qualifiers,
            self.subpath,
            encode=True,
        )

        purl = ["pkg:", type, "/"]

        if namespace:
            purl.append(namespace)
            purl.append("/")

        purl.append(name)

        if version:
            purl.append("@")
            purl.append(version)

        if qualifiers:
            purl.append("?")
            purl.append(qualifiers)

        if subpath:
            purl.append("#")
            purl.append(subpath)

        return "".join(purl)

    @classmethod
    def from_string(cls, purl: str) -> "PackageURL":
        """
        Return a PackageURL object parsed from a string.
        Raise ValueError on errors.
        """
        if not purl or not isinstance(purl, str) or not purl.strip():
            raise ValueError("A purl string argument is required.")

        scheme, sep, remainder = purl.partition(":")
        if not sep or scheme != "pkg":
            raise ValueError(f'purl is missing the required "pkg" scheme component: {repr(purl)}.')

        # this strip '/, // and /// as possible in :// or :///
        remainder = remainder.strip().lstrip("/")

        version: Optional[str]  # this line is just for type hinting
        subpath: Optional[str]  # this line is just for type hinting

        type, sep, remainder = remainder.partition("/")  # NOQA
        if not type or not sep:
            raise ValueError(f"purl is missing the required type component: {repr(purl)}.")

        type = type.lower()

        scheme, authority, path, qualifiers_str, subpath = _urlsplit(
            url=remainder, scheme="", allow_fragments=True
        )

        if scheme or authority:
            msg = (
                f'Invalid purl {repr(purl)} cannot contain a "user:pass@host:port" '
                f"URL Authority component: {repr(authority)}."
            )
            raise ValueError(msg)

        path = path.lstrip("/")

        namespace: Optional[str] = ""
        # NPM purl have a namespace in the path
        # and the namespace in an npm purl is
        # different from others because it starts with `@`
        # so we need to handle this case separately
        if type == "npm" and path.startswith("@"):
            namespace, sep, path = path.partition("/")

        remainder, sep, version = path.rpartition("@")
        if not sep:
            remainder = version
            version = None

        ns_name = remainder.strip().strip("/")
        ns_name_parts = ns_name.split("/")
        ns_name_parts = [seg for seg in ns_name_parts if seg and seg.strip()]
        name = ""
        if not namespace and len(ns_name_parts) > 1:
            name = ns_name_parts[-1]
            ns = ns_name_parts[0:-1]
            namespace = "/".join(ns)
        elif len(ns_name_parts) == 1:
            name = ns_name_parts[0]

        if not name:
            raise ValueError(f"purl is missing the required name component: {repr(purl)}")

        type, namespace, name, version, qualifiers, subpath = normalize(  # NOQA
            type,
            namespace,
            name,
            version,
            qualifiers_str,
            subpath,
            encode=False,
        )

        return PackageURL(type, namespace, name, version, qualifiers, subpath)
