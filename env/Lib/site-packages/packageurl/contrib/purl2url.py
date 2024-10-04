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

from packageurl import PackageURL
from packageurl.contrib.route import NoRouteAvailable
from packageurl.contrib.route import Router


def get_repo_download_url_by_package_type(
    type, namespace, name, version, archive_extension="tar.gz"
):
    """
    Return the download URL for a hosted git repository given a package type
    or None.
    """
    if archive_extension not in ("zip", "tar.gz"):
        raise ValueError("Only zip and tar.gz extensions are supported")

    download_url_by_type = {
        "github": f"https://github.com/{namespace}/{name}/archive/{version}.{archive_extension}",
        "bitbucket": f"https://bitbucket.org/{namespace}/{name}/get/{version}.{archive_extension}",
        "gitlab": f"https://gitlab.com/{namespace}/{name}/-/archive/{version}/{name}-{version}.{archive_extension}",
    }
    return download_url_by_type.get(type)


repo_router = Router()
download_router = Router()


def _get_url_from_router(router, purl):
    if purl:
        try:
            return router.process(purl)
        except NoRouteAvailable:
            return


def get_repo_url(purl):
    """
    Return a repository URL inferred from the `purl` string.
    """
    return _get_url_from_router(repo_router, purl)


def get_download_url(purl):
    """
    Return a download URL inferred from the `purl` string.
    """
    download_url = _get_url_from_router(download_router, purl)
    if download_url:
        return download_url

    # Fallback on the `download_url` qualifier when available.
    purl_data = PackageURL.from_string(purl)
    return purl_data.qualifiers.get("download_url", None)


def get_inferred_urls(purl):
    """
    Return all inferred URLs (repo, download) from the `purl` string.
    """
    url_functions = (
        get_repo_url,
        get_download_url,
    )

    inferred_urls = []
    for url_func in url_functions:
        url = url_func(purl)
        if url:
            inferred_urls.append(url)

    return inferred_urls


# Backward compatibility
purl2url = get_repo_url
get_url = get_repo_url


@repo_router.route("pkg:cargo/.*")
def build_cargo_repo_url(purl):
    """
    Return a cargo repo URL from the `purl` string.
    """
    purl_data = PackageURL.from_string(purl)

    name = purl_data.name
    version = purl_data.version

    if name and version:
        return f"https://crates.io/crates/{name}/{version}"
    elif name:
        return f"https://crates.io/crates/{name}"


@repo_router.route("pkg:bitbucket/.*")
def build_bitbucket_repo_url(purl):
    """
    Return a bitbucket repo URL from the `purl` string.
    """
    purl_data = PackageURL.from_string(purl)

    namespace = purl_data.namespace
    name = purl_data.name

    if name and namespace:
        return f"https://bitbucket.org/{namespace}/{name}"


@repo_router.route("pkg:github/.*")
def build_github_repo_url(purl):
    """
    Return a github repo URL from the `purl` string.
    """
    purl_data = PackageURL.from_string(purl)

    namespace = purl_data.namespace
    name = purl_data.name
    version = purl_data.version
    qualifiers = purl_data.qualifiers

    if not (name and namespace):
        return

    repo_url = f"https://github.com/{namespace}/{name}"

    if version:
        version_prefix = qualifiers.get("version_prefix", "")
        repo_url = f"{repo_url}/tree/{version_prefix}{version}"

    return repo_url


@repo_router.route("pkg:gitlab/.*")
def build_gitlab_repo_url(purl):
    """
    Return a gitlab repo URL from the `purl` string.
    """
    purl_data = PackageURL.from_string(purl)

    namespace = purl_data.namespace
    name = purl_data.name

    if name and namespace:
        return f"https://gitlab.com/{namespace}/{name}"


@repo_router.route("pkg:(gem|rubygems)/.*")
def build_rubygems_repo_url(purl):
    """
    Return a rubygems repo URL from the `purl` string.
    """
    purl_data = PackageURL.from_string(purl)

    name = purl_data.name
    version = purl_data.version

    if name and version:
        return f"https://rubygems.org/gems/{name}/versions/{version}"
    elif name:
        return f"https://rubygems.org/gems/{name}"


@repo_router.route("pkg:cran/.*")
def build_cran_repo_url(purl):
    """
    Return a cran repo URL from the `purl` string.
    """
    purl_data = PackageURL.from_string(purl)

    name = purl_data.name
    version = purl_data.version

    return f"https://cran.r-project.org/src/contrib/{name}_{version}.tar.gz"


@repo_router.route("pkg:npm/.*")
def build_npm_repo_url(purl):
    """
    Return a npm repo URL from the `purl` string.
    """
    purl_data = PackageURL.from_string(purl)

    namespace = purl_data.namespace
    name = purl_data.name
    version = purl_data.version

    repo_url = "https://www.npmjs.com/package/"
    if namespace:
        repo_url += f"{namespace}/"

    repo_url += f"{name}"

    if version:
        repo_url += f"/v/{version}"

    return repo_url


@repo_router.route("pkg:pypi/.*")
def build_pypi_repo_url(purl):
    """
    Return a pypi repo URL from the `purl` string.
    """
    purl_data = PackageURL.from_string(purl)

    name = (purl_data.name or "").replace("_", "-")
    version = purl_data.version

    if name and version:
        return f"https://pypi.org/project/{name}/{version}/"
    elif name:
        return f"https://pypi.org/project/{name}/"


@repo_router.route("pkg:composer/.*")
def build_composer_repo_url(purl):
    """
    Return a composer repo URL from the `purl` string.
    """
    purl_data = PackageURL.from_string(purl)

    name = purl_data.name
    version = purl_data.version
    namespace = purl_data.namespace

    if name and version:
        return f"https://packagist.org/packages/{namespace}/{name}#{version}"
    elif name:
        return f"https://packagist.org/packages/{namespace}/{name}"


@repo_router.route("pkg:nuget/.*")
def build_nuget_repo_url(purl):
    """
    Return a nuget repo URL from the `purl` string.
    """
    purl_data = PackageURL.from_string(purl)

    name = purl_data.name
    version = purl_data.version

    if name and version:
        return f"https://www.nuget.org/packages/{name}/{version}"
    elif name:
        return f"https://www.nuget.org/packages/{name}"


@repo_router.route("pkg:hackage/.*")
def build_hackage_repo_url(purl):
    """
    Return a hackage repo URL from the `purl` string.
    """
    purl_data = PackageURL.from_string(purl)

    name = purl_data.name
    version = purl_data.version

    if name and version:
        return f"https://hackage.haskell.org/package/{name}-{version}"
    elif name:
        return f"https://hackage.haskell.org/package/{name}"


@repo_router.route("pkg:golang/.*")
def build_golang_repo_url(purl):
    """
    Return a golang repo URL from the `purl` string.
    """
    purl_data = PackageURL.from_string(purl)

    namespace = purl_data.namespace
    name = purl_data.name
    version = purl_data.version

    if name and version:
        return f"https://pkg.go.dev/{namespace}/{name}@{version}"
    elif name:
        return f"https://pkg.go.dev/{namespace}/{name}"


# Download URLs:


@download_router.route("pkg:cargo/.*")
def build_cargo_download_url(purl):
    """
    Return a cargo download URL from the `purl` string.
    """
    purl_data = PackageURL.from_string(purl)

    name = purl_data.name
    version = purl_data.version

    if name and version:
        return f"https://crates.io/api/v1/crates/{name}/{version}/download"


@download_router.route("pkg:(gem|rubygems)/.*")
def build_rubygems_download_url(purl):
    """
    Return a rubygems download URL from the `purl` string.
    """
    purl_data = PackageURL.from_string(purl)

    name = purl_data.name
    version = purl_data.version

    if name and version:
        return f"https://rubygems.org/downloads/{name}-{version}.gem"


@download_router.route("pkg:npm/.*")
def build_npm_download_url(purl):
    """
    Return a npm download URL from the `purl` string.
    """
    purl_data = PackageURL.from_string(purl)

    namespace = purl_data.namespace
    name = purl_data.name
    version = purl_data.version

    base_url = "https://registry.npmjs.org"

    if namespace:
        base_url += f"/{namespace}"

    if name and version:
        return f"{base_url}/{name}/-/{name}-{version}.tgz"


@download_router.route("pkg:hackage/.*")
def build_hackage_download_url(purl):
    """
    Return a hackage download URL from the `purl` string.
    """
    purl_data = PackageURL.from_string(purl)

    name = purl_data.name
    version = purl_data.version

    if name and version:
        return f"https://hackage.haskell.org/package/{name}-{version}/{name}-{version}.tar.gz"


@download_router.route("pkg:nuget/.*")
def build_nuget_download_url(purl):
    """
    Return a nuget download URL from the `purl` string.
    """
    purl_data = PackageURL.from_string(purl)

    name = purl_data.name
    version = purl_data.version

    if name and version:
        return f"https://www.nuget.org/api/v2/package/{name}/{version}"


@download_router.route("pkg:gitlab/.*", "pkg:bitbucket/.*", "pkg:github/.*")
def build_repo_download_url(purl):
    """
    Return a gitlab download URL from the `purl` string.
    """
    return get_repo_download_url(purl)


def get_repo_download_url(purl):
    """
    Return ``download_url`` if present in ``purl`` qualifiers or
    if ``namespace``, ``name`` and ``version`` are present in ``purl``
    else return None.
    """
    purl_data = PackageURL.from_string(purl)

    namespace = purl_data.namespace
    type = purl_data.type
    name = purl_data.name
    version = purl_data.version
    qualifiers = purl_data.qualifiers

    download_url = qualifiers.get("download_url")
    if download_url:
        return download_url

    if not (namespace and name and version):
        return

    version_prefix = qualifiers.get("version_prefix", "")
    version = f"{version_prefix}{version}"

    return get_repo_download_url_by_package_type(
        type=type, namespace=namespace, name=name, version=version
    )
