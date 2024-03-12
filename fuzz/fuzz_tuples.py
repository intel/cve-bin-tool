# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This module contains fuzz testing for the InputEngine's handling of product tuples.
"""

import sys

import atheris
import atheris_libprotobuf_mutator

import fuzz.generated.product_tuple_pb2 as product_tuple_pb2

with atheris.instrument_imports():
    from cve_bin_tool.input_engine import InputEngine


def TestParseData(data):
    """
    Fuzz Test the InputEngine.parse_data function with a product tuple protobuf message.
    """
    try:
        # data should be a fuzzy product tuple
        InputEngine("").parse_data(
            {"vendor", "product", "version"},
            [{"vendor": data.vendor, "product": data.product, "version": data.version}],
        )

    except SystemExit:
        # force return on SystemExit since those are mostly InsufficientArgs
        return


atheris_libprotobuf_mutator.Setup(
    sys.argv, TestParseData, proto=product_tuple_pb2.ProductData
)
atheris.Fuzz()
