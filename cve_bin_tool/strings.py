#!/usr/bin/python3

"""
These are the customized strings and file classes, by doing this
the tool is able to support other operating systems like Windows
and MacOS.
"""

import sys

try:
    import cve_bin_tool.pstring as pstring
except ImportError:
    pstring = None


class Strings(object):
    def __init__(self, filename=""):
        self.filename = filename
        self.output = ""

    def parse(self):
        # Use c extention if available
        if pstring is not None:
            return pstring.string(self.filename)
        elif sys.version_info.major == 3:
            return self.parse_3()
        else:
            return self.parse_2()

    def parse_2(self):
        f = file(self.filename, "rb")
        l = f.readline()
        tmp = ""
        while l:
            for c in l:
                # remove all unprintable characters
                if ord(c) < 128 and ord(c) > 31:
                    tmp += c
                else:
                    if tmp != "":
                        self.output += tmp + "\n"
                        tmp = ""
            l = f.readline()
        return self.output

    def parse_3(self):
        with open(self.filename, "rb") as f:
            tmp = ""
            for l in f:
                for c in l:
                    # remove all unprintable characters
                    if c <= 31 or c >= 128:
                        if tmp != "":
                            self.output += tmp[:] + "\n"
                            tmp = ""
                    else:
                        tmp += chr(c)
        return self.output


if __name__ == "__main__":
    s = Strings(sys.argv[1])
    s.parse()
