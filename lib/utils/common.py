# -*- coding: utf-8 -*-
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#  Author: Mauro Soria

import os
import sys

from functools import reduce
from json import dumps
from html import escape
from ipaddress import IPv4Network, IPv6Network
from urllib.parse import quote, unquote, urljoin

from lib.core.settings import (
    INVALID_CHARS_FOR_WINDOWS_FILENAME,
    INVALID_FILENAME_CHAR_REPLACEMENT,
    IS_WINDOWS,
    URL_SAFE_CHARS,
    SCRIPT_PATH,
    TEXT_CHARS,
)
from lib.utils.file import FileUtils


def get_config_file():
    return os.environ.get("DIRSEARCH_CONFIG") or FileUtils.build_path(SCRIPT_PATH, "config.ini")


def safequote(string_: str) -> str:
    return quote(string_, safe=URL_SAFE_CHARS)


def _strip_and_uniquify_callback(array, item):
    item = item.strip()
    if not item or item in array:
        return array

    return array + [item]


# Strip values and remove duplicates from a list, respect the order
def strip_and_uniquify(array, type_=list):
    return type_(reduce(_strip_and_uniquify_callback, array, []))


def lstrip_once(string, pattern):
    if string.startswith(pattern):
        return string[len(pattern):]

    return string


def rstrip_once(string, pattern):
    if string.endswith(pattern):
        return string[:-len(pattern)]

    return string


# Some characters are denied in file name by Windows
def get_valid_filename(string):
    for char in INVALID_CHARS_FOR_WINDOWS_FILENAME:
        string = string.replace(char, INVALID_FILENAME_CHAR_REPLACEMENT)

    return string


def get_readable_size(num):
    base = 1024
    units = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")

    for unit in units:
        if -base < num < base:
            return f"{num}{unit}"

        num = round(num / base)

    return f"{num}TB"


def is_binary(bytes) -> bool:
    return bool(bytes.translate(None, TEXT_CHARS))


def is_ipv6(ip):
    return ip.count(":") >= 2


def iprange(subnet):
    network = IPv4Network(subnet)
    if is_ipv6(subnet):
        network = IPv6Network(subnet)

    return [str(ip) for ip in network]


# The browser direction behavior when you click on <a href="bar">link</a>
# (https://website.com/folder/foo -> https://website.com/folder/bar)
def merge_path(url, path):
    parts = url.split("/")
    # Normalize path like the browser does (dealing with ../ and ./)
    path = urljoin("/", path).lstrip("/")
    parts[-1] = path

    return "/".join(parts)


# Reference: https://stackoverflow.com/questions/46129898/conflict-between-sys-stdin-and-input-eoferror-eof-when-reading-a-line
def read_stdin():
    buffer = sys.stdin.read()

    try:
        if IS_WINDOWS:
            tty = "CON:"
        else:
            tty = os.ttyname(sys.stdout.fileno())

        sys.stdin = open(tty)
    except OSError:
        pass

    return buffer


# Replace a substring from an HTML body, where the substring might be encoded
# in many different ways (URL encoding, HTML escaping, ...).
def replace_from_all_encodings(string, to_replace, replace_with):
    string = string.replace(quote(to_replace), replace_with)
    string = string.replace(quote(quote(to_replace)), replace_with)
    string = string.replace(unquote(to_replace), replace_with)
    string = string.replace(unquote(unquote(to_replace)), replace_with)
    string = string.replace(escape(to_replace), replace_with)
    string = string.replace(dumps(to_replace), replace_with)
    return string.replace(to_replace, replace_with)
