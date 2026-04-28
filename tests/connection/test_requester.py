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

from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import patch

from lib.connection import requester as requester_module
from lib.connection.requester import AsyncRequester, Requester


class DummySyncResponse:
    status_code = 200
    headers = {"content-type": "text/plain"}
    history = []
    encoding = "utf-8"

    @staticmethod
    def iter_content(chunk_size):
        del chunk_size
        yield b"body"


class DummySyncSession:
    @staticmethod
    def prepare_request(request):
        return SimpleNamespace(url=request.url)

    def __init__(self, response):
        self.response = response

    def send(self, prep, **kwargs):
        del prep, kwargs
        return self.response


class DummyAsyncResponse:
    status_code = 200
    headers = {"content-type": "text/plain"}
    history = []
    encoding = "utf-8"

    def __init__(self):
        self.closed = False

    @staticmethod
    async def aiter_bytes(chunk_size):
        del chunk_size
        yield b"body"

    async def aclose(self):
        self.closed = True


class DummyAsyncSession:
    @staticmethod
    def build_request(*args, **kwargs):
        del args, kwargs
        return object()

    def __init__(self, response):
        self.response = response

    async def send(self, request, **kwargs):
        del request, kwargs
        return self.response


class TestRequesterElapsed(TestCase):
    def test_request_elapsed_includes_stream_read(self):
        requester = object.__new__(Requester)
        requester._rate = 0
        requester._url = "https://example.com/"
        requester.proxy_cred = None
        requester.headers = {}
        requester.agents = []
        requester.session = DummySyncSession(DummySyncResponse())

        with patch.object(requester_module.time, "perf_counter", side_effect=[10.0, 10.25]):
            with patch.object(requester_module.logger, "info"):
                response = requester.request("admin")

        self.assertEqual(response.elapsed, 0.25, "Sync elapsed should measure the full streamed request lifecycle")


class TestAsyncRequesterElapsed(IsolatedAsyncioTestCase):
    async def test_request_elapsed_waits_for_stream_close(self):
        requester = object.__new__(AsyncRequester)
        requester._rate = 0
        requester._url = "https://example.com/"
        requester.proxy_cred = None
        requester.headers = {}
        requester.agents = []
        requester.session = DummyAsyncSession(DummyAsyncResponse())

        with patch.object(requester_module.time, "perf_counter", side_effect=[20.0, 20.5]):
            with patch.object(requester_module.logger, "info"):
                response = await requester.request("admin")

        self.assertEqual(response.elapsed, 0.5, "Async elapsed should measure the full streamed request lifecycle")
        self.assertTrue(requester.session.response.closed, "Streamed async responses should be closed before elapsed is used")
