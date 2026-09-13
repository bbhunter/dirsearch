import os
import tempfile
from unittest import TestCase

from lib.core.data import options
from lib.core.logger import enable_logging, logger, redact_log_text


class TestLogger(TestCase):
    def setUp(self):
        self.original_options = dict(options)
        self.original_handlers = tuple(logger.handlers)
        self.original_disabled = logger.disabled
        for handler in self.original_handlers:
            logger.removeHandler(handler)

    def tearDown(self):
        self.close_handlers()
        for handler in self.original_handlers:
            logger.addHandler(handler)
        logger.disabled = self.original_disabled
        options.clear()
        options.update(self.original_options)

    def close_handlers(self):
        for handler in tuple(logger.handlers):
            handler.close()
            logger.removeHandler(handler)

    def test_redacts_url_secrets_without_hiding_request_metadata(self):
        options["proxy_auth"] = "proxy-user:scheme-less-password"
        message = (
            '"GET https://alice:target-password@example.test/admin'
            '?=empty-key-secret&token=query-secret&mode=debug&bare-secret" '
            "200 - 42B - "
            "LOCATION: /login?code=redirect-secret&empty= - "
            "PROXIES: socks5://encoded-user:p%3Ass@[2001:db8::1]:1080/ "
            "proxy-user:scheme-less-password@proxy.example.test"
        )

        self.assertEqual(
            redact_log_text(message),
            '"GET https://<redacted>@example.test/admin'
            '?=<redacted>&token=<redacted>&mode=<redacted>&<redacted>" '
            "200 - 42B - "
            "LOCATION: /login?code=<redacted>&empty=<redacted> - "
            "PROXIES: socks5://<redacted>@[2001:db8::1]:1080/ "
            "<redacted>@proxy.example.test",
        )

    def test_file_formatter_redacts_traceback_and_configured_proxy_auth(self):
        proxy_auth = "proxy-user:proxy-password/segment"
        with tempfile.TemporaryDirectory() as root:
            log_path = os.path.join(root, "dirsearch.log")
            options["log_file"] = log_path
            options["log_file_size"] = 0
            options["proxy_auth"] = proxy_auth
            enable_logging()

            logger.info(
                '"GET https://target-user:target-password@target.example.test/path'
                '?token=query-secret&debug=true" 200 - 42B'
            )
            try:
                raise ValueError(
                    f"Invalid proxy URL: http://{proxy_auth}"
                    "@proxy.example.test:8080"
                )
            except ValueError as error:
                logger.exception(error)
            logger.info('THREAD-7 started')

            self.close_handlers()
            with open(log_path, encoding="utf-8") as log_file:
                contents = log_file.read()

        for secret in (
            "target-password",
            "query-secret",
            "true",
            "proxy-password",
        ):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, contents)

        self.assertIn(
            "GET https://<redacted>@target.example.test/path",
            contents,
        )
        self.assertIn("?token=<redacted>&debug=<redacted>", contents)
        self.assertIn("proxy.example.test:8080", contents)
        self.assertIn("Traceback (most recent call last)", contents)
        self.assertIn("ValueError: Invalid proxy URL", contents)
        self.assertIn("THREAD-7 started", contents)

    def test_rotates_log_file_at_configured_size(self):
        with tempfile.TemporaryDirectory() as root:
            log_path = os.path.join(root, "dirsearch.log")
            options["log_file"] = log_path
            options["log_file_size"] = 256
            enable_logging()

            for index in range(20):
                logger.info("entry-%02d-%s", index, "x" * 40)
            for handler in logger.handlers:
                handler.flush()
            self.close_handlers()

            self.assertTrue(os.path.exists(f"{log_path}.1"))
            self.assertFalse(os.path.exists(f"{log_path}.2"))
            self.assertLessEqual(os.path.getsize(log_path), 256)
            self.assertLessEqual(os.path.getsize(f"{log_path}.1"), 256)
            with open(log_path, encoding="utf-8") as log_file:
                self.assertIn("entry-19-", log_file.read())

    def test_enabling_logging_twice_does_not_duplicate_records(self):
        with tempfile.TemporaryDirectory() as root:
            log_path = os.path.join(root, "dirsearch.log")
            options["log_file"] = log_path
            options["log_file_size"] = 0

            enable_logging()
            first_handler = logger.handlers[0]
            enable_logging()
            logger.info("single-record")
            for handler in logger.handlers:
                handler.flush()

            handler_count = len(logger.handlers)
            first_handler_closed = first_handler.stream is None
            self.close_handlers()

            self.assertEqual(handler_count, 1)
            self.assertTrue(first_handler_closed)
            with open(log_path, encoding="utf-8") as log_file:
                self.assertEqual(log_file.read().count("single-record"), 1)
