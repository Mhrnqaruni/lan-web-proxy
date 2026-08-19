import argparse
import unittest

import proxy_server


class ValidationTests(unittest.TestCase):
    def test_validate_port_accepts_boundary_values(self):
        self.assertEqual(proxy_server.validate_port("1"), 1)
        self.assertEqual(proxy_server.validate_port("65535"), 65535)

    def test_validate_port_rejects_invalid_values(self):
        for value in ("0", "65536", "abc", ""):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    proxy_server.validate_port(value)

    def test_validate_hostname_normalizes_dns_name(self):
        self.assertEqual(proxy_server.validate_hostname("Proxy.Example.COM."), "proxy.example.com")

    def test_validate_hostname_rejects_urls_and_single_labels(self):
        for value in ("https://proxy.example.com", "localhost", "bad_name.example", "example.com/path"):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    proxy_server.validate_hostname(value)


if __name__ == "__main__":
    unittest.main()
