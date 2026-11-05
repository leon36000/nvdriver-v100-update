#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for the credential-free SonarQube runner connectivity probe."""

from __future__ import annotations

import json
import socket
import unittest
from unittest.mock import patch

from tools.probe_sonar_runner_endpoint import probe_sonar_endpoint


class SonarRunnerEndpointProbeTests(unittest.TestCase):
    @staticmethod
    def _up_result():
        return {
            "tcp_connected": True,
            "tls_verified": True,
            "http_status": 200,
            "sonar_status": "UP",
            "failure_stage": "up",
        }

    def test_fallback_ip_is_tried_after_runner_dns_failure_without_leaking_it(self):
        with patch(
            "tools.probe_sonar_runner_endpoint._resolve_addresses",
            return_value=([], False),
        ), patch(
            "tools.probe_sonar_runner_endpoint._try_endpoint",
            return_value=self._up_result(),
        ) as attempt:
            result = probe_sonar_endpoint(
                "https://sonar.internal.example:8443",
                fallback_ip="100.76.101.48",
            )

        self.assertEqual(result["status"], "pass")
        self.assertFalse(result["dns_resolved"])
        self.assertTrue(result["fallback_attempted"])
        self.assertEqual(result["connection_address_source"], "tailnet_ip")
        self.assertEqual(result["http_status"], 200)
        self.assertTrue(result["tls_verified"])
        candidate = attempt.call_args.args[4]
        self.assertEqual(candidate[3], ("100.76.101.48", 8443))
        rendered = json.dumps(result)
        self.assertNotIn("sonar.internal.example", rendered)
        self.assertNotIn("100.76.101.48", rendered)

    def test_successful_runner_dns_avoids_the_fallback_address(self):
        dns_candidate = (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            ("192.0.2.5", 8443),
        )
        with patch(
            "tools.probe_sonar_runner_endpoint._resolve_addresses",
            return_value=([dns_candidate], True),
        ), patch(
            "tools.probe_sonar_runner_endpoint._try_endpoint",
            return_value=self._up_result(),
        ) as attempt:
            result = probe_sonar_endpoint(
                "https://sonar.internal.example:8443",
                fallback_ip="100.76.101.48",
            )

        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["dns_resolved"])
        self.assertFalse(result["fallback_attempted"])
        self.assertEqual(result["connection_address_source"], "dns")
        self.assertEqual(attempt.call_count, 1)

    def test_rejects_credentials_query_and_non_http_urls(self):
        for endpoint in (
            "ftp://sonar.example",
            "https://username@sonar.example",
            "https://sonar.example/?mode=health",
            "https://sonar.example/#private-fragment",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaisesRegex(
                ValueError, "invalid_endpoint"
            ):
                probe_sonar_endpoint(endpoint)

    def test_rejects_invalid_fallback_address(self):
        with self.assertRaisesRegex(ValueError, "invalid_fallback_ip"):
            probe_sonar_endpoint(
                "https://sonar.example:8443", fallback_ip="not-an-ip")


if __name__ == "__main__":
    unittest.main()
