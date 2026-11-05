#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for the credential-safe SonarQube auth and project-visibility probe."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from tools.probe_sonar_token_access import probe_sonar_token_access


class SonarTokenAccessProbeTests(unittest.TestCase):
    endpoint = "https://pc4.tail0c55ff.ts.net:8443/sonar"
    fallback_ip = "100.76.101.48"
    candidate = (2, 1, 6, ("100.76.101.48", 8443))

    def _run(self, responses, *, dns_resolved=False):
        calls = []

        def requester(host, port, path, candidate, token, timeout):
            calls.append((host, port, path, token, candidate, timeout))
            response = responses.pop(0)
            if isinstance(response, dict):
                return response
            return {
                "tcp_connected": True,
                "tls_verified": True,
                "http_status": response[0],
                "body": json.dumps(response[1]).encode(),
                "failure_stage": None,
            }

        with patch(
            "tools.probe_sonar_token_access._resolve_addresses",
            return_value=([self.candidate] if dns_resolved else [], dns_resolved),
        ), patch(
            "tools.probe_sonar_token_access._fallback_candidate",
            return_value=self.candidate,
        ):
            report = probe_sonar_token_access(
                self.endpoint,
                fallback_ip=self.fallback_ip,
                token="fixture-secret-token-value",
                requester=requester,
            )
        return report, calls

    def test_valid_token_and_visible_project_emit_only_safe_booleans(self):
        report, calls = self._run([
            (200, {"valid": True}),
            (200, {"components": [{"key": "nvdriver-v100-update"}]}),
        ])

        self.assertEqual(report["status"], "pass")
        self.assertIs(report["authenticated"], True)
        self.assertIs(report["project_visible"], True)
        self.assertEqual(report["connection_address_source"], "tailnet_ip")
        self.assertEqual(report["analysis_permission"], "not_tested")
        self.assertEqual(len(calls), 2)
        self.assertIn("/sonar/api/authentication/validate", calls[0][2])
        self.assertIn("/sonar/api/projects/search?projects=nvdriver-v100-update", calls[1][2])
        self.assertNotIn("fixture-secret-token-value", json.dumps(report))

    def test_invalid_token_stops_before_project_query(self):
        report, calls = self._run([{
            "tcp_connected": True,
            "tls_verified": True,
            "http_status": 401,
            "body": b"",
            "failure_stage": None,
        }])

        self.assertEqual(report["status"], "fail")
        # A 401 is an authentication rejection but does not prove whether the
        # token is invalid or merely lacks access to the validation endpoint.
        self.assertIsNone(report["authenticated"])
        self.assertIsNone(report["project_visible"])
        self.assertEqual(report["authentication_http_status"], 401)
        self.assertEqual(len(calls), 1)

    def test_search_forbidden_does_not_claim_project_is_absent(self):
        report, _calls = self._run([
            (200, {"valid": True}),
            {
                "tcp_connected": True,
                "tls_verified": True,
                "http_status": 403,
                "body": b"untrusted response details are not retained",
                "failure_stage": None,
            },
        ])

        self.assertIs(report["authenticated"], True)
        self.assertEqual(report["project_search_http_status"], 403)
        self.assertIsNone(report["project_visible"])

    def test_malformed_successful_project_search_keeps_http_evidence(self):
        report, _calls = self._run([
            (200, {"valid": True}),
            (200, {"unexpected": "response shape"}),
        ])

        self.assertEqual(report["project_search_http_status"], 200)
        self.assertIsNone(report["project_visible"])

    def test_requires_https_token_and_safe_project_key(self):
        for endpoint, token, project in (
            ("http://sonar.internal", "token", "project"),
            (self.endpoint, "", "project"),
            (self.endpoint, "token\r\nInjected: yes", "project"),
            (self.endpoint, "token", "../project"),
        ):
            with self.subTest(endpoint=endpoint, project=project), self.assertRaises(ValueError):
                probe_sonar_token_access(
                    endpoint,
                    fallback_ip=self.fallback_ip,
                    token=token,
                    project_key=project,
                    requester=lambda *_args: self.fail("must fail before network access"),
                )

    def test_prefers_verified_dns_route_and_uses_tailnet_fallback_only_when_needed(self):
        responses = [
            (200, {"valid": True}),
            (200, {"components": []}),
        ]
        report, calls = self._run(responses, dns_resolved=True)
        self.assertEqual(report["connection_address_source"], "dns")
        self.assertFalse(report["fallback_attempted"])
        self.assertEqual(calls[0][4], self.candidate)


if __name__ == "__main__":
    unittest.main()
