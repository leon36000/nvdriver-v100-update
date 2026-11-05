#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check SonarQube token validity and project visibility without logging secrets."""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sys
from typing import Any, Callable
from urllib.parse import quote, urlsplit

from tools.probe_sonar_runner_endpoint import (
    _Candidate,
    _fallback_candidate,
    _parse_endpoint,
    _resolve_addresses,
)


SCHEMA = "nvidia-hybrid-sonar-token-access-probe-v1"
PROJECT_KEY_DEFAULT = "nvdriver-v100-update"


def _get_over_tls(host: str, port: int, path: str, candidate: _Candidate,
                  token: str, timeout: float) -> dict[str, Any]:
    family, socktype, proto, sockaddr = candidate
    result: dict[str, Any] = {
        "tcp_connected": False,
        "tls_verified": False,
        "http_status": None,
        "body": b"",
        "failure_stage": "tcp",
    }
    sock = None
    response = None
    try:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        sock.connect(sockaddr)
        result["tcp_connected"] = True
        result["failure_stage"] = "tls"
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        result["tls_verified"] = True
        result["failure_stage"] = "http"

        host_header = f"[{host}]" if ":" in host else host
        if port != 443:
            host_header = f"{host_header}:{port}"
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
            f"Authorization: Bearer {token}\r\n"
            "Accept: application/json\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        sock.sendall(request)
        response = http.client.HTTPResponse(sock, method="GET")
        response.begin()
        result["http_status"] = response.status
        result["body"] = response.read(65537)
        result["failure_stage"] = None
    except ssl.SSLError:
        result["failure_stage"] = "tls"
    except (OSError, http.client.HTTPException, TimeoutError, UnicodeEncodeError):
        result["failure_stage"] = "http" if result["tcp_connected"] else "tcp"
    finally:
        if response is not None:
            response.close()
        if sock is not None:
            sock.close()
    return result


def _json_body(response: dict[str, Any]) -> dict[str, Any] | None:
    body = response.get("body")
    if not isinstance(body, bytes) or len(body) > 65536:
        return None
    try:
        decoded = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None
    return decoded if isinstance(decoded, dict) else None


def probe_sonar_token_access(endpoint: str, *, fallback_ip: str, token: str,
                             project_key: str = PROJECT_KEY_DEFAULT,
                             timeout: float = 5.0,
                             requester: Callable[..., dict[str, Any]] | None = None
                             ) -> dict[str, Any]:
    if timeout <= 0 or timeout > 30:
        raise ValueError("invalid_timeout")
    if not isinstance(token, str) or not token or "\r" in token or "\n" in token:
        raise ValueError("invalid_token")
    if not isinstance(project_key, str) or not re.fullmatch(
            r"[A-Za-z0-9_.:-]{1,200}", project_key):
        raise ValueError("invalid_project_key")

    try:
        scheme, host, port, _status_path = _parse_endpoint(endpoint)
        parsed = urlsplit(endpoint)
    except ValueError:
        raise ValueError("invalid_endpoint") from None
    if (scheme != "https" or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment):
        raise ValueError("invalid_endpoint")

    base_path = parsed.path.rstrip("/")
    auth_path = f"{base_path}/api/authentication/validate"
    project_path = (
        f"{base_path}/api/projects/search?projects={quote(project_key, safe='')}"
    )
    candidates, dns_resolved = _resolve_addresses(host, port)
    fallback = _fallback_candidate(fallback_ip, port) if fallback_ip else None
    choices = [(candidate, "dns") for candidate in candidates]
    if fallback is not None and fallback not in candidates:
        choices.append((fallback, "tailnet_ip"))

    send = _get_over_tls if requester is None else requester
    fallback_attempted = False
    best: dict[str, Any] | None = None
    selected: tuple[_Candidate, str] | None = None
    authenticated: bool | None = None
    for candidate, source in choices:
        if source == "tailnet_ip":
            fallback_attempted = True
        response = send(host, port, auth_path, candidate, token, timeout)
        response = dict(response)
        response["connection_address_source"] = source
        if response.get("http_status") == 200 and response.get("tls_verified") is True:
            document = _json_body(response)
            if document is not None and type(document.get("valid")) is bool:
                best = response
                selected = (candidate, source)
                authenticated = document["valid"]
                if authenticated:
                    break
                continue
        if response.get("http_status") is not None and response.get("tls_verified") is True:
            best = response
        elif best is None:
            best = response

    result: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "pass" if authenticated is True else "fail",
        "dns_resolved": dns_resolved,
        "fallback_configured": bool(fallback_ip),
        "fallback_attempted": fallback_attempted,
        "connection_address_source": (
            best.get("connection_address_source", "none") if best else "none"),
        "tcp_connected": bool(best and best.get("tcp_connected") is True),
        "tls_verified": bool(best and best.get("tls_verified") is True),
        "authentication_http_status": best.get("http_status") if best else None,
        "authenticated": authenticated,
        "project_search_http_status": None,
        "project_visible": None,
        "analysis_permission": "not_tested",
        "failure_stage": (
            None if authenticated is True else
            "authentication" if best and best.get("http_status") is not None else
            best.get("failure_stage", "dns") if best else "dns"),
    }

    if authenticated is True and selected is not None:
        candidate, _source = selected
        project_response = dict(send(host, port, project_path, candidate, token, timeout))
        if (project_response.get("tls_verified") is True
                and project_response.get("http_status") == 200):
            result["project_search_http_status"] = 200
            document = _json_body(project_response)
            components = document.get("components") if document else None
            if isinstance(components, list):
                result["project_visible"] = any(
                    isinstance(component, dict)
                    and component.get("key") == project_key
                    for component in components
                )
        else:
            result["project_search_http_status"] = project_response.get("http_status")

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default=os.environ.get("SONAR_HOST_URL", ""))
    parser.add_argument("--fallback-ip", default=os.environ.get("SONAR_HOST_IP", ""))
    parser.add_argument("--project-key", default=PROJECT_KEY_DEFAULT)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    try:
        report = probe_sonar_token_access(
            args.endpoint,
            fallback_ip=args.fallback_ip,
            token=os.environ.get("SONAR_TOKEN", ""),
            project_key=args.project_key,
            timeout=args.timeout,
        )
    except ValueError as error:
        reason = str(error)
        if reason not in {"invalid_timeout", "invalid_token", "invalid_project_key",
                          "invalid_endpoint", "invalid_fallback_ip"}:
            reason = "invalid_configuration"
        report = {
            "schema": SCHEMA,
            "status": "fail",
            "dns_resolved": False,
            "fallback_configured": bool(args.fallback_ip),
            "fallback_attempted": False,
            "connection_address_source": "none",
            "tcp_connected": False,
            "tls_verified": False,
            "authentication_http_status": None,
            "authenticated": None,
            "project_search_http_status": None,
            "project_visible": None,
            "analysis_permission": "not_tested",
            "failure_stage": reason,
        }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    return 0 if report["authenticated"] is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
