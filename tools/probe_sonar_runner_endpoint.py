#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Probe SonarQube connectivity from a CI runner without sending credentials."""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import sys
from typing import Any
from urllib.parse import urlsplit


SCHEMA = "nvidia-hybrid-sonar-runner-probe-v1"
_STAGE_RANK = {"dns": 0, "tcp": 1, "tls": 2, "http": 3, "status": 4, "up": 5}
_Candidate = tuple[int, int, int, Any]


def _parse_endpoint(endpoint: str) -> tuple[str, str, int, str]:
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError:
        raise ValueError("invalid_endpoint") from None
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment):
        raise ValueError("invalid_endpoint")
    port = port or (443 if parsed.scheme == "https" else 80)
    base_path = parsed.path.rstrip("/")
    return parsed.scheme, parsed.hostname, port, f"{base_path}/api/system/status"


def _resolve_addresses(host: str, port: int) -> tuple[list[_Candidate], bool]:
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return [], False
    candidates: list[_Candidate] = []
    seen: set[tuple[Any, ...]] = set()
    for family, socktype, proto, _canonname, sockaddr in records:
        key = (family, socktype, proto, sockaddr)
        if key not in seen:
            seen.add(key)
            candidates.append((family, socktype, proto, sockaddr))
    return candidates, bool(candidates)


def _fallback_candidate(address: str, port: int) -> _Candidate:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        raise ValueError("invalid_fallback_ip") from None
    if ip.version == 4:
        return socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, (str(ip), port)
    return socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, (str(ip), port, 0, 0)


def _try_endpoint(host: str, port: int, path: str, scheme: str,
                  candidate: _Candidate, timeout: float) -> dict[str, Any]:
    family, socktype, proto, sockaddr = candidate
    result: dict[str, Any] = {
        "tcp_connected": False,
        "tls_verified": None if scheme == "http" else False,
        "http_status": None,
        "sonar_status": "not_observed",
        "failure_stage": "tcp",
    }
    sock = None
    response = None
    try:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        sock.connect(sockaddr)
        result["tcp_connected"] = True
        result["failure_stage"] = "http" if scheme == "http" else "tls"
        if scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
            result["tls_verified"] = True
            result["failure_stage"] = "http"

        host_header = f"[{host}]" if ":" in host else host
        if port != (443 if scheme == "https" else 80):
            host_header = f"{host_header}:{port}"
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
            "Accept: application/json\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        sock.sendall(request)
        response = http.client.HTTPResponse(sock, method="GET")
        response.begin()
        result["http_status"] = response.status
        body = response.read(65536)
        result["failure_stage"] = "status"
        if response.status == 200:
            try:
                document = json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                document = None
            if isinstance(document, dict) and document.get("status") == "UP":
                result["sonar_status"] = "UP"
                result["failure_stage"] = "up"
    except ssl.SSLError:
        result["failure_stage"] = "tls"
    except (OSError, http.client.HTTPException, TimeoutError):
        if result["tcp_connected"]:
            result["failure_stage"] = "http"
    finally:
        if response is not None:
            response.close()
        if sock is not None:
            sock.close()
    return result


def probe_sonar_endpoint(endpoint: str, *, fallback_ip: str = "",
                         timeout: float = 5.0) -> dict[str, Any]:
    if timeout <= 0 or timeout > 30:
        raise ValueError("invalid_timeout")
    scheme, host, port, path = _parse_endpoint(endpoint)
    candidates, dns_resolved = _resolve_addresses(host, port)
    fallback = _fallback_candidate(fallback_ip, port) if fallback_ip else None
    fallback_attempted = False
    best: dict[str, Any] = {
        "tcp_connected": False,
        "tls_verified": None if scheme == "http" else False,
        "http_status": None,
        "sonar_status": "not_observed",
        "failure_stage": "dns" if not dns_resolved and fallback is None else "tcp",
        "connection_address_source": "none",
    }

    choices = [(candidate, "dns") for candidate in candidates]
    if fallback is not None and fallback not in candidates:
        choices.append((fallback, "tailnet_ip"))
    for candidate, source in choices:
        if source == "tailnet_ip":
            fallback_attempted = True
        observed = _try_endpoint(host, port, path, scheme, candidate, timeout)
        observed["connection_address_source"] = source
        if _STAGE_RANK[observed["failure_stage"]] > _STAGE_RANK[best["failure_stage"]]:
            best = observed
        if observed["sonar_status"] == "UP":
            best = observed
            break

    return {
        "schema": SCHEMA,
        "status": "pass" if best["sonar_status"] == "UP" else "fail",
        "dns_resolved": dns_resolved,
        "fallback_configured": bool(fallback_ip),
        "fallback_attempted": fallback_attempted,
        "connection_address_source": best["connection_address_source"],
        "tcp_connected": best["tcp_connected"],
        "tls_verified": best["tls_verified"],
        "http_status": best["http_status"],
        "sonar_status": best["sonar_status"],
        "failure_stage": None if best["sonar_status"] == "UP" else best["failure_stage"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default=os.environ.get("SONAR_HOST_URL", ""))
    parser.add_argument("--fallback-ip", default=os.environ.get("SONAR_HOST_IP", ""))
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = probe_sonar_endpoint(
            args.endpoint, fallback_ip=args.fallback_ip, timeout=args.timeout)
    except ValueError:
        result = {
            "schema": SCHEMA,
            "status": "fail",
            "dns_resolved": False,
            "fallback_configured": bool(args.fallback_ip),
            "fallback_attempted": False,
            "connection_address_source": "none",
            "tcp_connected": False,
            "tls_verified": None,
            "http_status": None,
            "sonar_status": "not_observed",
            "failure_stage": "configuration",
        }
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
