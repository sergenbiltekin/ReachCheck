"""Tests for the server-rendered HTML routes."""

from __future__ import annotations

import socket
import time

from fastapi.testclient import TestClient

from app.core import profiles
from app.main import app


def test_dashboard_renders():
    with TestClient(app) as client:
        resp = client.get("/")
        assert resp.status_code == 200
        assert "New reachability scan" in resp.text
        assert "Recent scans" in resp.text


def test_submit_invalid_profile_rerenders_with_error():
    with TestClient(app) as client:
        resp = client.post(
            "/scans",
            data={"cidrs": "10.0.0.0/30", "profile": "turbo", "mode": "early_exit"},
        )
        assert resp.status_code == 400
        assert "Unknown profile" in resp.text


def test_malicious_cidr_is_escaped_on_detail_page():
    # An invalid "CIDR" containing HTML is stored verbatim as an ERROR result.
    # It must never be rendered as live HTML (no whitespace so it stays one token).
    payload = "<img/src=x/onerror=alert(1)>"
    with TestClient(app) as client:
        resp = client.post(
            "/api/scans",
            json={"cidrs": payload, "profile": "fast", "mode": "early_exit"},
        )
        scan_id = resp.json()["id"]
        deadline = time.time() + 8
        while time.time() < deadline:
            if client.get(f"/api/scans/{scan_id}").json()["status"] == "completed":
                break
            time.sleep(0.05)

        html = client.get(f"/scans/{scan_id}").text
        # The raw payload must not appear unescaped anywhere (server table or inline JS).
        assert payload not in html
        # It is present, but HTML-escaped, in the server-rendered table.
        assert "&lt;img/src=x" in html


def test_submit_redirects_to_detail_and_renders(monkeypatch):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    port = sock.getsockname()[1]
    monkeypatch.setitem(
        profiles.PROFILES,
        "webtest",
        profiles.ScanProfile(
            name="webtest",
            label="Web test",
            concurrency=8,
            timeout=0.5,
            retries=0,
            tcp_ports=(port,),
            use_icmp=False,
        ),
    )
    try:
        with TestClient(app) as client:
            resp = client.post(
                "/scans",
                data={"cidrs": "127.0.0.1/32", "profile": "webtest", "mode": "early_exit"},
                follow_redirects=False,
            )
            assert resp.status_code == 303
            location = resp.headers["location"]
            assert location.startswith("/scans/")

            detail = client.get(location)
            assert detail.status_code == 200
            assert "Scan #" in detail.text

            # Let the background scan finish, then the detail reflects completion.
            scan_id = int(location.rsplit("/", 1)[1])
            deadline = time.time() + 8
            while time.time() < deadline:
                body = client.get(f"/api/scans/{scan_id}").json()
                if body["status"] == "completed":
                    break
                time.sleep(0.1)
            assert body["status"] == "completed"
            assert body["reachable_subnets"] == 1
    finally:
        sock.close()
