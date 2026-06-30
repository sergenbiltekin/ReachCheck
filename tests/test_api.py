"""API tests using the synchronous TestClient.

The background scan runs on the TestClient's event loop between requests, so we
create the scan and then poll the detail endpoint until it completes.
"""

from __future__ import annotations

import socket
import time

from fastapi.testclient import TestClient

from app.core import profiles
from app.main import app


def _listening_socket() -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    return sock, sock.getsockname()[1]


def _poll_until_done(client: TestClient, scan_id: int, timeout: float = 8.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        body = client.get(f"/api/scans/{scan_id}").json()
        if body["status"] in ("completed", "cancelled", "error"):
            return body
        time.sleep(0.1)
    raise AssertionError(f"scan {scan_id} did not finish within {timeout}s")


def test_create_scan_rejects_bad_profile():
    with TestClient(app) as client:
        resp = client.post("/api/scans", json={"cidrs": "10.0.0.0/30", "profile": "nope"})
        assert resp.status_code == 400


def test_get_missing_scan_is_404():
    with TestClient(app) as client:
        assert client.get("/api/scans/999999").status_code == 404


def test_delete_missing_scan_is_404():
    with TestClient(app) as client:
        assert client.delete("/api/scans/999999").status_code == 404


def test_export_missing_scan_is_404():
    with TestClient(app) as client:
        assert client.get("/api/scans/999999/export?format=csv").status_code == 404


def test_export_csv_and_json(monkeypatch):
    sock, port = _listening_socket()
    monkeypatch.setitem(
        profiles.PROFILES,
        "exporttest",
        profiles.ScanProfile(
            name="exporttest",
            label="Export test",
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
                "/api/scans",
                json={"cidrs": "127.0.0.1/32", "profile": "exporttest", "mode": "early_exit"},
            )
            scan_id = resp.json()["id"]
            _poll_until_done(client, scan_id)

            csv_resp = client.get(f"/api/scans/{scan_id}/export?format=csv")
            assert csv_resp.status_code == 200
            assert "text/csv" in csv_resp.headers["content-type"]
            assert "attachment" in csv_resp.headers["content-disposition"]
            assert "cidr,status,first_host" in csv_resp.text
            assert "127.0.0.1/32,reachable" in csv_resp.text

            json_resp = client.get(f"/api/scans/{scan_id}/export?format=json")
            assert json_resp.status_code == 200
            body = json_resp.json()
            assert body["id"] == scan_id
            assert body["results"][0]["cidr"] == "127.0.0.1/32"

            assert client.get(f"/api/scans/{scan_id}/export?format=xml").status_code == 400
    finally:
        sock.close()


def test_create_and_complete_scan(monkeypatch):
    sock, port = _listening_socket()
    monkeypatch.setitem(
        profiles.PROFILES,
        "apitest",
        profiles.ScanProfile(
            name="apitest",
            label="API test",
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
                "/api/scans",
                json={"cidrs": "127.0.0.1/32", "profile": "apitest", "mode": "early_exit"},
            )
            assert resp.status_code == 201
            scan_id = resp.json()["id"]

            body = _poll_until_done(client, scan_id)
            assert body["status"] == "completed"
            assert body["reachable_subnets"] == 1
            assert body["results"][0]["status"] == "reachable"

            # The new scan shows up in history.
            listed = client.get("/api/scans").json()
            assert any(s["id"] == scan_id for s in listed)
    finally:
        sock.close()
