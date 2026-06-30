"""Pydantic schemas for API request/response bodies."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ScanCreate(BaseModel):
    """Request body to start a scan.

    ``cidrs`` is free-form text (one or many CIDRs separated by whitespace, comma
    or semicolon); the service splits and validates it.
    """

    cidrs: str = Field(..., description="One or more CIDRs, e.g. '10.0.0.0/24 10.0.1.0/24'")
    profile: str = "normal"
    mode: str = "early_exit"
    parent_scan_id: int | None = None


class ReachedHost(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    host: str
    method: str | None = None
    response_ms: float | None = None


class SubnetResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cidr: str
    status: str
    first_host: str | None = None
    method: str | None = None
    response_ms: float | None = None
    reachable_hosts: list[ReachedHost] = []
    hosts_total: int = 0
    hosts_checked: int = 0
    duration_ms: float = 0.0
    error: str | None = None


class ScanSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    profile: str
    mode: str
    status: str
    parent_scan_id: int | None = None
    total_subnets: int = 0
    reachable_subnets: int = 0
    error: str | None = None


class ScanDetailOut(ScanSummaryOut):
    results: list[SubnetResultOut] = []
