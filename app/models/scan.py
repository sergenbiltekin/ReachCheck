"""ORM models for scans and their per-subnet results.

A Scan is one reachability question over one or more subnets. Each SubnetResultRow
records the outcome for a single subnet. ``parent_scan_id`` links a re-scan back to
the scan it was derived from (used by the "re-scan the unreachable ones" feature).
"""

from typing import Optional

from sqlalchemy import JSON, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    profile: Mapped[str] = mapped_column(String(32))
    mode: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    parent_scan_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scans.id"), nullable=True)
    total_subnets: Mapped[int] = mapped_column(default=0)
    reachable_subnets: Mapped[int] = mapped_column(default=0)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    results: Mapped[list["SubnetResultRow"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="SubnetResultRow.id",
    )


class SubnetResultRow(Base):
    __tablename__ = "subnet_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    cidr: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    first_host: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    method: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    response_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    # All reachable hosts (for "scan all" mode); list of {host, method, response_ms}.
    # In early-exit mode this holds the single host that was found.
    reachable_hosts: Mapped[list] = mapped_column(JSON, default=list)
    hosts_total: Mapped[int] = mapped_column(default=0)
    hosts_checked: Mapped[int] = mapped_column(default=0)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="results")
