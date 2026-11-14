from __future__ import annotations

from datetime import date

from sqlalchemy import Date, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class StatusDay(Base):
    """One service on one UTC day: how many times it was checked and how many checks failed.

    Counters, not one row per check. Ninety days of three services is 270 rows, and the uptime
    of a day is the same whether one worker counted it or two.
    """

    __tablename__ = "status_days"

    day: Mapped[date] = mapped_column(Date, primary_key=True)
    service_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    checks: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
