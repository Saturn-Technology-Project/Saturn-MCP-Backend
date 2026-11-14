"""Daily uptime counters for the status page.

The worker checks each service once a minute and adds to that day's row. GET /status/history
reads the last ninety days from here. A new, small table: nothing existing is touched.

Revision ID: 060_status_days
Revises: 059_hot_path_indexes
Create Date: 2026-11-13

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "060_status_days"
down_revision: Union[str, Sequence[str], None] = "059_hot_path_indexes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    if "status_days" in inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "status_days",
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("service_id", sa.String(length=32), nullable=False),
        sa.Column("checks", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failures", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("day", "service_id"),
    )


def downgrade() -> None:
    if "status_days" in inspect(op.get_bind()).get_table_names():
        op.drop_table("status_days")
