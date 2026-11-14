"""remove demo catalog rows

Revision ID: 009_remove_demo_catalog
Revises: 008_org_platform
Create Date: 2026-09-02

"""

from typing import Sequence, Union

from alembic import op
from sqlalchemy import inspect, text

revision: str = "009_remove_demo_catalog"
down_revision: Union[str, Sequence[str], None] = "008_org_platform"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

DEMO_AGENTS = ("agent_customer_ops", "agent_unmapped")
DEMO_MCP = ("mcp_crm", "mcp_billing", "mcp_email")
DEMO_TOOLS = (
    "tool_crm_get_customer",
    "tool_billing_get_payment",
    "tool_billing_refund",
    "tool_email_send",
)


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    agents = ", ".join(f"'{item}'" for item in DEMO_AGENTS)
    mcps = ", ".join(f"'{item}'" for item in DEMO_MCP)
    tools = ", ".join(f"'{item}'" for item in DEMO_TOOLS)

    def run(sql: str) -> None:
        bind.execute(text(sql))

    if "audit_logs" in tables and "runs" in tables:
        run(
            f"DELETE FROM audit_logs WHERE run_id IN "
            f"(SELECT id FROM runs WHERE agent_id IN ({agents}))"
        )
        run(f"DELETE FROM audit_logs WHERE actor_id IN ({agents})")
    if "payments" in tables and "runs" in tables:
        run(
            f"DELETE FROM payments WHERE run_id IN "
            f"(SELECT id FROM runs WHERE agent_id IN ({agents}))"
        )
        run("DELETE FROM payments WHERE wallet_id = 'wallet_customer_ops'")
    if "approvals" in tables and "runs" in tables:
        run(
            f"DELETE FROM approvals WHERE run_id IN "
            f"(SELECT id FROM runs WHERE agent_id IN ({agents}))"
        )
    if "actions" in tables and "runs" in tables:
        run(
            f"DELETE FROM actions WHERE run_id IN "
            f"(SELECT id FROM runs WHERE agent_id IN ({agents}))"
        )
    if "runs" in tables:
        run(f"DELETE FROM runs WHERE agent_id IN ({agents})")
    if "employee_agents" in tables:
        run(f"DELETE FROM employee_agents WHERE agent_id IN ({agents})")
    if "agent_mcp_servers" in tables:
        run(f"DELETE FROM agent_mcp_servers WHERE agent_id IN ({agents})")
        run(f"DELETE FROM agent_mcp_servers WHERE mcp_server_id IN ({mcps})")
    if "employee_mcp_servers" in tables:
        run(f"DELETE FROM employee_mcp_servers WHERE mcp_server_id IN ({mcps})")
    if "wallets" in tables:
        run("DELETE FROM wallets WHERE id = 'wallet_customer_ops'")
        run(f"DELETE FROM wallets WHERE agent_id IN ({agents})")
    if "policy_rules" in tables:
        run("DELETE FROM policy_rules WHERE policy_id = 'policy_refund'")
    if "policies" in tables:
        run("DELETE FROM policies WHERE id = 'policy_refund'")
    if "tools" in tables:
        run(f"DELETE FROM tools WHERE id IN ({tools})")
    if "mcp_servers" in tables:
        run(f"DELETE FROM mcp_servers WHERE id IN ({mcps})")
    if "agents" in tables:
        run(f"DELETE FROM agents WHERE id IN ({agents})")


def downgrade() -> None:
    # Nothing to restore, on purpose. The upgrade deletes demo rows and whatever referenced them;
    # that data is gone, and putting demo agents back into a real organization would be wrong.
    # Downgrading past this revision leaves the schema as revision 008 expects it.
    return
