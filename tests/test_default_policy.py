import pytest

from app.core.config import get_settings
from app.core.enums import PolicyDecision
from app.features.policy.policies.services.default_policy import (
    MARKER,
    decision_for_permissions,
    ensure_default_policy,
    log_agents_without_policy,
)
from app.features.policy.policies.services.policy_engine import EvaluationResult, merge_results
from app.models import Agent, Tool


def test_empty_merge_denies_when_the_flag_is_on():
    settings = get_settings()
    previous = settings.policy_default_deny
    settings.policy_default_deny = True
    try:
        result = merge_results([])
    finally:
        settings.policy_default_deny = previous
    assert result.decision == PolicyDecision.DENY
    assert result.reason == "沒有適用的 policy"


def test_allow_rule_still_wins():
    result = merge_results([EvaluationResult(decision=PolicyDecision.ALLOW, policy_id="policy_open")])
    assert result.decision == PolicyDecision.ALLOW


def test_write_permissions_require_approval():
    assert decision_for_permissions(["read"]) == "allow"
    assert decision_for_permissions(["write"]) == "approval"
    # Unknown permissions fail closed.
    assert decision_for_permissions([]) == "approval"
    assert decision_for_permissions(None) == "approval"
    assert decision_for_permissions(["read", "write"]) == "approval"
    assert decision_for_permissions(["execute"]) == "approval"


def test_upstream_annotations_set_permissions():
    from app.features.mcp.servers.services.mcp_remote import _tools, permissions_for

    assert permissions_for({"readOnlyHint": True}) == ["read"]
    assert permissions_for({"readOnlyHint": True, "destructiveHint": True}) == ["write"]
    assert permissions_for({"readOnlyHint": "true"}) == ["write"]
    assert permissions_for({}) == ["write"]
    assert permissions_for(None) == ["write"]
    listed = _tools(
        {
            "result": {
                "tools": [
                    {"name": "notes.read", "annotations": {"readOnlyHint": True}},
                    {"name": "notes.delete", "annotations": {"destructiveHint": True}},
                    {"name": "notes.send"},
                ]
            }
        }
    )
    assert {item["name"]: item["permissions"] for item in listed} == {
        "notes.read": ["read"],
        "notes.delete": ["write"],
        "notes.send": ["write"],
    }


@pytest.mark.asyncio
async def test_connecting_a_server_holds_unannotated_tools_for_approval(client, monkeypatch):
    from app.features.mcp.servers.services.mcp_remote import permissions_for

    async def listed(endpoint, authorization=""):
        return [
            {"name": "notes.read", "description": "", "inputSchema": {}, "permissions": permissions_for({"readOnlyHint": True})},
            {"name": "notes.transfer", "description": "", "inputSchema": {}, "permissions": permissions_for({})},
            # A mock that predates permissions: still must not be allowed.
            {"name": "notes.wipe", "description": "", "inputSchema": {}},
        ]

    monkeypatch.setattr("app.features.mcp.servers.services.mcp_connect.list_remote_tools", listed)
    org_id = (await client.get("/auth/me")).json()["organization"]["id"]
    generator, session = await _db_session()
    try:
        await ensure_default_policy(session, org_id)
        await session.commit()
    finally:
        await generator.aclose()
    connected = await client.post(
        "/mcp-servers", json={"name": "Notes", "endpoint": "https://mcp.notion.com/mcp", "authorization": "t"}
    )
    assert connected.status_code == 201, connected.text
    generator, session = await _db_session()
    try:
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload

        from app.models import Policy

        policy = await session.scalar(
            select(Policy).options(selectinload(Policy.rules)).where(Policy.organization_id == org_id, Policy.description == MARKER)
        )
        decisions = {rule.tool: rule.decision for rule in policy.rules}
    finally:
        await generator.aclose()
    assert decisions["notes.read"] == "allow"
    assert decisions["notes.transfer"] == "approval"
    assert decisions["notes.wipe"] == "approval"


async def _db_session():
    from app.db.database import get_session
    from app.main import app

    override = app.dependency_overrides[get_session]
    generator = override()
    session = await anext(generator)
    return generator, session


@pytest.mark.asyncio
async def test_onboarding_creates_a_default_policy(client):
    org_id = (await client.get("/auth/me")).json()["organization"]["id"]
    generator, session = await _db_session()
    try:
        session.add(
            Tool(
                id="tool_notes_read",
                organization_id=org_id,
                name="notes.read",
                permissions=["read"],
                status="active",
            )
        )
        session.add(
            Tool(
                id="tool_notes_write",
                organization_id=org_id,
                name="notes.write",
                permissions=["write"],
                status="active",
            )
        )
        await session.flush()
        policy = await ensure_default_policy(session, org_id)
        await session.commit()
        await session.refresh(policy, attribute_names=["rules"])
        decisions = {rule.tool: rule.decision for rule in policy.rules}
    finally:
        await generator.aclose()
    assert policy.description == MARKER
    assert decisions["notes.read"] == "allow"
    assert decisions["notes.write"] == "approval"


@pytest.mark.asyncio
async def test_startup_lists_agents_without_changing_them(client):
    from sqlalchemy import func, select

    generator, session = await _db_session()
    try:
        before = await session.scalar(select(func.count()).select_from(Agent))
        found = await log_agents_without_policy(session)
        after = await session.scalar(select(func.count()).select_from(Agent))
    finally:
        await generator.aclose()
    assert after == before
    assert isinstance(found, list)


@pytest.mark.asyncio
async def test_the_startup_report_names_only_agents_no_active_policy_covers(client):
    from app.core.ids import new_id
    from app.models import Organization, Policy

    generator, session = await _db_session()
    try:
        for org in ("org_cov_a", "org_cov_b", "org_cov_c"):
            session.add(Organization(id=org, name=org, plan="team", kind="organization"))
        await session.flush()

        def agent(org, name):
            item = Agent(id=f"agent_{org}_{name}", organization_id=org, name=name)
            session.add(item)
            return item

        def policy(org, status, agents=()):
            item = Policy(id=new_id("pol"), organization_id=org, name="p", status=status)
            item.agents = list(agents)
            session.add(item)

        # A: one active policy assigned to "named" only. "other" is left out.
        named, _other = agent("org_cov_a", "named"), agent("org_cov_a", "other")
        policy("org_cov_a", "active", [named])
        # B: an active policy with no agents covers everyone in B.
        agent("org_cov_b", "one")
        policy("org_cov_b", "active")
        # C: only a paused policy, which covers nobody.
        agent("org_cov_c", "one")
        policy("org_cov_c", "paused")
        await session.commit()

        found = await log_agents_without_policy(session)
    finally:
        await generator.aclose()
    ours = sorted(item for item in found if item.startswith("org_cov_"))
    assert ours == ["org_cov_a:agent_org_cov_a_other", "org_cov_c:agent_org_cov_c_one"]
