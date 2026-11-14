"""Changes to policies, tool sets and members leave an audit record the organization can read."""

from tests.policy_helpers import activate_created


async def _changes(client, headers=None):
    listed = await client.get("/activity/changes", headers=headers)
    assert listed.status_code == 200, listed.text
    return listed.json()


def _named(rows, event):
    return [item for item in rows if item["event"] == event]


async def test_policy_changes_are_recorded(client):
    created = await client.post(
        "/policies",
        json={"name": "Refund Guard", "rules": [{"tool": "billing.refund", "condition": "amount > 500", "decision": "deny"}]},
    )
    policy = await activate_created(client, created)
    renamed = await client.patch(f"/policies/{policy['id']}", json={"name": "Refund Guard v2"})
    assert renamed.status_code == 200, renamed.text
    assert (await client.delete(f"/policies/{policy['id']}")).status_code == 204

    rows = await _changes(client)
    me = (await client.get("/auth/me")).json()["id"]
    made = _named(rows, "policy_created")
    assert [item["payload"]["policy_id"] for item in made] == [policy["id"]]
    assert made[0]["actor_id"] == me and made[0]["result"] == "draft"
    activated = _named(rows, "policy_activated")
    assert activated[0]["payload"]["previous_status"] == "validated" and activated[0]["result"] == "active"
    updated = _named(rows, "policy_updated")
    assert updated[0]["payload"]["changed"] == ["name"]
    assert updated[0]["payload"]["policy_name"] == "Refund Guard v2"
    assert [item["payload"]["policy_id"] for item in _named(rows, "policy_deleted")] == [policy["id"]]
    # Newest first.
    assert [item["event"] for item in rows[:2]] == ["policy_deleted", "policy_updated"]

    from sqlalchemy import func, select

    from app.db.database import get_session
    from app.main import app
    from app.models import PolicyRule

    async for session in app.dependency_overrides[get_session]():
        left = await session.scalar(select(func.count()).select_from(PolicyRule).where(PolicyRule.policy_id == policy["id"]))
        assert left == 0


async def test_a_policy_edit_that_changes_nothing_is_not_recorded(client):
    created = await client.post("/policies", json={"name": "Quiet", "rules": []})
    assert created.status_code == 201, created.text
    assert (await client.patch(f"/policies/{created.json()['id']}", json={})).status_code == 200
    assert _named(await _changes(client), "policy_updated") == []


async def test_tool_set_and_assignment_changes_are_recorded(client):
    tools = (await client.get("/tools")).json()
    created = await client.post(
        "/tool-sets", json={"name": "Support", "items": [{"tool_id": tools[0]["id"], "approval": True}]}
    )
    assert created.status_code == 201, created.text
    set_id = created.json()["id"]
    assert (await client.patch("/agents/agent_customer_ops", json={"tool_set_id": set_id})).status_code == 200
    # Assigning the same set again changes nothing and adds no record.
    assert (await client.patch("/agents/agent_customer_ops", json={"tool_set_id": set_id})).status_code == 200
    assert (await client.patch(f"/tool-sets/{set_id}", json={"name": "Support v2"})).status_code == 200
    assert (await client.delete(f"/tool-sets/{set_id}")).status_code == 204

    rows = await _changes(client)
    made = _named(rows, "tool_set_created")[0]["payload"]
    assert made["tools"] == [tools[0]["name"]] and made["approval_tools"] == [tools[0]["name"]]
    assigned = _named(rows, "tool_set_assigned")
    assert len(assigned) == 1
    assert assigned[0]["payload"]["agent_id"] == "agent_customer_ops" and assigned[0]["payload"]["tool_set_id"] == set_id
    assert _named(rows, "tool_set_updated")[0]["payload"]["changed"] == ["name"]
    gone = _named(rows, "tool_set_deleted")[0]
    assert gone["result"] == "Support v2" and gone["payload"]["agent_ids"] == ["agent_customer_ops"]


async def test_member_and_removal_changes_are_recorded_and_only_team_readers_see_them(client):
    invited = await client.post("/org/invites", json={"email": "new@saturn.ai", "name": "New", "role": "operator"})
    assert invited.status_code == 201, invited.text
    accepted = await client.post("/auth/accept-invite", json={"token": invited.json()["token"], "password": "password1"})
    assert accepted.status_code == 200, accepted.text
    employee_id = accepted.json()["user"]["employee"]["id"]
    member = {"Authorization": f"Bearer {accepted.json()['token']}"}

    assert (await client.patch(f"/org/members/{employee_id}", json={"role": "viewer"})).status_code == 200
    # A title edit is not an access change.
    assert (await client.patch(f"/org/members/{employee_id}", json={"title": "Analyst"})).status_code == 200
    assert (await client.delete("/agents/agent_customer_ops")).status_code == 204
    assert (await client.delete("/mcp-servers/mcp_email")).status_code == 204

    rows = await _changes(client)
    assert _named(rows, "member_invited")[0]["payload"]["email"] == "new@saturn.ai"
    updated = _named(rows, "member_updated")
    assert len(updated) == 1
    assert updated[0]["payload"]["previous"]["role"] == "operator" and updated[0]["payload"]["role"] == "viewer"
    assert updated[0]["payload"]["changed"] == ["role"]
    assert _named(rows, "agent_deleted")[0]["payload"]["agent_id"] == "agent_customer_ops"
    assert _named(rows, "mcp_server_deleted")[0]["payload"]["mcp_server_id"] == "mcp_email"

    # The list names members and their access, so it needs team access. An operator or viewer has none.
    assert (await client.get("/activity/changes", headers=member)).status_code == 403
    # None of this shows up in the tool-call activity list.
    events = {item["event"] for item in (await client.get("/activity")).json()}
    assert not events & {"member_updated", "member_invited", "agent_deleted", "mcp_server_deleted"}


async def test_what_the_platform_does_inside_a_tenant_is_in_that_tenants_change_log(client, monkeypatch):
    async def sent(_email, _code, _locale=None):
        return None

    monkeypatch.setattr("app.shared.runtime.email_configured", lambda: True)
    monkeypatch.setattr("app.features.identity.auth.services.mailer.send_reset_code", sent)
    created = await client.post(
        "/admin/orgs",
        json={
            "name": "Acme",
            "admin_email": "admin@acme.test",
            "admin_name": "Acme Admin",
            "admin_password": "password1",
            "plan": "enterprise",
        },
    )
    assert created.status_code == 201, created.text
    org = created.json()
    added = await client.post(
        f"/admin/orgs/{org['id']}/members",
        json={"email": "planted@acme.test", "name": "Planted", "password": "password1", "role": "admin"},
    )
    assert added.status_code == 201, added.text
    assert (await client.patch(f"/admin/orgs/{org['id']}", json={"status": "trial"})).status_code == 200
    assert (await client.post(f"/admin/orgs/{org['id']}/members/{added.json()['id']}/password")).status_code == 200

    login = await client.post("/auth/login", json={"email": "admin@acme.test", "password": "password1"})
    assert login.status_code == 200, login.text
    tenant = {"Authorization": f"Bearer {login.json()['token']}"}
    from tests.totp_access import finish_totp

    await finish_totp(client, tenant)
    rows = await _changes(client, tenant)
    platform = (await client.get("/auth/me")).json()["id"]

    member = _named(rows, "member_created")
    assert [item["payload"]["email"] for item in member] == ["planted@acme.test"]
    assert member[0]["payload"]["role"] == "admin" and member[0]["payload"]["employee_id"] == added.json()["id"]
    assert _named(rows, "org_updated")[0]["payload"]["status"] == "trial"
    assert _named(rows, "member_password_reset")[0]["payload"]["employee_id"] == added.json()["id"]
    for item in member + _named(rows, "org_updated") + _named(rows, "member_password_reset"):
        assert item["actor_id"] == platform and item["payload"]["platform_admin"] is True

    # The platform's own organization sees none of it.
    assert not {item["event"] for item in await _changes(client)} & {"member_created", "org_updated", "member_password_reset"}
