async def test_seed_admin_has_org_access(client):
    me = (await client.get("/auth/me")).json()
    assert me["role"] == "admin"
    assert me["permissions"]["team"] == "write"
    assert me["permissions"]["agents"] == "write"
    assert me["employee"]["role"] == "admin"

    org = (await client.get("/org")).json()
    assert org["organization"]["id"] == "org_saturn"
    assert {item["id"] for item in org["catalog"]["resources"]} == {
        "agents",
        "policies",
        "approvals",
        "team",
    }
    members = (await client.get("/org/members")).json()
    assert any(member["email"] == "rick@saturn.ai" for member in members)
    org = (await client.get("/org")).json()
    assert org["mcp_gateway"]["connected"] == 3
    assert org["mcp_gateway"]["total"] == 3
    assert any(agent["id"] == "agent_customer_ops" for agent in org["agents"])


async def test_cannot_remove_last_admin(client):
    members = (await client.get("/org/members")).json()
    admin = next(member for member in members if member["email"] == "rick@saturn.ai")
    response = await client.patch(f"/org/members/{admin['id']}", json={"role": "viewer"})
    assert response.status_code == 409


async def test_invite_accept_and_enforce_permissions(client):
    invited = await client.post(
        "/org/invites",
        json={
            "email": "viewer@saturn.ai",
            "name": "Viewer",
            "title": "Analyst",
            "role": "viewer",
            "agent_ids": ["agent_customer_ops"],
            "mcp_server_ids": ["mcp_crm", "mcp_billing", "mcp_email"],
        },
    )
    assert invited.status_code == 201, invited.text
    token = invited.json()["token"]
    assert token.startswith("inv_")

    accepted = await client.post(
        "/auth/accept-invite",
        json={"token": token, "password": "password1"},
    )
    assert accepted.status_code == 200, accepted.text
    body = accepted.json()
    assert body["user"]["email"] == "viewer@saturn.ai"
    assert body["user"]["role"] == "viewer"
    assert body["user"]["permissions"]["agents"] == "read"
    assert body["user"]["permissions"]["team"] == "none"

    headers = {"Authorization": f"Bearer {body['token']}"}
    assert (await client.get("/org/members", headers=headers)).status_code == 403
    assert (await client.post("/org/invites", headers=headers, json={
        "email": "other@saturn.ai",
        "name": "Other",
    })).status_code == 403
    assert (await client.get("/agents", headers=headers)).status_code == 200
    assert (await client.post(
        "/agents",
        headers=headers,
        json={"name": "Shadow", "description": "", "model": "claude-sonnet"},
    )).status_code == 403
    assert (await client.get("/policies", headers=headers)).status_code == 200
    assert (await client.post(
        "/policies",
        headers=headers,
        json={"name": "No", "rules": []},
    )).status_code == 403


async def test_operator_can_run_but_not_manage_team(client):
    invited = await client.post(
        "/org/invites",
        json={
            "email": "ops@saturn.ai",
            "name": "Ops",
            "role": "operator",
            "agent_ids": ["agent_customer_ops"],
            "mcp_server_ids": ["mcp_billing", "mcp_crm", "mcp_email"],
        },
    )
    assert invited.status_code == 201, invited.text
    accepted = await client.post(
        "/auth/accept-invite",
        json={"token": invited.json()["token"], "password": "password1"},
    )
    headers = {"Authorization": f"Bearer {accepted.json()['token']}"}
    created = await client.post(
        "/agents",
        headers=headers,
        json={"name": "Ops Agent", "description": "", "model": "claude-sonnet"},
    )
    assert created.status_code == 201, created.text
    assert (await client.get("/org/members", headers=headers)).status_code == 403
    run = await client.post(
        "/runs",
        headers=headers,
        json={"agent_id": "agent_customer_ops", "input": "Refund 50 for Acme"},
    )
    assert run.status_code == 201


async def test_admin_can_change_member_access(client):
    invited = await client.post(
        "/org/invites",
        json={"email": "temp@saturn.ai", "name": "Temp", "role": "viewer"},
    )
    accepted = await client.post(
        "/auth/accept-invite",
        json={"token": invited.json()["token"], "password": "password1"},
    )
    employee_id = accepted.json()["user"]["employee"]["id"]
    updated = await client.patch(
        f"/org/members/{employee_id}",
        json={
            "role": "operator",
            "title": "Support",
            "agent_ids": ["agent_customer_ops"],
        },
    )
    assert updated.status_code == 200, updated.text
    body = updated.json()
    assert body["role"] == "operator"
    assert body["title"] == "Support"
    assert body["permissions"]["approvals"] == "write"
    assert "agent_customer_ops" in body["agent_ids"]


async def test_a_member_without_agent_access_is_not_sent_agents_through_the_summaries(client):
    """GET /agents refuses them, so GET /org and GET /auth/me must not hand the same list over."""
    invited = await client.post(
        "/org/invites",
        json={
            "email": "approver@saturn.ai",
            "name": "Approver",
            "role": "custom",
            "permissions": {"agents": "none", "policies": "none", "approvals": "write", "team": "none"},
        },
    )
    assert invited.status_code == 201, invited.text
    accepted = await client.post("/auth/accept-invite", json={"token": invited.json()["token"], "password": "password1"})
    assert accepted.status_code == 200, accepted.text
    headers = {"Authorization": f"Bearer {accepted.json()['token']}"}

    assert (await client.get("/agents", headers=headers)).status_code == 403
    for body in (
        accepted.json()["user"],
        (await client.get("/auth/me", headers=headers)).json(),
        (await client.get("/org", headers=headers)).json(),
    ):
        assert body["agents"] == [] and body["mcp_servers"] == []
        assert body.get("tool_sets", []) == [] and body["users"] == []

    # Someone who may read agents still gets them.
    mine = (await client.get("/org")).json()
    assert mine["agents"] and mine["mcp_servers"]
    assert (await client.get("/auth/me")).json()["agents"]
