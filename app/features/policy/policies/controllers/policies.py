from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse

from app.features.identity.auth.controllers.deps import (
    CurrentUser,
    PoliciesRead,
    PoliciesWrite,
    ProPlan,
    SaturnCloud,
    SessionDep,
)
from app.core.enums import AuditEvent
from app.features.execution.activity.services.change_log import record_change
from app.models import Organization
from app.features.organization.org.services.plans import allows_pro
from app.schemas import (
    PolicyActivate,
    PolicyCreate,
    PolicyGenerate,
    PolicyOptimize,
    PolicyRead,
    PolicySimulate,
    PolicyUpdate,
)
from app.features.policy.policies.services.policy_service import enforce_llm_quota, policy_service, serialize_policy

router = APIRouter(prefix="/policies", tags=["policies"])


@router.get("", response_model=list[PolicyRead])
async def list_policies(session: SessionDep, user: CurrentUser, _access: PoliciesRead):
    org = await session.get(Organization, user.organization_id)
    if org is None or not allows_pro(org.plan):
        return []
    policies = await policy_service.list_policies(session, user.organization_id)
    return [serialize_policy(policy) for policy in policies]


@router.get("/{policy_id}", response_model=PolicyRead)
async def get_policy(policy_id: str, session: SessionDep, user: CurrentUser, _access: PoliciesRead, _pro: ProPlan):
    policy = await policy_service.get_policy(session, policy_id, user.organization_id)
    return serialize_policy(policy)


@router.post("/generate", response_model=PolicyRead, status_code=201)
async def generate_policy(
    body: PolicyGenerate, session: SessionDep, user: CurrentUser, _access: PoliciesWrite, _cloud: SaturnCloud, _pro: ProPlan
):
    await enforce_llm_quota(user.id, user.organization_id)
    policy = await policy_service.generate_from_set(
        session, user.organization_id, body.tool_set_id, body.name, body.instructions
    )
    await _record(session, user, AuditEvent.POLICY_CREATED, policy, drafted_by="model")
    return serialize_policy(policy)


async def _record(session, user, event: AuditEvent, policy, **details) -> None:
    await record_change(
        session,
        user,
        event,
        result=policy.status,
        policy_id=policy.id,
        policy_name=policy.name,
        version=policy.version,
        agent_ids=sorted(agent.id for agent in policy.agents),
        tool_set_id=policy.tool_set_id,
        **details,
    )


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False, default=str)}\n\n"


@router.post("/generate/stream")
async def generate_policy_stream(
    body: PolicyGenerate, session: SessionDep, user: CurrentUser, _access: PoliciesWrite, _cloud: SaturnCloud, _pro: ProPlan
):
    await enforce_llm_quota(user.id, user.organization_id)

    async def events():
        try:
            async for event in policy_service.iter_generate(
                session, user.organization_id, body.tool_set_id, body.name, body.instructions
            ):
                if event.get("type") == "policy":
                    await _record(session, user, AuditEvent.POLICY_CREATED, event["policy"], drafted_by="model")
                    yield _sse({"type": "policy", "policy": serialize_policy(event["policy"]).model_dump(mode="json")})
                else:
                    yield _sse(event)
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, str) else "Policy model request failed"
            yield _sse({"type": "error", "message": detail})
        except Exception:
            yield _sse({"type": "error", "message": "Could not save the policy draft"})

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("", response_model=PolicyRead, status_code=201)
async def create_policy(
    body: PolicyCreate, session: SessionDep, user: CurrentUser, _access: PoliciesWrite, _cloud: SaturnCloud, _pro: ProPlan
):
    if not body.name.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Name is required")
    policy = await policy_service.create_policy(session, user.organization_id, body)
    await _record(session, user, AuditEvent.POLICY_CREATED, policy)
    return serialize_policy(policy)


@router.patch("/{policy_id}", response_model=PolicyRead)
async def update_policy(
    policy_id: str,
    body: PolicyUpdate,
    session: SessionDep,
    user: CurrentUser,
    _access: PoliciesWrite,
    _cloud: SaturnCloud, _pro: ProPlan,
):
    policy = await policy_service.get_policy(session, policy_id, user.organization_id)
    before = {"status": policy.status, "version": policy.version}
    policy = await policy_service.update_policy(session, policy, body)
    if policy.version != before["version"]:
        await _record(
            session,
            user,
            AuditEvent.POLICY_UPDATED,
            policy,
            previous_status=before["status"],
            previous_version=before["version"],
            changed=sorted(body.model_fields_set),
        )
    return serialize_policy(policy)


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: str, session: SessionDep, user: CurrentUser, _access: PoliciesWrite, _cloud: SaturnCloud, _pro: ProPlan
):
    policy = await policy_service.get_policy(session, policy_id, user.organization_id)
    await _record(session, user, AuditEvent.POLICY_DELETED, policy)
    await policy_service.delete_policy(session, policy)


@router.post("/{policy_id}/validate")
async def validate_policy(
    policy_id: str, session: SessionDep, user: CurrentUser, _access: PoliciesWrite, _cloud: SaturnCloud, _pro: ProPlan
):
    policy = await policy_service.get_policy(session, policy_id, user.organization_id)
    report = await policy_service.validate_policy(session, policy)
    fresh = await policy_service.get_policy(session, policy_id, user.organization_id)
    return {"report": report, "policy": serialize_policy(fresh)}


@router.post("/{policy_id}/activate", response_model=PolicyRead)
async def activate_policy(
    policy_id: str,
    body: PolicyActivate,
    session: SessionDep,
    user: CurrentUser,
    _access: PoliciesWrite,
    _cloud: SaturnCloud, _pro: ProPlan,
):
    policy = await policy_service.get_policy(session, policy_id, user.organization_id)
    previous = policy.status
    policy = await policy_service.activate_policy(session, policy, body.confirm)
    await _record(session, user, AuditEvent.POLICY_ACTIVATED, policy, previous_status=previous)
    return serialize_policy(policy)


@router.post("/{policy_id}/optimize")
async def optimize_policy(
    policy_id: str,
    body: PolicyOptimize,
    session: SessionDep,
    user: CurrentUser,
    _access: PoliciesWrite,
    _cloud: SaturnCloud, _pro: ProPlan,
):
    policy = await policy_service.get_policy(session, policy_id, user.organization_id)
    await enforce_llm_quota(user.id, user.organization_id)
    return await policy_service.optimize_policy(session, policy, body.definition, body.instructions)


@router.post("/{policy_id}/optimize/stream")
async def optimize_policy_stream(
    policy_id: str,
    body: PolicyOptimize,
    session: SessionDep,
    user: CurrentUser,
    _access: PoliciesWrite,
    _cloud: SaturnCloud, _pro: ProPlan,
):
    policy = await policy_service.get_policy(session, policy_id, user.organization_id)
    await enforce_llm_quota(user.id, user.organization_id)

    async def events():
        try:
            async for event in policy_service.iter_optimize(session, policy, body.definition, body.instructions):
                yield _sse(event)
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, str) else "Policy model request failed"
            yield _sse({"type": "error", "message": detail})
        except Exception:
            yield _sse({"type": "error", "message": "Could not save the optimized policy"})

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/{policy_id}/simulate")
async def simulate_policy(
    policy_id: str,
    body: PolicySimulate,
    session: SessionDep,
    user: CurrentUser,
    _access: PoliciesRead,
    _pro: ProPlan,
):
    policy = await policy_service.get_policy(session, policy_id, user.organization_id)
    if not body.tool.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Tool is required")
    return await policy_service.simulate_policy(policy, body.tool.strip(), body.arguments, body.agent_id)
