from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.features.execution.approvals.models.approval import ApprovalPolicy
from app.features.execution.approvals.services.approval_policy_service import approval_policy_service
from app.features.identity.auth.controllers.deps import (
    ActorDep,
    CurrentUser,
    PoliciesRead,
    PoliciesWrite,
    SessionDep,
)

router = APIRouter(prefix="/org/approval-policies", tags=["approval-policies"])


# Groups one approval policy may name. Far above any real policy; it bounds the request.
MAX_REQUIREMENTS = 50


class ApprovalRequirementRead(BaseModel):
    group_id: str
    group_name: str = ""
    required_count: int


class ApprovalRequirementWrite(BaseModel):
    group_id: str = Field(max_length=64)
    required_count: int = 1


class ApprovalPolicyRead(BaseModel):
    id: str
    name: str
    status: str
    required_count: int
    group_id: str | None = None
    requirements: list[ApprovalRequirementRead] = []
    allow_requester: bool
    expires_minutes: int | None = None
    resubmit_minutes: int | None = None
    version: int


class ApprovalPolicyWrite(BaseModel):
    # The column holds 255 characters. Longer names used to reach the database and fail there.
    name: str = Field(max_length=255)
    required_count: int = 1
    group_id: str | None = Field(default=None, max_length=64)
    requirements: list[ApprovalRequirementWrite] | None = Field(default=None, max_length=MAX_REQUIREMENTS)
    allow_requester: bool = False
    expires_minutes: int | None = None
    resubmit_minutes: int | None = None


class ApprovalPolicyUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    status: str | None = Field(default=None, max_length=32)
    required_count: int | None = None
    group_id: str | None = Field(default=None, max_length=64)
    requirements: list[ApprovalRequirementWrite] | None = Field(default=None, max_length=MAX_REQUIREMENTS)
    clear_group: bool = False
    allow_requester: bool | None = None
    expires_minutes: int | None = None
    resubmit_minutes: int | None = None


def serialize_policy(policy: ApprovalPolicy) -> ApprovalPolicyRead:
    return ApprovalPolicyRead(
        id=policy.id,
        name=policy.name,
        status=policy.status,
        required_count=policy.required_count,
        group_id=policy.group_id,
        requirements=[
            ApprovalRequirementRead(
                group_id=item.group_id,
                group_name=item.group.name if item.group is not None else "",
                required_count=item.required_count,
            )
            for item in policy.requirements
        ],
        allow_requester=policy.allow_requester,
        expires_minutes=policy.expires_minutes,
        resubmit_minutes=policy.resubmit_minutes,
        version=policy.version or 1,
    )


@router.get("", response_model=list[ApprovalPolicyRead])
async def list_approval_policies(session: SessionDep, user: CurrentUser, _access: PoliciesRead):
    policies = await approval_policy_service.list_policies(session, user.organization_id)
    return [serialize_policy(item) for item in policies]


@router.post("", response_model=ApprovalPolicyRead, status_code=201)
async def create_approval_policy(
    body: ApprovalPolicyWrite,
    session: SessionDep,
    user: CurrentUser,
    actor_id: ActorDep,
    _access: PoliciesWrite,
):
    policy = await approval_policy_service.create_policy(
        session,
        user.organization_id,
        actor_id=actor_id,
        name=body.name,
        required_count=body.required_count,
        group_id=body.group_id,
        requirements=[item.model_dump() for item in body.requirements] if body.requirements is not None else None,
        allow_requester=body.allow_requester,
        expires_minutes=body.expires_minutes,
        resubmit_minutes=body.resubmit_minutes,
    )
    return serialize_policy(policy)


@router.patch("/{policy_id}", response_model=ApprovalPolicyRead)
async def update_approval_policy(
    policy_id: str,
    body: ApprovalPolicyUpdate,
    session: SessionDep,
    user: CurrentUser,
    actor_id: ActorDep,
    _access: PoliciesWrite,
):
    policy = await approval_policy_service.update_policy(
        session,
        user.organization_id,
        policy_id,
        actor_id=actor_id,
        name=body.name,
        status_name=body.status,
        required_count=body.required_count,
        group_id=body.group_id,
        requirements=[item.model_dump() for item in body.requirements] if body.requirements is not None else None,
        clear_group=body.clear_group,
        allow_requester=body.allow_requester,
        expires_minutes=body.expires_minutes,
        resubmit_minutes=body.resubmit_minutes,
    )
    return serialize_policy(policy)
