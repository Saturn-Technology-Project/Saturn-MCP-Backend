from enum import Enum


class ToolStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"


class ToolType(str, Enum):
    MCP = "mcp"


class RunStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ActionStatus(str, Enum):
    PENDING = "pending"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    DENIED = "denied"
    FAILED = "failed"
    REJECTED = "rejected"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    INVALIDATED = "invalidated"


class ExecutionState(str, Enum):
    """How far the approved call has got. An approval stays "approved" while its call runs."""

    NONE = "none"
    CLAIMED = "claimed"
    EXECUTED = "executed"
    UNCERTAIN = "uncertain"
    FAILED = "failed"


class ExpiryPhase(str, Enum):
    """Which deadline passed: nobody decided in time, or the approved call was never sent again."""

    PENDING = "pending"
    RESUBMIT = "resubmit"


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    APPROVAL_REQUIRED = "approval_required"
    DENY = "deny"


class ActorType(str, Enum):
    USER = "user"
    AGENT = "agent"
    SYSTEM = "system"


class AuditEvent(str, Enum):
    RUN_CREATED = "run_created"
    AGENT_STARTED = "agent_started"
    TOOL_REQUESTED = "tool_requested"
    POLICY_EVALUATED = "policy_evaluated"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_REJECTED = "approval_rejected"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_QUORUM = "approval_quorum"
    APPROVAL_INVALIDATED = "approval_invalidated"
    EXECUTION_CLAIMED = "execution_claimed"
    GROUP_UPDATED = "group_updated"
    TOOL_EXECUTED = "tool_executed"
    RUN_COMPLETED = "run_completed"
    RUN_FAILED = "run_failed"
    PROMPT_UPDATED = "prompt_updated"
    CREDENTIAL_ACCESSED = "credential_accessed"
    CONTENT_REVEALED = "content_revealed"
    MCP_OAUTH_REFUSED = "mcp_oauth_refused"
    POLICY_PAUSED = "policy_paused"
    POLICY_CREATED = "policy_created"
    POLICY_UPDATED = "policy_updated"
    POLICY_ACTIVATED = "policy_activated"
    POLICY_DELETED = "policy_deleted"
    TOOL_SET_CREATED = "tool_set_created"
    TOOL_SET_UPDATED = "tool_set_updated"
    TOOL_SET_DELETED = "tool_set_deleted"
    TOOL_SET_ASSIGNED = "tool_set_assigned"
    MEMBER_INVITED = "member_invited"
    MEMBER_UPDATED = "member_updated"
    # Written when a platform admin acts inside a tenant.
    MEMBER_CREATED = "member_created"
    MEMBER_PASSWORD_RESET = "member_password_reset"  # noqa: S105 (an event name)
    ORG_UPDATED = "org_updated"
    INVITE_REVOKED = "invite_revoked"
    AGENT_DELETED = "agent_deleted"
    MCP_SERVER_DELETED = "mcp_server_deleted"
