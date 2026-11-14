from __future__ import annotations

import re
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import delete, insert, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.ids import new_id, utcnow
from app.models import Agent, Policy, PolicyRule
from app.shared.models.associations import agent_policies
from app.schemas import PolicyCreate, PolicyRead, PolicyRuleIn, PolicyRuleRead, PolicyUpdate
from app.features.policy.policies.services.default_policy import MARKER
from app.features.policy.policies.services.limits import (
    LLM_ORG_LIMIT,
    LLM_USER_LIMIT,
    LLM_WINDOW_SECONDS,
    MAX_AGENT_IDS,
    MAX_CONDITION_TEXT,
    MAX_CONDITIONS_BYTES,
    MAX_CONDITIONS_PER_RULE,
    MAX_DEFINITION_BYTES,
    MAX_DESCRIPTION,
    MAX_ENVIRONMENT,
    MAX_ID,
    MAX_INSTRUCTIONS,
    MAX_LLM_TOOLS,
    MAX_NAME,
    MAX_PRIORITY,
    MAX_RULES,
    MAX_TOOL_NAME,
    bad_request,
    bounded_text,
    clean_condition,
    json_size,
)
from app.features.policy.policies.services.policy_engine import (
    compile_condition,
    conditions_for,
    normalize_decision,
    parse_condition_string,
)
from app.features.policy.policies.services.policy_graph import (
    PolicyGraphTooLarge,
    compile_definition,
    normalize_definition,
)


_STATUSES = {"active", "paused", "draft", "validated"}
_AND_SPLIT = re.compile(r"\s+AND\s+", re.I)


def _status(raw: str | None) -> str:
    value = (raw or "").strip().lower()
    if value not in _STATUSES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown policy status")
    if value == "validated":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Run validation to mark a policy validated")
    return value


def _is_default(policy: Policy) -> bool:
    return (policy.description or "") == MARKER


def _description(raw: str | None) -> str:
    text = bounded_text(raw, MAX_DESCRIPTION, "Description")
    if text == MARKER:
        raise bad_request("That description is reserved")
    return text


def _name(raw: str | None) -> str:
    text = bounded_text(raw, MAX_NAME, "Name")
    if not text:
        raise bad_request("Name is required")
    return text


def _environment(raw: str | None) -> str:
    return bounded_text(raw, MAX_ENVIRONMENT, "Environment").lower() or "production"


def _agent_ids(raw: list[str]) -> list[str]:
    if len(raw) > MAX_AGENT_IDS:
        raise bad_request(f"A policy can name at most {MAX_AGENT_IDS} agents")
    return [item for item in raw if isinstance(item, str) and 0 < len(item) <= MAX_ID]


def _instructions(raw: str | None) -> str:
    return bounded_text(raw, MAX_INSTRUCTIONS, "Instructions")


def _cap_tools(count: int) -> None:
    if count > MAX_LLM_TOOLS:
        raise bad_request(
            f"The policy model reviews at most {MAX_LLM_TOOLS} tools at a time. Split the capability set and try again."
        )


def _definition(raw: dict | None) -> dict:
    """Normalize a client definition and refuse one over the size limits."""
    if json_size(raw) > MAX_DEFINITION_BYTES:
        raise bad_request(f"The policy graph is too large: at most {MAX_DEFINITION_BYTES // 1000} KB")
    definition = normalize_definition(raw)
    try:
        rules, _errors = compile_definition(definition, strict=True)
    except PolicyGraphTooLarge as exc:
        raise bad_request(str(exc)) from exc
    if any(len(str(rule["tool"])) > MAX_TOOL_NAME for rule in rules):
        raise bad_request(f"Tool names must be at most {MAX_TOOL_NAME} characters")
    return definition


async def enforce_llm_quota(user_id: str, organization_id: str) -> None:
    """Each call to these endpoints is billed by the model provider. Bound it per user and per organization."""
    from app.core.rate_limit import allow

    if not await allow(f"policy-llm:user:{user_id}", limit=LLM_USER_LIMIT, window=LLM_WINDOW_SECONDS) or not await allow(
        f"policy-llm:org:{organization_id}", limit=LLM_ORG_LIMIT, window=LLM_WINDOW_SECONDS
    ):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many policy model requests. Try again later.",
        )


def _rule_payload(rule: PolicyRuleIn, fallback_tool: str | None) -> tuple[str, str, list[dict], str, int | None]:
    try:
        decision = normalize_decision(rule.decision).value
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if len(rule.conditions or []) > MAX_CONDITIONS_PER_RULE:
        raise bad_request(f"A rule can have at most {MAX_CONDITIONS_PER_RULE} conditions")
    structured: list[dict] = []
    for item in rule.conditions or []:
        cleaned = clean_condition(item.model_dump())
        if cleaned is None:
            raise bad_request(
                "Each condition needs a field, an operator (gt, gte, lt, lte, eq or ne) and a plain value"
            )
        structured.append(cleaned)
    condition = bounded_text(rule.condition, MAX_CONDITION_TEXT, "Condition")
    if structured:
        condition = compile_condition(structured)
    elif condition and condition.lower() not in {"true", "*"}:
        structured = parse_condition_string(condition)
        if len(structured) != len(_AND_SPLIT.split(condition)):
            raise bad_request("Could not read the condition. Use field operator value, joined with AND.")
    else:
        condition = "true"
    if len(condition) > MAX_CONDITION_TEXT or json_size(structured) > MAX_CONDITIONS_BYTES:
        raise bad_request("The rule conditions are too large")
    tool = bounded_text(rule.tool or fallback_tool or "", MAX_TOOL_NAME, "Tool")
    if not tool:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Each rule needs a tool")
    priority = rule.priority
    if priority is not None:
        # Order inside this policy only. Negative values used to jump ahead of
        # every other policy's rules, so they are clamped.
        priority = max(0, min(int(priority), MAX_PRIORITY))
    return tool, condition, structured, decision, priority


def _approval_policy_id(rule: PolicyRule) -> str | None:
    attributes = rule.attributes if isinstance(rule.attributes, dict) else {}
    raw = attributes.get("approvalPolicyId") or attributes.get("approval_policy_id")
    return raw.strip() if isinstance(raw, str) and raw.strip() else None


def serialize_rule(rule: PolicyRule) -> PolicyRuleRead:
    structured = rule.conditions if isinstance(rule.conditions, list) else []
    if not structured:
        structured = parse_condition_string(rule.condition)
    return PolicyRuleRead(
        id=rule.id,
        tool=rule.tool,
        condition=rule.condition,
        conditions=structured,
        decision=rule.decision,
        position=rule.position,
        approval_policy_id=_approval_policy_id(rule),
    )


def _flat_conditions(expression: dict | None) -> list[dict] | None:
    if not isinstance(expression, dict):
        return None
    op = expression.get("op")
    if op == "true":
        return []
    if op == "cmp":
        field = str(expression.get("field") or "").strip()
        if not field:
            return []
        return [{"field": field, "operator": expression.get("operator") or "eq", "value": expression.get("value")}]
    if op == "and":
        parts: list[dict] = []
        for item in expression.get("args") or []:
            flat = _flat_conditions(item if isinstance(item, dict) else None)
            if flat is None:
                return None
            parts.extend(flat)
        return parts
    return None


def _legacy_rule(rule: PolicyRule) -> tuple[dict, str | None]:
    """A stored legacy rule in the shape the validator reads, and a problem with it if any."""
    conds = conditions_for(rule)
    text = (rule.condition or "").strip()
    problem = None
    if not conds and text and text.lower() not in {"true", "*"}:
        problem = f"Could not read a condition on {rule.tool}"
    expression = {"op": "true"} if not conds else {"op": "and", "args": [{"op": "cmp", **item} for item in conds]}
    try:
        decision = normalize_decision(rule.decision).value
    except ValueError:
        decision = "deny"
        problem = f"Unknown decision on {rule.tool}"
    return (
        {
            "id": rule.id,
            "tool": rule.tool,
            "expression": expression,
            "decision": decision,
            "attributes": rule.attributes if isinstance(rule.attributes, dict) else {},
            "position": rule.position or 0,
        },
        problem,
    )


def serialize_policy(policy: Policy) -> PolicyRead:
    rules = sorted(policy.rules, key=lambda item: item.position)
    definition = policy.definition if isinstance(policy.definition, dict) else None
    return PolicyRead(
        id=policy.id,
        name=policy.name,
        description=policy.description or "",
        status=policy.status or "active",
        version=policy.version or 1,
        environment=policy.environment or "production",
        tool_set_id=policy.tool_set_id,
        definition=definition,
        agent_ids=[agent.id for agent in policy.agents],
        rules=[serialize_rule(rule) for rule in rules],
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


class PolicyService:
    async def list_policies(self, session: AsyncSession, organization_id: str) -> list[Policy]:
        result = await session.execute(
            select(Policy)
            .options(selectinload(Policy.rules), selectinload(Policy.agents))
            .where(Policy.organization_id == organization_id)
            .order_by(Policy.created_at.asc())
        )
        return list(result.scalars().unique().all())

    async def get_policy(
        self, session: AsyncSession, policy_id: str, organization_id: str
    ) -> Policy:
        result = await session.execute(
            select(Policy)
            .options(selectinload(Policy.rules), selectinload(Policy.agents))
            .where(Policy.id == policy_id, Policy.organization_id == organization_id)
            # Reload rules and agents that an update in this session replaced.
            .execution_options(populate_existing=True)
        )
        policy = result.scalar_one_or_none()
        if policy is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")
        return policy

    async def delete_policy(self, session: AsyncSession, policy: Policy) -> None:
        if _is_default(policy):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "The organization default policy cannot be deleted. Change its rules or pause it instead.",
            )
        await session.execute(delete(agent_policies).where(agent_policies.c.policy_id == policy.id))
        # The rules go with the policy through the relationship's cascade. Deleting them here as
        # well made the cascade delete rows that were already gone.
        await session.delete(policy)
        await session.flush()

    async def _own_tool_set(self, session: AsyncSession, organization_id: str, raw: str | None) -> str | None:
        from app.models import ToolSet

        value = (raw or "").strip()
        if not value:
            return None
        found = None
        if len(value) <= MAX_ID:
            found = await session.scalar(
                select(ToolSet.id).where(ToolSet.id == value, ToolSet.organization_id == organization_id)
            )
        if found is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Capability set not found")
        return found

    async def _check_approval_policies(self, session: AsyncSession, organization_id: str, ids: set[str]) -> set[str]:
        """Return the ids that are not approval policies of this organization."""
        from app.models import ApprovalPolicy

        wanted = {item for item in ids if item}
        if not wanted:
            return set()
        candidates = {item for item in wanted if len(item) <= MAX_ID}
        found: set[str] = set()
        if candidates:
            found = set(
                (
                    await session.scalars(
                        select(ApprovalPolicy.id).where(
                            ApprovalPolicy.id.in_(candidates),
                            ApprovalPolicy.organization_id == organization_id,
                        )
                    )
                ).all()
            )
        return wanted - found

    async def _prepared_rules(
        self, session: AsyncSession, organization_id: str, rules: list[PolicyRuleIn], fallback_tool: str | None
    ) -> list[tuple[PolicyRuleIn, tuple[str, str, list[dict], str, int | None]]]:
        if len(rules) > MAX_RULES:
            raise bad_request(f"A policy can have at most {MAX_RULES} rules")
        prepared = [(rule, _rule_payload(rule, fallback_tool)) for rule in rules]
        linked = {(rule.approval_policy_id or "").strip() for rule in rules}
        if await self._check_approval_policies(session, organization_id, linked):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval policy not found")
        return prepared

    async def create_policy(
        self, session: AsyncSession, organization_id: str, body: PolicyCreate
    ) -> Policy:
        name = _name(body.name)
        description = _description(body.description)
        environment = _environment(body.environment)
        agent_ids = _agent_ids(body.agent_ids)
        definition = _definition(body.definition) if body.definition is not None else None
        tool_set_id = await self._own_tool_set(session, organization_id, body.tool_set_id)
        if definition is not None and definition.get("toolSetId"):
            definition_set = await self._own_tool_set(session, organization_id, definition["toolSetId"])
            tool_set_id = tool_set_id or definition_set
        prepared = None
        if definition is None:
            prepared = await self._prepared_rules(session, organization_id, body.rules, body.tool)
        policy = Policy(
            # Ids are always generated here. A client-chosen id leaked whether
            # another organization already used it, and could collide.
            id=new_id("policy"),
            organization_id=organization_id,
            name=name,
            description=description,
            # Every new policy starts as a draft. It applies to agents only
            # after validate and activate, where allows must be confirmed.
            status="draft",
            version=1,
            environment=environment,
            tool_set_id=tool_set_id,
            definition=definition,
        )
        session.add(policy)
        await session.flush()
        await self._set_agents(session, policy.id, organization_id, agent_ids)
        if definition is not None:
            await self._replace_compiled(session, policy.id, definition)
        else:
            await self._replace_rules(session, policy.id, prepared or [], keep_ids=set())
        await session.flush()
        return await self.get_policy(session, policy.id, organization_id)

    async def update_policy(
        self, session: AsyncSession, policy: Policy, body: PolicyUpdate
    ) -> Policy:
        from app.features.policy.policies.services.policy_graph import risky_allows

        # Check everything before changing anything: the session is committed
        # even when the request ends in an HTTP error, so a late 400 must not
        # leave half of an update behind.
        organization_id = policy.organization_id
        name = _name(body.name) if body.name is not None else None
        description = None
        if body.description is not None:
            if _is_default(policy):
                if body.description.strip() != MARKER:
                    raise bad_request("The organization default policy keeps its description")
            else:
                description = _description(body.description)
        next_status = None
        if body.status is not None and body.definition is None and body.rules is None:
            next_status = _status(body.status)
            if next_status == "active" and (policy.status or "") != "active":
                if (policy.status or "") != "validated":
                    raise HTTPException(
                        status.HTTP_400_BAD_REQUEST,
                        "Validate the policy before activating it",
                    )
                risky = risky_allows(list(policy.rules))
                if risky:
                    raise HTTPException(
                        status.HTTP_409_CONFLICT,
                        f"Confirm high-risk allows: {', '.join(risky)}",
                    )
                # PATCH cannot carry a confirmation, so a draft with flagged tools goes through activate.
                set_tools = (
                    await self._set_tool_names(session, organization_id, policy.tool_set_id) if policy.tool_set_id else []
                )
                flagged = [item["tool"] for item in (await self._review(session, policy, set_tools))["flagged_tools"]]
                if flagged:
                    raise HTTPException(
                        status.HTTP_409_CONFLICT,
                        f"Review tools with untrusted descriptions: {', '.join(flagged)}",
                    )
        environment = _environment(body.environment) if body.environment is not None else None
        tool_set_id = (
            await self._own_tool_set(session, organization_id, body.tool_set_id) if body.tool_set_id is not None else None
        )
        agent_ids = _agent_ids(body.agent_ids) if body.agent_ids is not None else None
        definition = None
        definition_set = None
        prepared = None
        if body.definition is not None:
            definition = _definition(body.definition)
            if definition.get("toolSetId"):
                definition_set = await self._own_tool_set(session, organization_id, definition["toolSetId"])
        elif body.rules is not None:
            prepared = await self._prepared_rules(session, organization_id, body.rules, body.tool)

        changed = False
        if name is not None:
            policy.name = name
            changed = True
        if description is not None:
            policy.description = description
            changed = True
        if next_status is not None:
            policy.status = next_status
            changed = True
        if environment is not None:
            policy.environment = environment
            changed = True
        if body.tool_set_id is not None:
            policy.tool_set_id = tool_set_id
            changed = True
        if agent_ids is not None:
            await self._set_agents(session, policy.id, organization_id, agent_ids)
            changed = True
        if definition is not None:
            if definition_set and body.tool_set_id is None:
                policy.tool_set_id = definition_set
            policy.definition = definition
            await self._replace_compiled(session, policy.id, definition)
            if policy.status in {"active", "validated"}:
                policy.status = "draft"
            changed = True
        elif prepared is not None:
            await self._replace_rules(session, policy.id, prepared, keep_ids={rule.id for rule in policy.rules})
            if policy.status in {"active", "validated"}:
                policy.status = "draft"
            changed = True
        if changed:
            policy.version = (policy.version or 1) + 1
            policy.updated_at = utcnow()
            await session.flush()
        return await self.get_policy(session, policy.id, organization_id)

    async def _set_agents(
        self,
        session: AsyncSession,
        policy_id: str,
        organization_id: str,
        agent_ids: list[str],
    ) -> None:
        # Check the ids before anything is removed: a refused request is still committed.
        agents = await self._load_agents(session, organization_id, agent_ids)
        await session.execute(delete(agent_policies).where(agent_policies.c.policy_id == policy_id))
        if agents:
            await session.execute(
                insert(agent_policies),
                [{"agent_id": agent.id, "policy_id": policy_id} for agent in agents],
            )

    async def _load_agents(
        self, session: AsyncSession, organization_id: str, agent_ids: list[str]
    ) -> list[Agent]:
        if not agent_ids:
            return []
        wanted = list(dict.fromkeys(agent_ids))
        result = await session.execute(
            select(Agent).where(
                Agent.organization_id == organization_id,
                Agent.id.in_(wanted),
            )
        )
        agents = list(result.scalars().all())
        # An empty agent list means every agent. Dropping an id that does not exist would
        # turn a policy meant for one agent into one that applies to all of them.
        if len(agents) != len(wanted):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Agent not found")
        return agents

    async def _replace_rules(
        self,
        session: AsyncSession,
        policy_id: str,
        prepared: list[tuple[PolicyRuleIn, tuple[str, str, list[dict], str, int | None]]],
        *,
        keep_ids: set[str],
    ) -> None:
        await session.execute(delete(PolicyRule).where(PolicyRule.policy_id == policy_id))
        await session.flush()
        used: set[str] = set()
        for index, (rule, payload) in enumerate(prepared):
            tool, condition, structured, decision, priority = payload
            approval_policy_id = (rule.approval_policy_id or "").strip()
            attributes = {"approvalPolicyId": approval_policy_id} if approval_policy_id else None
            # A client id is kept only when it already named a rule of this same
            # policy, so ids stay stable across edits without letting a client
            # pick, or probe for, a key another organization holds.
            ident = rule.id if rule.id and rule.id in keep_ids and rule.id not in used else new_id("rule")
            used.add(ident)
            session.add(
                PolicyRule(
                    id=ident,
                    policy_id=policy_id,
                    tool=tool,
                    condition=condition,
                    conditions=structured or None,
                    decision=decision,
                    position=priority if priority is not None else index,
                    attributes=attributes,
                )
            )

    async def set_inventory(self, session: AsyncSession, organization_id: str, tool_set_id: str):
        from app.models import Tool, ToolSet, ToolSetItem

        if not tool_set_id or len(tool_set_id) > MAX_ID:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Capability set not found")
        result = await session.execute(
            select(ToolSet)
            .options(
                selectinload(ToolSet.items).selectinload(ToolSetItem.tool).selectinload(Tool.mcp_server)
            )
            .where(ToolSet.id == tool_set_id, ToolSet.organization_id == organization_id)
        )
        tool_set = result.scalar_one_or_none()
        if tool_set is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Capability set not found")
        inventory = []
        for item in tool_set.items or []:
            tool = item.tool
            if tool is None or tool.status != "active":
                continue
            server = tool.mcp_server
            inventory.append(
                {
                    "name": tool.name,
                    "description": tool.description or "",
                    "inputSchema": tool.input_schema or {},
                    "server": server.name if server is not None else "",
                    "origin": tool.type or "",
                }
            )
        if not inventory:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "This capability set has no tools")
        return tool_set, inventory

    def _draft_body(self, tool_set, name: str, used_model: bool, definition: dict) -> PolicyCreate:
        description = (
            "Draft proposed from the capability set. Review every tool, then validate and activate it."
            if used_model
            else "No policy model is configured. Every tool is unclassified and denied until you review it."
        )
        return PolicyCreate(
            name=(name or "").strip()[:MAX_NAME] or f"{tool_set.name} policy"[:MAX_NAME],
            description=description,
            status="draft",
            tool_set_id=tool_set.id,
            definition=definition,
        )

    async def generate_from_set(
        self, session: AsyncSession, organization_id: str, tool_set_id: str, name: str, instructions: str = ""
    ) -> Policy:
        from app.features.policy.policies.services.policy_graph import definition_from_analyses
        from app.features.policy.policies.services.policy_llm import analyze_tools

        request = _instructions(instructions)
        bounded_text(name, MAX_NAME, "Name")
        tool_set, inventory = await self.set_inventory(session, organization_id, tool_set_id)
        _cap_tools(len(inventory))
        # The model can take minutes. Nothing is pending, so end the transaction and give the
        # connection back to the pool while it thinks.
        await session.commit()
        analyses, used_model = await analyze_tools(inventory, request)
        definition = definition_from_analyses(tool_set.id, analyses)
        return await self.create_policy(
            session, organization_id, self._draft_body(tool_set, name, used_model, definition)
        )

    async def iter_generate(
        self, session: AsyncSession, organization_id: str, tool_set_id: str, name: str, instructions: str = ""
    ):
        from app.features.policy.policies.services.policy_graph import definition_from_analyses
        from app.features.policy.policies.services.policy_llm import iter_tool_analysis

        request = _instructions(instructions)
        bounded_text(name, MAX_NAME, "Name")
        tool_set, inventory = await self.set_inventory(session, organization_id, tool_set_id)
        _cap_tools(len(inventory))
        yield {"type": "status", "code": "reading", "name": tool_set.name, "count": len(inventory)}
        # The model can take minutes. Nothing is pending, so end the transaction and give the
        # connection back to the pool while it thinks.
        await session.commit()
        analyses = None
        used_model = False
        async for kind, payload in iter_tool_analysis(inventory, request):
            if kind == "think":
                yield {"type": "think", "text": payload}
            elif kind == "status":
                yield {"type": "status", **payload}
            elif kind == "result":
                analyses, used_model = payload
        if analyses is None:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Policy model returned an unreadable response")
        definition = definition_from_analyses(tool_set.id, analyses)
        policy = await self.create_policy(
            session, organization_id, self._draft_body(tool_set, name, used_model, definition)
        )
        await session.commit()
        yield {"type": "policy", "policy": policy}

    async def _optimize_inputs(
        self, session: AsyncSession, policy: Policy, definition: dict, instructions: str
    ) -> tuple[dict, list[dict], str]:
        request = _instructions(instructions)
        document = _definition(definition)
        set_id = str(document.get("toolSetId") or "") or (policy.tool_set_id or "")
        inventory: list[dict] = []
        if set_id:
            try:
                _tool_set, inventory = await self.set_inventory(session, policy.organization_id, set_id)
            except HTTPException:
                inventory = []
        _cap_tools(max(len(inventory), sum(1 for node in document.get("nodes") or [] if node.get("type") == "tool")))
        return document, inventory, request

    async def optimize_policy(
        self, session: AsyncSession, policy: Policy, definition: dict, instructions: str = ""
    ) -> dict:
        from app.features.policy.policies.services.policy_llm import optimize_definition

        document, inventory, request = await self._optimize_inputs(session, policy, definition, instructions)
        # The model can take minutes. Nothing is pending, so end the transaction and give the
        # connection back to the pool while it thinks.
        await session.commit()
        optimized, diff = await optimize_definition(document, inventory, request)
        return {"definition": optimized, "diff": diff}

    async def iter_optimize(self, session: AsyncSession, policy: Policy, definition: dict, instructions: str = ""):
        from app.features.policy.policies.services.policy_llm import iter_optimize_definition

        document, inventory, request = await self._optimize_inputs(session, policy, definition, instructions)
        tool_count = len(inventory) or sum(1 for node in document.get("nodes") or [] if node.get("type") == "tool")
        yield {"type": "status", "code": "optimizing", "total": tool_count}
        # The model can take minutes. Nothing is pending, so end the transaction and give the
        # connection back to the pool while it thinks.
        await session.commit()
        outcome = None
        async for kind, payload in iter_optimize_definition(document, inventory, request):
            if kind == "think":
                yield {"type": "think", "text": payload}
            elif kind == "result":
                outcome = payload
        if outcome is None:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Policy model returned an unreadable response")
        optimized, diff = outcome
        yield {"type": "result", "definition": optimized, "diff": diff}

    async def _set_tool_names(self, session: AsyncSession, organization_id: str, tool_set_id: str) -> list[str]:
        from app.models import ToolSet, ToolSetItem

        result = await session.execute(
            select(ToolSet)
            .options(selectinload(ToolSet.items).selectinload(ToolSetItem.tool))
            .where(ToolSet.id == tool_set_id, ToolSet.organization_id == organization_id)
        )
        tool_set = result.scalar_one_or_none()
        if tool_set is None:
            return []
        return sorted(
            item.tool.name
            for item in tool_set.items or []
            if item.tool is not None and item.tool.status == "active"
        )

    async def validate_policy(self, session: AsyncSession, policy: Policy) -> dict:
        from app.features.policy.policies.services.policy_graph import validate_definition, validate_rules

        names = []
        if policy.tool_set_id:
            names = await self._set_tool_names(session, policy.organization_id, policy.tool_set_id)
        if isinstance(policy.definition, dict):
            report = validate_definition(policy.definition, names)
        else:
            # Legacy rules: first match by position inside this policy.
            shaped = [_legacy_rule(rule) for rule in policy.rules]
            report = validate_rules(
                [rule for rule, _problem in shaped],
                names,
                structure_errors=[problem for _rule, problem in shaped if problem],
                ordered=True,
            )
        linked: dict[str, str] = {}
        for rule in policy.rules:
            ident = _approval_policy_id(rule)
            if ident:
                linked.setdefault(ident, rule.tool)
        for ident in sorted(await self._check_approval_policies(session, policy.organization_id, set(linked))):
            report["issues"].append(
                {
                    "level": "error",
                    "code": "approval_policy",
                    "tool": linked[ident],
                    "message": f"{linked[ident]} links an approval policy that does not exist",
                }
            )
            report["ok"] = False
        report["issues"].extend(await self._unknown_fields(session, policy))
        report["review"] = await self._review(session, policy, names)
        if report["ok"] and policy.status != "active":
            policy.status = "validated"
            policy.version = (policy.version or 1) + 1
            policy.updated_at = utcnow()
            await session.flush()
        elif not report["ok"] and policy.status == "active":
            policy.status = "draft"
            policy.version = (policy.version or 1) + 1
            policy.updated_at = utcnow()
            await session.flush()
        return report

    async def _unknown_fields(self, session: AsyncSession, policy: Policy) -> list[dict]:
        """Conditions on a field the tool's input schema does not declare.

        Such a condition never matches a real call: a restriction on it applies to every call and an
        allow on it never applies. A warning, not an error, so re-validating a policy that is already
        enforced never turns it off.
        """
        from app.models import Tool

        wanted: dict[str, set[str]] = {}
        for rule in policy.rules:
            fields = _condition_fields(rule)
            if fields:
                wanted.setdefault(rule.tool, set()).update(fields)
        if not wanted:
            return []
        tools = await session.scalars(
            select(Tool).where(Tool.organization_id == policy.organization_id, Tool.name.in_(sorted(wanted)))
        )
        issues = []
        for tool in sorted(tools.all(), key=lambda item: item.name):
            schema = tool.input_schema if isinstance(tool.input_schema, dict) else {}
            properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
            if not properties:
                continue
            for field in sorted(wanted.get(tool.name, set()) - set(properties)):
                issues.append(
                    {
                        "level": "warning",
                        "code": "unknown_field",
                        "tool": tool.name,
                        "message": f"{tool.name} has no argument named {field[:128]}, so that condition never matches a call",
                    }
                )
        return issues

    async def _review(self, session: AsyncSession, policy: Policy, set_tools: list[str]) -> dict:
        """What activation will enforce, for a person to read before confirming.

        A draft may come from the policy model, which read each tool's description. A description
        that was cut short or carried hidden characters is where an injected instruction would sit,
        so those tools are named here and activation asks for confirmation.
        """
        from app.features.policy.policies.services.policy_graph import risky_allows
        from app.features.policy.policies.services.policy_llm import PROMPT_DESCRIPTION_LIMIT, hidden_characters
        from app.models import Tool

        approvals = sorted({rule.tool for rule in policy.rules if rule.decision == "approval_required"})
        names = sorted({rule.tool for rule in policy.rules} | set(set_tools))
        flagged = []
        if names:
            tools = await session.scalars(
                select(Tool).where(Tool.organization_id == policy.organization_id, Tool.name.in_(names))
            )
            for tool in sorted(tools.all(), key=lambda item: item.name):
                description = tool.description or ""
                reasons = []
                if len(" ".join(description.split())) > PROMPT_DESCRIPTION_LIMIT:
                    reasons.append("description_truncated")
                if hidden_characters(description):
                    reasons.append("hidden_characters")
                if hidden_characters(tool.name or "") or len(tool.name or "") > 128:
                    reasons.append("name_hidden_characters")
                if reasons:
                    flagged.append({"tool": tool.name, "reasons": reasons})
        return {"allows": risky_allows(list(policy.rules)), "approvals": approvals, "flagged_tools": flagged}

    async def activate_policy(self, session: AsyncSession, policy: Policy, confirm: bool) -> Policy:
        from app.features.policy.policies.services.policy_graph import risky_allows

        report = await self.validate_policy(session, policy)
        if not report["ok"]:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Policy did not pass validation")
        risky = risky_allows(list(policy.rules))
        if risky and not confirm:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"Confirm high-risk allows: {', '.join(risky)}",
            )
        flagged = [item["tool"] for item in report["review"]["flagged_tools"]]
        if flagged and not confirm:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"Review tools with untrusted descriptions: {', '.join(flagged)}",
            )
        policy.status = "active"
        policy.version = (policy.version or 1) + 1
        policy.updated_at = utcnow()
        await session.flush()
        return await self.get_policy(session, policy.id, policy.organization_id)

    async def simulate_policy(
        self,
        policy: Policy,
        tool: str,
        arguments: dict,
        agent_id: str | None,
    ) -> dict:
        from app.features.policy.policies.services.policy_engine import EvaluationResult, PolicyDecision, evaluate_graph_rules, evaluate_rules

        tool_rules = [rule for rule in policy.rules if rule.tool == tool]
        definition = policy.definition if isinstance(policy.definition, dict) else None
        if definition and definition.get("nodes"):
            if not tool_rules:
                result = EvaluationResult(decision=PolicyDecision.DENY, reason="No policy rule")
            else:
                result = evaluate_graph_rules(tool_rules, arguments, agent_id)
        elif tool_rules:
            result = evaluate_rules(tool_rules, arguments)
        else:
            result = EvaluationResult(decision=PolicyDecision.DENY, reason="No policy rule")
        return {
            "decision": result.decision.value,
            "reason": result.reason,
            "ruleId": result.matched_rule_id,
        }

    async def _replace_compiled(self, session: AsyncSession, policy_id: str, definition: dict) -> None:
        try:
            compiled, _errors = compile_definition(definition, strict=True)
        except PolicyGraphTooLarge as exc:
            raise bad_request(str(exc)) from exc
        await session.execute(delete(PolicyRule).where(PolicyRule.policy_id == policy_id))
        await session.flush()
        for index, rule in enumerate(compiled):
            try:
                decision = normalize_decision(rule["decision"]).value
            except ValueError as exc:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
            if len(str(rule["tool"])) > MAX_TOOL_NAME:
                raise bad_request(f"Tool names must be at most {MAX_TOOL_NAME} characters")
            expression = rule.get("expression") if isinstance(rule.get("expression"), dict) else {"op": "true"}
            flat = _flat_conditions(expression)
            structured = flat or []
            condition = compile_condition(structured) if flat is not None else "true"
            session.add(
                PolicyRule(
                    id=new_id("rule"),
                    policy_id=policy_id,
                    tool=str(rule["tool"]),
                    condition=condition,
                    conditions=structured or None,
                    expression=expression,
                    attributes=rule.get("attributes") or None,
                    decision=decision,
                    position=index,
                )
            )


policy_service = PolicyService()


def _condition_fields(rule: Any) -> set[str]:
    fields: set[str] = set()

    def walk(expr: Any) -> None:
        if not isinstance(expr, dict):
            return
        if expr.get("op") == "cmp" and expr.get("field"):
            fields.add(str(expr["field"]))
        for item in expr.get("args") or []:
            walk(item)

    walk(getattr(rule, "expression", None))
    for item in conditions_for(rule):
        if item.get("field"):
            fields.add(str(item["field"]))
    return fields
