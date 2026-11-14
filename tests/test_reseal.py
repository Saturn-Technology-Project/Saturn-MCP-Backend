import hashlib
import hmac
import json

from sqlalchemy import select

from app.cli.reseal import Keys, main, reseal
from app.features.credentials.vault.services import pq_crypto

OLD_ROOT = b"\x11" * 32  # the root conftest installs
NEW_ROOT = b"\x22" * 32


def _local(root: bytes):
    return lambda data: hmac.new(root, data, hashlib.sha256).digest()


def test_keys_derive_what_pq_crypto_derives():
    from app.features.execution.activity.services.content_seal import open_json, seal_json
    from app.features.execution.approvals.services.approval_arguments import keyed_digest

    keys = Keys(_local(OLD_ROOT))
    assert pq_crypto.open_secret(keys.seal("token", "org_a", "user_a"), "org_a", "user_a") == "token"
    assert keys.open(pq_crypto.seal("token", "org_a", ""), "org_a", "") == "token"
    assert keys.open(pq_crypto.seal("token", "org_a", ""), "org_b", "") is None
    assert open_json("org_a", keys.seal_content(b'{"a":1}', "org_a")) == {"a": 1}
    assert keys.open_content(seal_json("org_a", {"a": 1}), "org_a") == b'{"a":1}'
    assert keys.digest("org_a", {"amount": 5}) == keyed_digest("org_a", {"amount": 5})


async def test_reseal_moves_every_sealed_value_to_the_new_key(client):
    from app.core.ids import utcnow
    from app.db.database import get_session
    from app.main import app
    from app.models import SecretVault, User
    from app.features.execution.activity.services.content_seal import seal_json

    override = app.dependency_overrides[get_session]
    generator = override()
    session = await anext(generator)
    try:
        user = (await session.scalars(select(User).where(User.email == "rick@saturn.ai"))).one()
        organization_id, user_id = user.organization_id, user.id
        user.totp_secret = pq_crypto.seal("JBSWY3DPEHPK3PXP", organization_id, user_id)
        # The vault table does not name its tenant; the tool finds it by trying each one.
        session.add(SecretVault(id="vault-org", ciphertext=pq_crypto.seal("org-secret", organization_id), updated_at=utcnow()))
        session.add(SecretVault(id="vault-content", ciphertext=seal_json(organization_id, {"q": "x"}), updated_at=utcnow()))
        await session.commit()

        old, new = Keys(_local(OLD_ROOT)), Keys(_local(NEW_ROOT))
        connection = await session.connection()
        dry = await reseal(connection, old, new, apply=False)
        assert dry.resealed == {"users": 1, "secret_vault": 2} and not dry.unopened
        await session.rollback()
        assert pq_crypto.open_secret((await session.get(User, user_id)).totp_secret, organization_id, user_id)

        connection = await session.connection()
        report = await reseal(connection, old, new, apply=True)
        await session.commit()
        assert report.resealed == {"users": 1, "secret_vault": 2} and not report.unopened

        session.expire_all()
        totp = (await session.get(User, user_id)).totp_secret
        vault = (await session.get(SecretVault, "vault-org")).ciphertext
        content = (await session.get(SecretVault, "vault-content")).ciphertext
        assert old.open(totp, organization_id, user_id) is None
        assert new.open(totp, organization_id, user_id) == "JBSWY3DPEHPK3PXP"
        assert new.open(vault, organization_id, "") == "org-secret"
        assert new.open_content(content, organization_id) == b'{"q":"x"}'

        # A second run finds nothing the old key opens, and refuses to pretend otherwise.
        again = await reseal(await session.connection(), old, new, apply=False)
        assert again.resealed == {} and len(again.unopened) == 3
        await session.rollback()
    finally:
        await generator.aclose()


def test_command_refuses_the_same_key_twice(capsys):
    try:
        main(["--old-key", "k/1", "--new-key", "k/1"])
    except SystemExit as exit:
        assert exit.code == 2
    assert "the same" in capsys.readouterr().err


async def test_tenant_text_that_looks_sealed_does_not_block_a_reseal(client):
    from app.db.database import get_session
    from app.main import app
    from app.models import User

    from app.cli.reseal import sealed_location

    assert sealed_location("secret_vault vault-1 ciphertext")
    assert sealed_location("users u1 totp_secret")
    assert sealed_location("audit_logs a1 payload.sealed")
    assert not sealed_location("users u1 name")
    assert not sealed_location("agents a1 settings.instructions")

    generator = app.dependency_overrides[get_session]()
    session = await anext(generator)
    try:
        user = (await session.scalars(select(User).where(User.email == "rick@saturn.ai"))).one()
        user.name = "pq2.not-really-sealed"
        await session.commit()
        report = await reseal(await session.connection(), Keys(_local(OLD_ROOT)), Keys(_local(NEW_ROOT)), apply=False)
        assert not report.unopened
        assert any(item.endswith(" name") for item in report.ignored)
        await session.rollback()
    finally:
        await generator.aclose()


async def test_reseal_binds_old_vault_rows_to_their_entry(client):
    from app.core.ids import utcnow
    from app.db.database import get_session
    from app.features.credentials.vault.services.pq_crypto import split_bound
    from app.main import app
    from app.models import SecretVault, User

    generator = app.dependency_overrides[get_session]()
    session = await anext(generator)
    try:
        user = (await session.scalars(select(User).where(User.email == "rick@saturn.ai"))).one()
        organization_id = user.organization_id
        session.add(SecretVault(id="mcp-legacy", ciphertext=pq_crypto.seal("tok", organization_id), updated_at=utcnow()))
        session.add(SecretVault(id="mcp-bound", ciphertext=pq_crypto.seal("tok2", organization_id, "", "vault:mcp-bound"), updated_at=utcnow()))
        await session.commit()
        old, new = Keys(_local(OLD_ROOT)), Keys(_local(NEW_ROOT))
        await reseal(await session.connection(), old, new, apply=True)
        await session.commit()
        session.expire_all()
        legacy = (await session.get(SecretVault, "mcp-legacy")).ciphertext
        bound = (await session.get(SecretVault, "mcp-bound")).ciphertext
        assert split_bound(legacy)[0] == "vault:mcp-legacy"
        assert split_bound(bound)[0] == "vault:mcp-bound"
        assert new.open(legacy, organization_id, "") == "tok"
        assert new.open(bound, organization_id, "") == "tok2"
    finally:
        await generator.aclose()


async def test_reseal_recomputes_the_digests_a_waiting_approval_is_checked_against(client):
    """The gateway stores {digest, sealed, encryption}; both digests must follow the key."""
    from app.core.ids import new_id
    from app.db.database import get_session
    from app.features.execution.approvals.services.approval_arguments import keyed_digest, legacy_digest, server_sealed
    from app.main import app
    from app.models import Action, Approval, Run, User

    generator = app.dependency_overrides[get_session]()
    session = await anext(generator)
    try:
        user = (await session.scalars(select(User).where(User.email == "rick@saturn.ai"))).one()
        organization_id = user.organization_id
        arguments = {"amount": 900, "to": "acct_1"}

        def waiting(stored, digest):
            run = Run(id=new_id("run"), organization_id=organization_id, agent_id="agent_customer_ops", input="billing.refund", status="waiting_approval")
            action = Action(id=new_id("act"), run_id=run.id, tool="billing.refund", arguments=stored, status="waiting_approval")
            approval = Approval(id=new_id("apr"), run_id=run.id, action_id=action.id, status="pending", parameter_digest=digest)
            session.add_all([run, action, approval])
            return action.id, approval.id

        digest = keyed_digest(organization_id, arguments)
        sealed_action, sealed_approval = waiting({"digest": digest, **server_sealed(organization_id, arguments)}, digest)
        # Rows from before digests were keyed hold a plain SHA-256, which no key change touches.
        old_action, old_approval = waiting(dict(arguments), legacy_digest(arguments))
        # Sealed for the organization's own key: the server cannot recompute these, and says so.
        zero_action, zero_approval = waiting({"digest": digest, "envelope": {"org_key_version": 1}, "encryption": "payload-v1"}, digest)
        await session.commit()

        old, new = Keys(_local(OLD_ROOT)), Keys(_local(NEW_ROOT))
        report = await reseal(await session.connection(), old, new, apply=True)
        await session.commit()
        session.expire_all()

        assert report.digests == 2
        moved = new.digest(organization_id, arguments)
        action = await session.get(Action, sealed_action)
        assert action.arguments["digest"] == moved
        assert json.loads(new.open_content(action.arguments["sealed"], organization_id)) == arguments
        assert (await session.get(Approval, sealed_approval)).parameter_digest == moved

        assert (await session.get(Action, old_action)).arguments == arguments
        assert (await session.get(Approval, old_approval)).parameter_digest == legacy_digest(arguments)

        assert (await session.get(Action, zero_action)).arguments["digest"] == digest
        assert (await session.get(Approval, zero_approval)).parameter_digest == digest
        assert sorted(item.split(":")[0] for item in report.digests_left) == sorted([f"actions {zero_action}", f"approvals {zero_approval}"])
        assert not report.unopened
    finally:
        await generator.aclose()


class _Store:
    def __init__(self, entries):
        self.entries = dict(entries)
        self.written = []

    def names(self):
        return sorted(self.entries)

    def read(self, name):
        return self.entries[name]

    def write(self, name, blob):
        self.written.append(name)
        self.entries[name] = blob


def test_reseal_moves_secret_manager_entries_and_can_be_repeated():
    from app.cli.reseal import Report, Tenants, reseal_store, write_store
    from app.features.credentials.vault.services.secret_vault import _gcp_name, _legacy_gcp_name, vault_context

    old, new = Keys(_local(OLD_ROOT)), Keys(_local(NEW_ROOT))
    tenants = Tenants({"user_a": "org_a", "user_b": "org_b"}, ["org_a", "org_b"])
    named, personal, legacy = _gcp_name("mcp-1", "org_a"), _gcp_name("mcp-2", "org_b"), _legacy_gcp_name("mcp-3")
    store = _Store(
        {
            named: old.seal("token-1", "org_a", "", vault_context("mcp-1")),
            personal: old.seal("token-2", "org_b", "user_b", vault_context("mcp-2")),
            legacy: old.seal("token-3", "org_b", ""),
            "sat-not-ours": "plain text that is not a sealed value",
            # Named for org_a but sealed for org_b: the name decides whose key is tried.
            _gcp_name("mcp-4", "org_a"): old.seal("token-4", "org_b", ""),
        }
    )
    stray = _gcp_name("mcp-4", "org_a")

    report = Report()
    pending = reseal_store(store, old, new, tenants, report)
    assert report.resealed == {"secret_manager": 3}
    assert report.unopened == [f"secret_manager {stray} ciphertext"]
    assert store.written == []  # reading decides nothing is written yet

    write_store(store, pending)
    assert sorted(store.written) == sorted([named, personal, legacy])
    assert new.open(store.entries[named], "org_a", "") == "token-1"
    assert pq_crypto.split_bound(store.entries[named])[0] == vault_context("mcp-1")
    assert new.open(store.entries[personal], "org_b", "user_b") == "token-2"
    assert new.open(store.entries[legacy], "org_b", "") == "token-3"
    assert old.open(store.entries[named], "org_a", "") is None

    # A second run after a partial failure: what already moved is skipped, not reported as lost.
    again = Report()
    assert reseal_store(store, old, new, tenants, again) == []
    assert len(again.already) == 3 and again.unopened == [f"secret_manager {stray} ciphertext"]
