# AgentAuth MCP — Test Plan

You have access to the AgentAuth MCP server. Work through every test below in
order, calling the appropriate MCP tools for each one. After each test report
whether it passed or failed and why, then continue to the next. Keep track of
IDs, keys, and tokens as you go — later tests depend on them.

At the end, print a summary table: test number, name, and PASS/FAIL.

### Naming convention

To avoid collisions with previous runs, prefix all agent names with a short
unique tag derived from the current timestamp (e.g., `t1710-mcp-test-bot`).
The plan uses bare names like `mcp-test-bot` for readability — prepend your
prefix when calling the tools.

### Variable tracker

Maintain a running list of variables as you go. At minimum track:

| Variable | Description |
|----------|-------------|
| **test-bot-id** | mcp-test-bot agent id |
| **test-bot-key** | mcp-test-bot api_key from quickstart |
| **unrelated-bot-id** | mcp-unrelated-bot agent id |
| **unrelated-bot-key** | mcp-unrelated-bot api_key |
| **token-A … token-D** | access tokens as introduced |
| **refresh-A … refresh-D** | paired refresh tokens |
| **token-U** | mcp-unrelated-bot access token |
| **cred-1, cred-2, cred-U** | credential ids |

---

## Section 1 — Discovery

**Test 1.1 — Fetch service capabilities**
Call the discover tool. Confirm the response includes supported grant types,
a list of available scopes, and token lifetime values (access and refresh).
Expected: 200, non-empty capabilities object.

---

## Section 2 — Agent Registration

**Test 2.1 — Register a root agent via quickstart**
Register a new root agent: name `mcp-test-bot`, agent_type `autonomous`,
description `MCP smoke test agent`. Note the agent id, api_key, access_token,
and refresh_token from the response — they are used throughout this test plan.
Expected: agent created with trust_level `root`, api_key shown once, valid
access_token and refresh_token returned.

**Test 2.2 — Duplicate root agent name is rejected (Task 7.3)**
Call quickstart again with the identical name `mcp-test-bot` and agent_type
`autonomous`. Expected: 409 Conflict. The error body must be RFC 7807 format
with `detail.status == 409`,
`detail.type == "https://agentauth.dev/problems/agent-name-conflict"`, and
the name `mcp-test-bot` mentioned in `detail.detail`.

**Test 2.3 — Two distinct root agent names both succeed (Task 7.3)**
Call quickstart twice: once with name `mcp-alpha-bot` agent_type `tool`,
then with name `mcp-beta-bot` agent_type `tool`. Note both agent ids.
Expected: both return 201 with distinct agent ids.

---

## Section 3 — Authentication & Token Lifecycle

Quickstart credentials are created with empty scopes. To test scoped
authentication, first create a scoped credential with create_credential.

**Test 3.1 — Create a scoped credential and authenticate**
Call create_credential for mcp-test-bot's agent id using its quickstart
access_token, requesting scopes `["agents.read", "agents.write"]`. Note the
credential_id and raw_key.
Then authenticate with the new raw_key, requesting only scope `agents.read`.
Note this access_token (call it **token-A**) and its paired refresh_token
(call it **refresh-A**).
Expected: access_token and refresh_token present, token_type `Bearer`,
scope `agents.read`.

**Test 3.2 — Introspect a valid token**
Introspect token-A. Expected: `active: true`, claims include `sub` matching
mcp-test-bot's agent id, `scopes` containing `agents.read`, and an `exp`
timestamp in the future.

**Test 3.3 — Scope escalation is rejected**
Using the same raw_key from Test 3.1 (which has scopes
`["agents.read", "agents.write"]`), authenticate requesting scope
`["agents.read", "agents.write", "credentials.admin"]`.
Expected: 400, error `invalid_scope` — requested scopes exceed the
credential's allowed scopes.

**Test 3.4 — Scope downscoping on authenticate**
Using the same raw_key, authenticate requesting only `["agents.read"]`.
Expected: token issued with scope limited to `agents.read`, not the full
credential scope set.

**Test 3.5 — Refresh the token pair**
Exchange refresh-A for a new token pair. Note the new access_token
(**token-B**) and new refresh_token (**refresh-B**).
Expected: new tokens issued, token-B differs from token-A.

**Test 3.6 — Original token is still valid after refresh**
Introspect token-A (issued before the refresh in Test 3.5).
Expected: `active: true` — AgentAuth does not invalidate earlier tokens on
refresh.

**Test 3.7 — Revoke an access token**
Revoke token-A. Then introspect token-A.
Expected: revoke returns 200; introspect returns `active: false`.

**Test 3.8 — Revoking an access token cascades to its paired refresh token (Task 7.2)**
Introspect refresh-A (the refresh token that was paired with token-A, which
was just revoked in Test 3.7).
Expected: `active: false` — cascading revocation must have invalidated the
paired refresh token automatically.

**Test 3.9 — A cascaded-revoked refresh token cannot mint new tokens (Task 7.2)**
Attempt to use refresh-A to get new tokens.
Expected: 401 Unauthorized — the refresh token is revoked and must be rejected.

**Test 3.10 — Revoking a refresh token cascades to its paired access token (Task 7.2)**
Authenticate again with mcp-test-bot's raw_key to get a fresh pair
(token-C / refresh-C). Revoke refresh-C. Then introspect token-C.
Expected: after revoking the refresh token, token-C must also be `active: false`.

**Test 3.11 — Refresh token replay is detected**
Authenticate to get a fresh pair (token-D / refresh-D). Use refresh-D to
get a new pair (token-E / refresh-E) — this should succeed.
Now use refresh-D a **second time** (replaying the already-consumed token).
Expected: 401 with error indicating refresh token reuse detected and the
entire token family revoked. Then introspect token-E — expected:
`active: false` (the whole family is invalidated on replay detection).

---

## Section 4 — Agent Visibility (Task 7.4)

**Test 4.1 — Agent can see itself in the list**
Authenticate with mcp-test-bot's raw_key to get a working token (token-F).
Call list_agents with token-F. Expected: mcp-test-bot appears in the results;
`meta.total` reflects only the agents visible to this caller.

**Test 4.2 — Fetch own agent by ID**
Call get_agent with mcp-test-bot's agent id and token-F.
Expected: 200, name `mcp-test-bot`, trust_level `root`.

**Test 4.3 — Register an unrelated root agent**
Register a second agent: name `mcp-unrelated-bot`, agent_type `tool` via
quickstart. Note its agent id, api_key, and access_token (**token-U**).
These two agents have no parent-child or delegation relationship.

**Test 4.4 — Unrelated agent is invisible to mcp-test-bot (Task 7.4)**
Call list_agents with token-F (mcp-test-bot's token).
Expected: mcp-unrelated-bot does NOT appear — the agents are in separate trust
hierarchies with no relationship.

**Test 4.5 — get_agent for an invisible agent returns 404, not 403 (Task 7.4)**
Call get_agent for mcp-unrelated-bot's agent id using token-F.
Expected: 404 Not Found — the service must not reveal whether the agent exists
to an unrelated caller.

---

## Section 5 — Credential Management (Task 7.1)

**Test 5.1 — Create a credential for own agent**
Call create_credential for mcp-test-bot's agent id using token-F, requesting
scopes `["agents.read"]`. Note the credential_id (**cred-1**) and raw_key.
Expected: 201, credential id returned, raw_key shown once, is_valid true.

**Test 5.2 — Authenticate with the new credential**
Use raw_key from Test 5.1 to authenticate requesting scope `["agents.read"]`.
Introspect the resulting access_token and confirm `scopes` is limited to
`["agents.read"]`.
Expected: token active, scope correctly restricted.

**Test 5.3 — Rotate own credential**
Call rotate_credential with cred-1's id using token-F. Note the new
credential_id (**cred-2**) and new raw_key.
Expected: 200, old_credential_id matches cred-1, new raw_key differs, cred-2
is_valid true.

**Test 5.4 — Old key is rejected after rotation**
Authenticate with cred-1's raw_key (the key that was rotated in Test 5.3).
Expected: 401 — the old key must be invalidated immediately upon rotation.

**Test 5.5 — Rotated key works**
Authenticate with cred-2's raw_key from Test 5.3.
Expected: 200, valid token pair returned.

**Test 5.6 — Revoke own credential**
Call create_credential again for mcp-test-bot to get a throwaway credential.
Then revoke it with revoke_credential using token-F.
Expected: 200, revoked_at is set, is_valid false.

**Test 5.7 — Revoked credential rejects authentication**
Authenticate with the revoked credential's raw_key from Test 5.6.
Expected: 401 — revoked credentials must not issue tokens.

**Test 5.8 — Cannot create a credential for an unrelated agent (Task 7.1)**
Call create_credential targeting mcp-unrelated-bot's agent id, authenticated
as mcp-test-bot using token-F.
Expected: 403 Forbidden, RFC 7807 body, error title contains "authority" or
"denied".

**Test 5.9 — Cannot rotate a credential belonging to an unrelated agent (Task 7.1)**
Using token-U (mcp-unrelated-bot's token), create a credential for
mcp-unrelated-bot and note its credential_id (**cred-U**).
Then call rotate_credential for cred-U using token-F (mcp-test-bot's token).
Expected: 403 Forbidden.

**Test 5.10 — Cannot revoke a credential belonging to an unrelated agent (Task 7.1)**
Call revoke_credential for cred-U using token-F.
Expected: 403 Forbidden.

---

## Section 6 — Delegation

**Test 6.1 — Create a delegation between agents**
Call create_delegation from mcp-test-bot (authenticated with token-F) to
mcp-unrelated-bot, delegating scope `agents.read`, expires_in_hours 1.
Expected: 201, delegation id returned, delegate_agent_id matches mcp-unrelated-bot,
is_active true.

**Test 6.2 — Delegation peer becomes visible in list (Task 7.4)**
Call list_agents again with token-F.
Expected: mcp-unrelated-bot NOW appears — the active delegation makes it a
visibility peer.

**Test 6.3 — get_agent for delegation peer returns 200 (Task 7.4)**
Call get_agent for mcp-unrelated-bot's id using token-F.
Expected: 200 — previously 404 (Test 4.5), now accessible via delegation.

**Test 6.4 — Delegation does NOT grant credential management rights (Task 7.1)**
Call create_credential targeting mcp-unrelated-bot's agent id, authenticated
with token-F. The delegation from Test 6.1 is still active.
Expected: 403 Forbidden — visibility through delegation must not grant the
right to manage another agent's credentials.

**Test 6.5 — Check permission for delegated scope**
Call check_permission for mcp-unrelated-bot's agent id, action `read`,
resource `/api/v1/agents`, authenticated with token-F.
Expected: response indicates the permission is allowed.

**Test 6.6 — Scope escalation in re-delegation is rejected**
Create a delegation from mcp-test-bot to mcp-alpha-bot with scopes
`["agents.read"]`. Authenticate as mcp-alpha-bot. Then attempt to
create_delegation from mcp-alpha-bot to mcp-beta-bot with scopes
`["agents.read", "agents.write"]`.
Expected: rejected — a delegate cannot escalate beyond the scopes it received.

**Test 6.7 — Delegation chain respects max_chain_depth**
Create a delegation from mcp-test-bot to mcp-alpha-bot with scopes
`["agents.read"]` and max_chain_depth 1. Authenticate as mcp-alpha-bot and
delegate to mcp-beta-bot (depth 1 — should succeed). Authenticate as
mcp-beta-bot and attempt to delegate onward to mcp-unrelated-bot.
Expected: rejected — chain depth exceeded.

---

## Section 7 — Error Handling

**Test 7.1 — Invalid API key**
Authenticate with a completely bogus key `totally-invalid-key-000`.
Expected: 401, error body contains `invalid_client`.

**Test 7.2 — Garbage token introspect**
Introspect the string `not.a.real.jwt.token`.
Expected: `active: false`, no 500 error — graceful handling.

**Test 7.3 — Non-existent agent**
Call get_agent with UUID `00000000-0000-0000-0000-000000000000` using token-F.
Expected: 404 with a clear error message.

**Test 7.4 — Idempotent token revocation**
Revoke an already-revoked token (reuse token-A from Section 3).
Expected: 200 — revocation is idempotent per RFC 7009.

**Test 7.5 — Revoke a garbage token**
Call revoke_token with the string `not.a.real.jwt.token`.
Expected: 200 — per RFC 7009, the server must respond with 200 even for
invalid tokens to avoid leaking token validity information.

---

## Section 8 — End-to-End Smoke Test

**Test 8.1 — Full agent lifecycle**
Perform all of the following in sequence, reporting each result:

1. Register a new agent `mcp-e2e-bot` via quickstart.
2. Create a scoped credential with `["agents.read"]` using the quickstart token.
3. Authenticate with the scoped credential to get a token pair.
4. Introspect the access_token — confirm active, sub matches agent id, and
   scopes contains `agents.read`.
5. Call list_agents — confirm `mcp-e2e-bot` appears.
6. Revoke the access_token.
7. Introspect the access_token again — confirm active: false.
8. Introspect the refresh_token — confirm active: false (cascading revocation).
9. Attempt to use the revoked refresh_token to get new tokens — confirm 401.

Expected: all 9 steps behave as described.
