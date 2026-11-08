# Scope rig: agent-token coverage (#306)

## Problem

The rig mints only proxy (`ghx_`) tokens. AGENT-C49, TOK-C02, TOK-C03,
TOK-C04 and REPO-C08 have no scenario, and GAP-A6 only checks that an agent
token can be created. The #294 question (does GitHub accept `owner/repo` in
the installation `access_tokens` body) has never been probed at run time.

## Live observation (0.26.0, before #358)

An agent token for the rig App with `repositories: ["OWNER/ghp-scoperig-a"]`
is created (201; creation does not call GitHub). The first proxied request
to A returns 422 "There is at least one repository that does not exist or is
not accessible to the parent installation": GitHub rejects the `owner/repo`
form and GHP fails closed. Requests to B and W are 403 from GHP ("Token is
not scoped to ..."). An agent token with no repositories reads A, B and W
(200). So #294 is real, and the failure mode is a broken token, not a widened
one.

## Design

1. Config: `instance.agent_installation: {app_record_id, installation_id}`.
   LoadConfig rejects a non-UUID `app_record_id` and a non-positive
   `installation_id`. `GHP_RIG_INSTALLATION_ID` still overrides the
   installation. Template vars gain `.Agent.AppRecordID` and
   `.Agent.InstallationID`.
2. Capability `agent_installation`: both values set and
   `GET /api/apps/{app_record_id}` answers 200 with that id. It is computed
   before profile tokens are minted, so agent profiles are not minted when it
   is false. Replaces the old "can list all tokens" rule.
3. Profiles gain `requires:`. `type: agent` is accepted only with
   `requires: [agent_installation]`, and every scenario that uses a profile
   must list the profile's requires (so it reports GAP, not ERROR). The
   token manager sends `app_record_id` and `installation_id` for agent
   profiles; values are never logged.
4. token_api may also GET `/api/apps` and `/api/apps/{id}[/installations]`
   (read only), the endpoints the CLI uses for `--app` / `--installation`.
5. Scenarios (`rig/scenarios/agent.yaml`): proxy allowlist (A allowed with
   `known_issue: #294` until #358 deploys, B and W denied), permission levels
   (read allowed, write denied by GHP), admin can mint, non-admin cannot
   (capability `non_admin_session`, never set: the rig has only the admin
   session), name resolution and default-app data through the API (the default-app
   check requires a `default_app` capability: exactly one app marked
   default), REPO-C08
   body shapes. The validator requires every token_api agent body to name
   the app and installation by template. GAP-A6 passes `app_record_id` so the default app is never
   used.

## What the #294 probe proves

(a) With #358 deployed, a 200 from A proves GitHub accepted the mint body;
the 403 for B is GHP's own allowlist. (b) GitHub-side narrowing needs the raw
installation token, which never leaves GHP. The W probe shows only that GHP
denies W; it does not prove the installation token is narrowed.
