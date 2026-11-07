# Admin token scope edit: permission selector and client-side validation (#350)

## Problem

The admin token edit row (`internal/web/templates/admin.html`) takes scopes as a
raw JSON textarea. The server validates each entry with `permissions.Validate`
and rejects the whole PATCH with one long message. A typo or a legacy alias
such as `pulls` only shows up after a 400.

## Decisions

1. **Selector.** The edit row uses `<ghp-permission-select>`, the component the
   create forms use. It can only emit canonical names with `read` or `write`.
2. **Source of available permissions.** An admin edits tokens that belong to
   other users. GHP stores no per-user grant data for that user that the admin
   page can read, and agent tokens are bounded by the installation, not by the
   admin. The selector therefore offers the canonical list from
   `permissions.Names()` with `write` as the maximum level for every name. The
   server stays the authority: it still validates every entry.
3. **Delivery.** `handleAdmin` embeds the list in the page as JSON
   (`PermissionNamesJSON`, rendered as `template.JS`). No new endpoint.
4. **Pre-population.** The component gains a `value` setter. It applies each
   entry whose name is offered and whose level is `read` or `write`, and
   returns the entries it could not apply. The edit row lists those entries in
   a warning ("will be removed on save") so legacy names are not dropped
   silently.
5. **Metadata.** On create, the component shows `metadata` as a fixed `read`.
   In the edit row that would add `metadata:read` to every saved token and turn
   an open-scoped token into a scoped one. The component gains an
   `optional-metadata` attribute; with it, `metadata` is an ordinary
   No access / Read control. The edit row sets it.
6. **Current scopes as text.** A read-only `<pre>` shows the token's current
   scopes as JSON, behind a "Show current scopes as JSON" toggle.
7. **Client-side validation.** Before submit, `validateScopes()` applies the
   same rules as `permissions.Validate`: every name must be in the canonical
   list and every level must be `read` or `write`. A failure renders in the
   form's error element and no request is sent.
8. **Server rejection.** A 400 still renders the server message in the same
   error element.

## Tests

- Go: `handleAdmin` renders the canonical list (`internal/web/handler_test.go`).
- Playwright (`e2e/tests/admin-token-edit.spec.ts`): a successful edit through
  the selector, a server rejection rendered in the form (route stubbed with
  `page.route`), and the server's 400 for a crafted PATCH with `pulls`.
