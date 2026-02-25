# Admin View & Navigation Redesign

## Goal

Make the navigation consistent across dashboard and admin pages, fix admin tab behaviour, add token filtering/pagination, and make the users view interactive with expandable token cards.

## 1. Consistent Navigation Header

Both dashboard and admin pages share the same header:

```
[octobear 32px] GitHub Proxy --- [Dashboard] [Admin*] [theme-toggle] [avatar 32px] [Sign out]
```

- **Dashboard** link: always visible, active/highlighted when on `/`, plain link otherwise.
- **Admin** link: only rendered for admin-role users, active when on `/admin`.
- **Avatar**: 32px circular image from `https://github.com/{username}.png`, links to `https://github.com/{username}`. Replaces the username text.
- **"admin" badge** removed from admin page title — active nav state communicates location.
- Login page unchanged (no nav header).

## 2. Admin Tabs Fix

- SSE stream on connect sends **only the users panel** (matches default active tab).
- Clicking "Tokens" tab fires `@get('/ui/admin/tokens')` to load the tokens panel via SSE.
- Clicking "Users" tab fires `@get('/ui/admin/users')` to reload users panel.
- Tab state tracked via Datastar signal, CSS highlights active tab.

## 3. Admin Tokens View — Filtering & Pagination

**Filter bar** above the table with:

- **Status** dropdown: All / Active / Expired / Revoked
- **User** text input: filter by username (substring match)
- **Repo** text input: filter by repository name (substring match)
- **Scope** text input: filter by scope (substring match)

Filters submit via SSE POST — server returns just the filtered/paginated table fragment. Pagination controls (prev/next + page indicator) below the table. Page size of 25 rows.

New database method: `ListAllProxyTokensFiltered(ctx, filters)` with status/user/repo/scope filters plus limit/offset.

## 4. Admin Users View — Expandable Token Cards

- User rows are clickable (cursor pointer, hover highlight).
- Clicking a row fires `@get('/ui/admin/users/{id}/tokens')`.
- Server returns a token card grid (same `token-card` fragment as dashboard) inserted below the clicked row.
- Accordion behaviour: clicking another user collapses the previous expansion. Clicking the same user again collapses it.
- Expanded row gets a visual indicator (chevron rotation or highlight).
