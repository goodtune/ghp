# UI Redesign Design

## Overview

Revamp the GHP user interface to be fresh, user-friendly, and visually distinct. The redesign focuses the UI purely on token lifecycle (creation and revocation), removes audit log views entirely, and introduces a warm earthy color palette inspired by the octobear logo with teal action accents. Supports both light and dark modes.

## Screens

| Screen | Route | Purpose |
|--------|-------|---------|
| Login | `/login` | Sign in with GitHub, octobear logo prominent |
| User Dashboard | `/` | Token cards + "New Token" stepper dialog |
| Admin Dashboard | `/admin` | Users tab, Tokens tab (table) + "New Agent Token" stepper |

### Login (`/login`)

- Centered card with generous padding and soft shadow/glow
- Octobear logo (~120px) with "ghp" wordmark below
- Subtitle: "GitHub Proxy for Coding Agents"
- Single "Sign in with GitHub" button (teal) with GitHub octocat icon
- Warm background with subtle radial gradient or soft texture
- Auto-redirects to `/` if already authenticated

### User Dashboard (`/`)

**Header bar:**
- Left: small octobear mark + "ghp" wordmark
- Right: theme toggle (sun/moon), username, admin link (if applicable), sign out

**Token cards area:**
- Prominent "New Token" button (teal, top right)
- Responsive card grid (1-2 columns depending on viewport)
- Each card shows:
  - Repository name (bold, prominent)
  - Permission chips (small muted pills: `contents:read`, `pulls:write`)
  - Status dot + expiry ("Expires in 6h" or "Expired 2d ago")
  - Session ID if present (small, secondary text)
  - Revoke button (subtle, danger-colored on hover)
- Empty state: octobear illustration (smaller/faded) with "No tokens yet. Create one to get started." + CTA button

**New Token stepper (modal dialog):**
1. **Repository** - search and pick a repo
2. **Permissions** - permission selector filtered for the chosen repo
3. **Details** - duration dropdown + optional session ID
4. **Confirm** - summary of choices, "Create Token" button
- On creation: token display with copy button and "shown once" warning
- Progress indicator: step dots across the top of the dialog
- Back/Next navigation, keyboard friendly
- Smooth slide transition between steps

### Admin Dashboard (`/admin`)

**Header bar:**
- Left: small octobear mark + "ghp" wordmark + "admin" label
- Right: "Dashboard" link, theme toggle, username, sign out

**Tabs: Users | Tokens**

**Users tab:**
- Clean table: username, role badge, created date
- Row click or "View tokens" action switches to Tokens tab filtered by that user

**Tokens tab:**
- Compact table: token prefix, type badge (proxy/agent), repos, scopes, status, expiry, revoke action
- Filter bar: by user, by status (active/expired/revoked), by repo
- "New Agent Token" button (teal) triggers agent token stepper

**Agent Token stepper (modal dialog):**
1. **Installation** - select GitHub App installation
2. **Repositories** - multi-select repos from that installation
3. **Permissions** - filtered by installation's available permissions
4. **Details** - duration + optional session ID
5. **Confirm** - summary, create
- Token display on success (same pattern as user flow)

## Removed from UI

- **Audit log** - removed from both user and admin dashboards. Observability is handled via external metrics and log aggregation. The UI focuses purely on token lifecycle.

## Color Palette

| Role | Dark Mode | Light Mode |
|------|-----------|------------|
| Base background | Espresso brown `#1a1210` | Warm cream `#f5f0eb` |
| Surface (cards, dialogs) | Dark walnut `#2a2220` | White `#ffffff` |
| Border | Medium brown `#3d3230` | Tan `#d9cfc7` |
| Text primary | Cream `#ede5db` | Dark brown `#2a1f1a` |
| Text secondary | Muted tan `#9a8a7c` | Medium brown `#7a6b5e` |
| Accent (actions) | Teal `#2cb5a0` | Teal `#1a9a87` |
| Accent hover | Bright teal `#3ccdb5` | Deep teal `#158575` |
| Danger | Warm red `#d94040` | Warm red `#c53030` |
| Status: active | Soft green `#3fb950` | Green `#2d8a3e` |
| Status: expired | Faded red `#d9534f` | Red `#c53030` |
| Status: revoked | Muted brown `#6a5a4e` | Gray-brown `#9a8a7c` |

## Typography

- **Body:** Inter (loaded via font-face or CDN) with system sans-serif fallback. 15px base, 1.5 line-height.
- **Headings:** Same family, semi-bold, slightly tighter tracking.
- **Mono:** JetBrains Mono or system monospace for token prefixes.
- **Generous sizing** - low-density app, give elements room to breathe.

## Design System

### CSS Custom Properties

All colors, radii, shadows, and spacing defined as CSS custom properties on `:root` (light) and `[data-theme="dark"]`. Single source of truth. Respects `prefers-color-scheme` on first visit, remembers user choice via localStorage.

### Shared Patterns

- **Border radius:** 8-12px on cards and dialogs, 6px on buttons and inputs
- **Spacing:** Airy - comfortable padding inside cards and forms
- **Shadows:** Soft layered shadows in light mode, subtle warm border glow in dark mode
- **Transitions:** 150-200ms on hover states, tab switches, stepper dialog open/close
- **Status indicators:** Small colored dot (not loud badges), paired with text

### Component Summary

| Component | User Dashboard | Admin Dashboard |
|-----------|---------------|-----------------|
| Token display | Cards (grid) | Table (compact rows) |
| Token creation | Stepper dialog (4 steps) | Stepper dialog (5 steps) |
| User list | N/A | Table with "View tokens" action |
| Theme toggle | Header | Header |
| Empty state | Octobear + CTA | Octobear + CTA |

### Tech Stack (unchanged)

- Go `html/template` with `//go:embed`
- Vanilla JavaScript with Web Components
- No external CSS framework or JS build tools
- CSS custom properties for theming
