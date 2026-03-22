# OdinForge UI/UX Audit Report

**Date**: 2026-03-22
**Auditor**: Claude Opus 4.6 (automated code audit)
**Scope**: All frontend files (`client/src/`), relevant backend routes (`server/routes.ts`), storage layer, WebSocket infrastructure, and production deployment config.

---

## Critical Issues (blocks usage)

### C1. Pause and Stop buttons call non-existent backend routes (404)

**What's broken**: The `ChainDetailView` component calls `POST /api/breach-chains/${chain.id}/pause` and `POST /api/breach-chains/${chain.id}/stop`. Neither route exists on the backend. The backend only provides `/resume` and `/abort`.

**Where**: `client/src/pages/BreachChains.tsx:357-360`
```
pauseMut: POST /api/breach-chains/${chain.id}/pause  ← DOES NOT EXIST
stopMut:  POST /api/breach-chains/${chain.id}/stop   ← DOES NOT EXIST
```

**Backend has**: `/api/breach-chains/:id/resume` (line 2756) and `/api/breach-chains/:id/abort` (line 2775)

**Impact**: Clicking "Pause" or "Stop" on a running chain silently fails with a 404. The chain cannot be stopped from the UI. Since chains stuck in "running" status cannot be deleted (backend rejects with "Cannot delete a running breach chain — abort it first"), this creates permanently stuck chains that can never be cleaned up.

**Fix**: Change `pauseMut` to call `/abort` (or create a real `/pause` endpoint), and change `stopMut` to call `/abort`.

---

### C2. WebSocket JWT validation is hard-coded to always fail in production

**What's broken**: The WebSocket server's JWT token validation is stubbed out with a hard-coded failure:
```typescript
const validation = { valid: false, error: "JWT auth service not available (core-v2)" };
```
When `requireAuth` is `true` (the default in production), every WebSocket connection is rejected with `"Invalid token"`. This means all real-time updates (breach chain progress, live events, graph updates) are dead in production.

**Where**: `server/services/websocket.ts:252-253`

**Impact**: In production (`NODE_ENV=production`), no WebSocket connections succeed. The entire live breach chain visualization, action feed, progress tracking, and graph streaming are non-functional. The UI shows stale data and never updates in real-time.

**Fix**: Either implement proper JWT validation using the UI auth JWT secret, or set `WS_REQUIRE_AUTH=false` in production env until JWT validation is implemented.

---

### C3. Three duplicate 5-second polling queries for `/api/breach-chains` fire simultaneously

**What's broken**: Three independent components each create their own `useQuery` with `refetchInterval: 5000` for the exact same endpoint `/api/breach-chains`:
1. `TopBar` (App.tsx:90)
2. `Sidebar` (App.tsx:207)
3. `StatusBar` (App.tsx:271)
4. `BreachChains` page (BreachChains.tsx:714)

All four share the same query key so React Query deduplicates the actual fetch, but all four process the full chain list every 5 seconds to compute stats. The polling **never stops** — even when no chains are running, even when the user is on a different page, even when the tab is backgrounded.

**Where**: `client/src/App.tsx:90, 207, 271` and `client/src/pages/BreachChains.tsx:714`

**Impact**: Continuous 5-second polling creates constant network traffic, unnecessary CPU usage processing chain data, and contributes to the "UI feels sluggish" perception. Combined with the broken WebSocket (C2), the polling is the only way data updates — but it's wasteful and unconditional.

**Fix**: (a) Make `refetchInterval` conditional: `refetchInterval: hasRunningChains ? 5000 : false`. (b) Centralize the chain stats computation into a single context/hook instead of recomputing in 3 layout components. (c) When WebSocket is working, disable polling entirely for connected clients.

---

### C4. `queryClient` default 401 behavior throws, crashes the app instead of redirecting to login

**What's broken**: The global query client is configured with `on401: "throw"`, meaning any expired token or session timeout causes an unhandled error that bubbles up and crashes the current view (caught only by AppErrorBoundary, which shows a full-screen error).

**Where**: `client/src/lib/queryClient.ts:63`

**Impact**: When a user's token expires, instead of being redirected to the login page, they see "Something went wrong" with a stack trace. The only recovery is clicking "Reload". This is the most likely cause of the "UI hangs/freezes" reports — the error boundary catches the crash but the user perception is that the app froze.

**Fix**: Change default to `on401: "returnNull"` and add a global query error handler or an Axios interceptor that detects 401 responses and calls `clearAuthData()` + redirect to login.

---

## High Issues (degrades experience)

### H1. Download button in chain list has no onClick handler (dead button)

**What's broken**: The Download button (`<Download>` icon) rendered for completed chains in `ChainsListView` has no `onClick` handler. It renders a clickable-looking button that does nothing.

**Where**: `client/src/pages/BreachChains.tsx:599-602`

**Fix**: Add an `onClick` handler that triggers a PDF download via `/api/breach-chains/${chain.id}/report/pdf` or opens a download modal.

---

### H2. "Profile" and "Settings" dropdown menu items are dead (no onClick handlers)

**What's broken**: In the user dropdown menu in the TopBar, two items have no click handlers:
```tsx
<DropdownMenuItem>Profile</DropdownMenuItem>    // no onClick
<DropdownMenuItem>Settings</DropdownMenuItem>    // no onClick
```

**Where**: `client/src/App.tsx:189-190`

**Fix**: Either add navigation handlers (Settings → `/admin/settings`, Profile → a profile page) or remove these menu items until the features exist.

---

### H3. `new URL(targetUrl)` in New Engagement modal throws on invalid URLs, crashing the mutation

**What's broken**: The `createMut` mutation function does `new URL(targetUrl).hostname` without try/catch. If the user enters an invalid URL (e.g., `example.com` without `https://`), this throws a `TypeError: Invalid URL` that is caught by the mutation's `onError` but provides a confusing error message.

**Where**: `client/src/pages/BreachChains.tsx:634`

**Impact**: Users who enter a domain without a protocol prefix get a cryptic error. No input validation prevents this.

**Fix**: Add URL validation before the mutation fires, or wrap in try/catch with a user-friendly message, or auto-prepend `https://` if no protocol is provided.

---

### H4. Settings page queries `/api/organization/settings` — route does not exist

**What's broken**: The Settings page queries `{ queryKey: ["/api/organization/settings"] }` and the save mutation PATCHes to the same endpoint. No such route exists in `server/routes.ts`. The query silently fails (returns undefined due to React Query retry:false), and the save button fails with a network error.

**Where**: `client/src/pages/Settings.tsx:58-59, 67-68`

**Impact**: The entire Settings page is non-functional. All organization and API rate limit settings cannot be viewed or saved.

**Fix**: Implement the `/api/organization/settings` GET and PATCH endpoints in `server/routes.ts`, or remove the Settings page until the backend is ready.

---

### H5. Settings page uses `--falcon-*` CSS variables but the app uses `--*` variables

**What's broken**: The Settings page uses a different CSS variable naming convention (`--falcon-panel`, `--falcon-border`, `--falcon-t1`, `--falcon-t4`, `--falcon-red`, etc.) than the rest of the app (`--panel`, `--border`, `--t1`, `--t3`, `--red`). These `--falcon-*` variables are likely undefined, causing the Settings page to render with missing/broken styles.

**Where**: `client/src/pages/Settings.tsx:17-34` and throughout the file

**Impact**: The Settings page likely has invisible text, missing borders, and broken layout because the CSS variables resolve to nothing.

**Fix**: Replace all `--falcon-*` variable references with the standard `--*` variables used elsewhere.

---

### H6. Notifications popover queries endpoints that may not exist or return errors

**What's broken**: `NotificationsPopover` queries three endpoints:
- `/api/aev/evaluations` — exists, but may return large datasets (no pagination)
- `/api/agents` — not found in routes.ts search
- `/api/hitl/pending` with `refetchInterval: 10000` — does not exist

The `/api/hitl/pending` query fires every 10 seconds and likely 404s silently. The `/api/agents` query also likely 404s.

**Where**: `client/src/components/NotificationsPopover.tsx:35-47`

**Impact**: Console floods with 404 errors every 10 seconds. Notifications panel may show misleading empty state or error toasts.

**Fix**: Guard queries with feature flags or check route existence. Remove refetchInterval on non-existent endpoints.

---

### H7. WebSocket `connect` function has stale closure over `isConnected` and `isConnecting` state

**What's broken**: The `connect` callback depends on `isConnecting` and `isConnected` state values. When a reconnect timer fires, it calls `connect()`, but the callback captured at creation time may hold stale boolean values. The guard `if (!enabled || isConnecting || isConnected)` can evaluate with outdated state, causing reconnection to be skipped or creating duplicate connections.

Additionally, `wsUrl` is computed at render time (not memoized) and reads `localStorage` every render. If the token changes between renders (e.g., after refresh), the WebSocket may connect with a stale token.

**Where**: `client/src/hooks/useWebSocket.ts:47-52, 54-113`

**Fix**: Use refs for `isConnected`/`isConnecting` state inside the `connect` callback, or restructure to avoid the stale closure. Memoize `wsUrl` with `useMemo`.

---

### H8. Caddy production config does not explicitly handle WebSocket upgrade

**What's broken**: The production `Caddyfile` uses a bare `reverse_proxy app:5000` without WebSocket-specific configuration. While Caddy 2 does proxy WebSocket upgrades by default, when behind Cloudflare (as noted in the memory), the connection may be terminated if Cloudflare's WebSocket settings aren't configured, or if the Caddy config doesn't set appropriate timeouts for long-lived connections.

**Where**: `Caddyfile:1-13`

**Impact**: In combination with C2 (broken WS auth), WebSocket connections may also be blocked at the proxy layer. Even if C2 is fixed, Cloudflare may time out idle WebSocket connections.

**Fix**: Add explicit WebSocket handling in Caddyfile with appropriate timeouts. Ensure Cloudflare dashboard has WebSocket enabled for the domain.

---

## Medium Issues (should fix)

### M1. React key warning: Fragment children in EvidencePanel lack proper keys

**What's broken**: The `EvidencePanel` maps over `data.assets` and wraps each pair of `<span>` elements in a bare `<>...</>` Fragment. Keys are placed on the children inside the Fragment, but React requires keys on the outermost element in a `.map()`. This produces console warnings.

**Where**: `client/src/pages/BreachChains.tsx:90-95`

**Fix**: Change `<>` to `<React.Fragment key={i}>` or restructure to avoid fragments.

---

### M2. SVG NetworkMap uses imperative DOM manipulation instead of React rendering

**What's broken**: The `NetworkMap` component bypasses React's rendering by directly creating SVG elements with `document.createElementNS` and appending them to the DOM via `svgRef.current.appendChild()`. This means:
- React has no knowledge of these DOM nodes
- No cleanup on re-render (stale nodes accumulate)
- Memory leaks from event listeners attached to SVG elements that are never removed
- The fallback graph effect (line 238-277) clears children with `while (s.children.length > 1) s.removeChild(s.lastChild!)` which is fragile

**Where**: `client/src/pages/BreachChains.tsx:157-316`

**Impact**: Over time, as nodes are added, the SVG accumulates DOM nodes that are never garbage collected. The `click`, `mouseenter`, and `mouseleave` event listeners on graph nodes create closures that hold references to state, preventing GC.

**Fix**: Either: (a) use a React-based SVG rendering approach, (b) add proper cleanup in a `useEffect` return function that removes all appended children and event listeners, or (c) migrate to a canvas-based renderer.

---

### M3. `useEffect` dependency in `useToast` hook uses `[state]` which triggers on every toast change

**What's broken**: The `useToast` hook's `useEffect` has `[state]` as a dependency, which means it re-registers and re-deregisters the listener on every state change. This is inefficient and can cause subtle bugs with the listener array.

**Where**: `client/src/hooks/use-toast.ts:174-182`

**Fix**: Change dependency to `[]` (empty array) since the `setState` function identity is stable.

---

### M4. `TOAST_REMOVE_DELAY` is set to 1,000,000ms (~16 minutes)

**What's broken**: Dismissed toasts are not removed from the DOM for ~16 minutes. This means the toast component accumulates hidden DOM nodes.

**Where**: `client/src/hooks/use-toast.ts:9`

**Impact**: Minor memory leak. Not a UX issue since `TOAST_LIMIT = 1` caps visible toasts, but dismissed toasts linger in memory.

**Fix**: Reduce to a reasonable value like 5000ms.

---

### M5. No CORS configuration on the Express server

**What's broken**: There is no CORS middleware configured on the Express app (`server/index.ts`). In production behind Caddy, same-origin requests work fine. But in development or if the frontend is ever served from a different origin, all API calls will be blocked by the browser.

**Where**: `server/index.ts` (missing `app.use(cors(...))`)

**Impact**: Low in production (same-origin via Caddy), but blocks local development if frontend runs on a different port.

**Fix**: Add `cors` middleware with appropriate origin allowlist.

---

### M6. Chain detail elapsed timer resets on every re-render

**What's broken**: The `elapsed` state in `ChainDetailView` starts at 0 and counts up with a 1-second interval. However, it doesn't account for the actual chain start time. When the user navigates away and back, or when the component re-mounts (e.g., after a query refetch updates the chain), the timer resets to 0.

**Where**: `client/src/pages/BreachChains.tsx:347-355`

**Fix**: Calculate elapsed time from `chain.startedAt` or `chain.createdAt` instead of using a local counter.

---

### M7. `staleTime: 5 * 60 * 1000` (5 minutes) means users see outdated data after mutations

**What's broken**: The global React Query `staleTime` is 5 minutes. While mutations call `invalidateQueries`, any component that mounts within the 5-minute window will show cached data without refetching. This is especially problematic for the chain list after deletion — the deleted chain may still appear from cache.

**Where**: `client/src/lib/queryClient.ts:65`

**Impact**: After deleting a chain, navigating away and back may show the deleted chain for up to 5 minutes.

**Fix**: Reduce `staleTime` to 30 seconds for breach chain queries, or use `0` for critical data paths.

---

### M8. Login/Signup routes redirect to `/breach-chains` even when user is not authenticated

**What's broken**: In `App.tsx` Router, `/login` and `/signup` routes both `<Redirect to="/breach-chains" />`. This means if a user navigates to `/login` while already authenticated, they go to breach chains (correct). But these routes are inside the authenticated layout — the unauthenticated flow is handled by `AuthenticatedApp` which renders `<Login>` or `<Signup>` directly. The Router redirects are therefore dead code for unauthenticated users and confusing for authenticated ones.

**Where**: `client/src/App.tsx:68-69`

**Impact**: Minor — no functional break, but the `/login` and `/signup` routes inside the authenticated Router are misleading. A user who bookmarks `/login` and visits while authenticated gets silently redirected.

**Fix**: Remove the dead `/login` and `/signup` routes from the authenticated Router, since `AuthenticatedApp` handles the unauthenticated case before the Router is rendered.

---

### M9. Reports page `--falcon-*` CSS variables (same issue as Settings)

**What's broken**: The Reports page also uses `--falcon-*` CSS variables extensively (`--falcon-panel`, `--falcon-border`, `--falcon-t1`, `--falcon-t3`, `--falcon-t4`, `--falcon-blue-hi`, `--falcon-red`, `--falcon-panel-2`).

**Where**: `client/src/pages/Reports.tsx` (throughout)

**Impact**: Same as H5 — potentially broken styling on the Reports page.

**Fix**: Audit whether `--falcon-*` variables are defined in the global CSS. If not, replace with the standard `--*` variables.

---

## Low Issues (nice to have)

### L1. `_liveEventCounter` is a module-level mutable variable

**What's broken**: `useBreachChainUpdates` uses `let _liveEventCounter = 0` at module scope to generate unique IDs for live events. This works but is not React-idiomatic and could cause issues with concurrent features or strict mode double-mounting.

**Where**: `client/src/hooks/useBreachChainUpdates.ts:60`

**Fix**: Use `useRef` for the counter, or use `crypto.randomUUID()`.

---

### L2. Login page boot sequence replays on every mount (no sessionStorage gate)

**What's broken**: The boot sequence animation (3.7 seconds of fake terminal output) plays every time the Login page mounts. If a user's session expires and they're redirected to login, they must wait 3.7 seconds before they can enter credentials.

**Where**: `client/src/pages/Login.tsx:54-62`

**Fix**: Store a flag in `sessionStorage` to skip the boot sequence on subsequent visits within the same browser session.

---

### L3. `useBreachChainUpdates` keeps a 1-second `setInterval` running even when no chain is active

**What's broken**: The cleanup interval for expired live events runs every 1 second regardless of whether any chain is being monitored:
```typescript
cleanupRef.current = setInterval(() => { ... }, 1000);
```

**Where**: `client/src/hooks/useBreachChainUpdates.ts:90-99`

**Fix**: Only start the interval when there are active live events.

---

### L4. BreachChains WebSocket updates are enabled only for `running` or `paused` chains

**What's broken**: In `ChainDetailView`, WebSocket updates are conditional:
```typescript
enabled: chain.status === "running" || chain.status === "paused"
```
This means if a chain transitions to `completed` while the user is watching, WebSocket disconnects and the final state must come from polling (which has a 5-second delay). The completion event from WebSocket would be the ideal trigger.

**Where**: `client/src/pages/BreachChains.tsx:343-346`

**Fix**: Keep WebSocket enabled for 30 seconds after completion to catch the final `breach_chain_complete` event, then disconnect.

---

### L5. `drawEdge` in NetworkMap uses `setTimeout` for animation delays, creating potential memory leaks

**What's broken**: `drawEdge` calls `setTimeout(() => { ... }, delay)` without storing the timer ID. If the component unmounts before the timeout fires, the callback will attempt to access `svgRef.current` which may be null.

**Where**: `client/src/pages/BreachChains.tsx:172-180`

**Fix**: Store timeout IDs in a ref and clear them on unmount.

---

### L6. TrialBanner component is imported but never rendered in the app layout

**What's broken**: `TrialBanner` exists at `client/src/components/TrialBanner.tsx` and is fully implemented, but is not rendered anywhere in `App.tsx` or `AppLayout`.

**Where**: `client/src/components/TrialBanner.tsx` (unused)

**Fix**: Add `<TrialBanner />` to the `AppLayout` or `AuthenticatedApp` component if trial functionality is desired.

---

### L7. Breach chain table rows are clickable but cursor shows default, not pointer

**What's broken**: Chain rows in `ChainsListView` have `onClick={() => onSelect(chain)}` but no `cursor: pointer` style on the row `div`. The row uses class `f-tbl-row` which may or may not set cursor.

**Where**: `client/src/pages/BreachChains.tsx:577`

**Fix**: Add `cursor: pointer` to the row style or ensure `f-tbl-row` includes it.

---

### L8. No error boundary around lazy-loaded page components

**What's broken**: While there is an `AppErrorBoundary` wrapping the `Router`, lazy-loaded chunks (`import("@/pages/BreachChains")` etc.) that fail to load (network error, chunk not found after deploy) will crash the Suspense boundary. The error boundary catches this, but the UX is a full-page error instead of a retry prompt.

**Where**: `client/src/App.tsx:62-78`

**Fix**: Add a retry mechanism to the error boundary for chunk loading failures (detect `ChunkLoadError` and offer a reload).

---

## Working Correctly

1. **Auth flow**: Login, signup, token refresh, and session management work correctly. JWT tokens are stored in localStorage, and the UIAuthProvider handles token refresh with a 2-minute buffer.

2. **Chain creation**: The "New Engagement" modal correctly calls `POST /api/breach-chains` with proper payload. The backend route exists and creates chains.

3. **Chain deletion (backend)**: `DELETE /api/breach-chains/:id` exists, `storage.deleteBreachChain()` is implemented, and it correctly prevents deletion of running chains. The frontend delete button (`Trash2`) calls the correct endpoint and invalidates the query cache on success.

4. **Delete from list view**: The delete button in `ChainsListView` (line 604-612) correctly calls the DELETE endpoint and shows toast feedback.

5. **Delete from detail view**: The delete button in `ChainDetailView` (line 440-450) correctly calls DELETE, shows feedback, and calls `onBack()` to return to the list.

6. **Report generation**: Both V1 and V2 report generation flows have proper mutations, error handling, and success feedback.

7. **Report downloads**: PDF/JSON/CSV download options work correctly with proper Blob creation and download triggers.

8. **Report deletion**: Delete mutation calls the correct endpoint and invalidates cache.

9. **Toast notifications**: The toast system works correctly for success and error feedback.

10. **Error boundary**: `AppErrorBoundary` catches render errors and displays a reload button.

11. **Auth context bridge**: `AuthContext` correctly bridges to `UIAuthContext` for backward compatibility.

12. **WebSocket reconnection logic**: The exponential backoff reconnection (up to 30s, 10 attempts) is well-implemented.

13. **Additive graph model**: `useBreachChainUpdates` correctly implements additive-only graph state that resets on chain ID change.

14. **Permission checks**: UI correctly checks permissions before showing Settings, delete buttons, report generation, etc.

---

## Summary

| Severity | Count | Key Theme |
|----------|-------|-----------|
| Critical | 4 | Broken pause/stop routes, dead WebSocket in production, aggressive polling, crash on 401 |
| High | 8 | Dead buttons, missing API routes, broken CSS variables, stale closures |
| Medium | 9 | Memory leaks, stale data, dead routes, CSS mismatches |
| Low | 8 | Minor UX polish, unused components, animation timing |

**Root cause of "UI hangs/freezes"**: The combination of C2 (WebSocket broken in production → no real-time updates), C3 (4 independent 5-second polling loops that never stop), and C4 (401 errors crash the app instead of redirecting to login) creates a degraded experience where the UI is constantly fetching, occasionally crashes, and never receives real-time updates.

**Root cause of "old chains can't be deleted"**: C1 — the Pause/Stop buttons hit non-existent routes. Chains stuck in "running" status cannot be stopped, and the backend correctly prevents deletion of running chains. This creates permanently undeletable chains.

**Root cause of "stale data persists"**: C2 (no WebSocket) + C3 (polling is the only update mechanism) + M7 (5-minute staleTime cache) means data can be up to 5 minutes stale, and deleted items may reappear from cache.
