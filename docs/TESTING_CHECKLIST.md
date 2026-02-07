# 🧪 OdinForge-AI Testing Checklist

## Pre-Testing Setup

### Environment Requirements
- [ ] PostgreSQL database running and accessible
- [ ] Redis instance running (for BullMQ job queue)
- [ ] Node.js v20+ installed
- [ ] Environment variables configured:
  ```bash
  DATABASE_URL=postgresql://user:pass@localhost:5432/odinforge
  REDIS_URL=redis://localhost:6379
  SESSION_SECRET=your-secret-key
  NODE_ENV=development
  ```

### Start the Application
```bash
# Terminal 1: Start development server
npm run dev

# The app should start on http://localhost:5000 (or configured port)
```

---

## 🎯 Feature Testing

### 1. Remediation Center (`/remediation`)

#### Access & Navigation
- [ ] Navigate to Sidebar → Analysis → Remediation
- [ ] Page loads without errors
- [ ] Statistics cards display (4 cards)
- [ ] Tabs are visible (Available Fixes, Pull Requests)

#### Git Configuration
- [ ] Click "Configure Git" button
- [ ] Dialog opens with provider selection
- [ ] Select GitHub provider
- [ ] Enter token: `ghp_test_token_here`
- [ ] Optional: Enter base URL for GitHub Enterprise
- [ ] Click "Save Configuration"
- [ ] Success message appears
- [ ] Dialog closes

#### Available Fixes Tab
- [ ] Tab shows list of findings with remediation available
- [ ] Each finding displays:
  - Finding ID
  - Vulnerability type
  - Severity badge (color-coded)
  - Asset information
  - Create PR button
- [ ] Findings are sortable by severity
- [ ] Search/filter works if implemented

#### Create Pull Request
- [ ] Click "Create PR" on any finding
- [ ] Dialog opens with PR configuration form
- [ ] Enter repository URL: `https://github.com/your-org/repo`
- [ ] Optional: Enter custom branch name
- [ ] Optional: Enter labels (comma-separated): `security, odinforge`
- [ ] Optional: Enter reviewers (comma-separated): `@reviewer1, @reviewer2`
- [ ] Click "Create Pull Request"
- [ ] Loading state shows
- [ ] Success: PR created message appears
- [ ] PR appears in Pull Requests tab

#### Pull Requests Tab
- [ ] Tab shows list of created PRs
- [ ] Each PR displays:
  - PR number and title
  - Repository name
  - Status badge (created, merged, closed)
  - Branch name
  - Files changed count
  - View PR button (opens GitHub)
  - Check Status button
- [ ] Click "View PR" - opens GitHub in new tab
- [ ] Click "Check Status" - refreshes PR status
- [ ] Status updates correctly (created → merged)

#### Statistics Validation
- [ ] "Findings with Fixes" count is accurate
- [ ] "Active PRs" shows only open PRs
- [ ] "Merged Fixes" increments when PR merges
- [ ] "Total Changes" sums all files changed

---

### 2. Approval History (`/approvals/history`)

#### Access & Navigation
- [ ] Navigate to Sidebar → System → Approval History
- [ ] Page loads without errors
- [ ] Statistics cards display (5 cards)
- [ ] Filters are visible (search, status, risk level)
- [ ] History table displays with data

#### Statistics Dashboard
- [ ] "Total Requests" shows correct count
- [ ] "Approved" shows count and percentage
- [ ] "Rejected" shows count and percentage
- [ ] "Expired" shows count of timeouts
- [ ] "Avg Response Time" displays human-readable time
- [ ] Statistics update when filters change

#### Filtering
- [ ] **Search Box**: Type command keyword → filters results
- [ ] **Search Box**: Type agent name → filters results
- [ ] **Search Box**: Type target → filters results
- [ ] **Status Filter**: Select "Approved" → shows only approved
- [ ] **Status Filter**: Select "Rejected" → shows only rejected
- [ ] **Status Filter**: Select "Expired" → shows only expired
- [ ] **Status Filter**: Select "Pending" → shows only pending
- [ ] **Risk Level Filter**: Select "Critical" → shows only critical
- [ ] **Risk Level Filter**: Select "High" → shows only high
- [ ] **Risk Level Filter**: Select "Medium" → shows only medium
- [ ] Multiple filters work together (AND logic)

#### History Table
- [ ] Table displays all approval records
- [ ] Columns: ID, Agent, Command, Target, Risk Level, Status, Requested At, Response Time
- [ ] Risk level badges are color-coded (red=critical, orange=high, yellow=medium)
- [ ] Status badges are color-coded (green=approved, red=rejected, gray=expired)
- [ ] Command text is truncated with ellipsis if long
- [ ] Timestamps show relative time ("2 hours ago")
- [ ] Click "Details" button on any row

#### Detail Dialog
- [ ] Dialog opens with full approval information
- [ ] Displays: ID, Agent, Status, Risk Level, Timestamps
- [ ] Shows full command (not truncated)
- [ ] Shows target system
- [ ] Shows risk reason explanation
- [ ] Shows responder identity
- [ ] Shows cryptographic signature
- [ ] Shows rejection reason (if rejected)
- [ ] Shows expiration time (if expired)
- [ ] Close dialog with X or outside click

#### CSV Export
- [ ] Click "Export CSV" button
- [ ] File downloads: `approval-history-YYYY-MM-DD.csv`
- [ ] Open CSV in Excel/Sheets
- [ ] Verify columns: ID, Agent, Command, Target, Risk Level, Status, Timestamps, Responder, Rejection Reason
- [ ] Verify data matches UI display
- [ ] Verify special characters are properly escaped
- [ ] Verify dates are formatted correctly

---

### 3. Enhanced Notifications (Bell Icon)

#### Notification Badge
- [ ] Bell icon visible in top navigation bar
- [ ] Badge shows unread count when notifications exist
- [ ] Badge shows number 1-9 for small counts
- [ ] Badge shows "9+" for 10 or more notifications
- [ ] Badge is red (destructive variant)
- [ ] Badge disappears when all notifications read

#### Notification Popover
- [ ] Click bell icon → popover opens
- [ ] Header shows "Notifications" title
- [ ] Header shows unread count: "3 new"
- [ ] "Mark all read" button visible when unread exists
- [ ] Scrollable list of notifications (max height 300px)
- [ ] Close button at bottom

#### Notification Types & Display

**Approval Notifications:**
- [ ] Title: "🚨 Approval Required" for critical risk
- [ ] Title: "Approval Required" for high/medium risk
- [ ] Icon: Red pulsing shield for critical
- [ ] Icon: Orange shield for high/medium
- [ ] Message: Shows agent name and command preview
- [ ] Orange left border for unread approvals
- [ ] Blue dot indicator for unread
- [ ] Timestamp shows relative time

**Evaluation Notifications:**
- [ ] Title: "Evaluation Found Exploitable" or "Evaluation Completed Safe"
- [ ] Icon: Red warning for exploitable, green shield for safe
- [ ] Message: Shows asset ID and exposure type
- [ ] Color-coded severity

**Agent Notifications:**
- [ ] Title: "Agent Offline" or "Agent Stale"
- [ ] Icon: Amber bot icon
- [ ] Message: Shows agent name and last seen time

**Scan Notifications:**
- [ ] Icon: Cyan globe icon
- [ ] Message: Shows scan progress/completion

#### Interaction & Navigation
- [ ] Click approval notification → navigates to `/approvals`
- [ ] Popover closes after navigation
- [ ] Notification marked as read automatically
- [ ] Click "Mark as read" button → marks individual notification
- [ ] Click "Mark all read" → marks all notifications
- [ ] Badge count updates immediately
- [ ] Read notifications show with 60% opacity
- [ ] Unread notifications show with accent background

#### Real-Time Updates
- [ ] New approval appears within 10 seconds
- [ ] Badge count updates automatically
- [ ] No manual refresh needed
- [ ] WebSocket connection active (check browser console)
- [ ] Polling fallback works if WebSocket fails

---

### 4. HITL Approval Flow (`/approvals`)

#### Access & Landing Page
- [ ] Navigate to Sidebar → System → Approvals
- [ ] Page loads without errors
- [ ] Shows "Pending Approvals" section
- [ ] Shows statistics cards (if applicable)
- [ ] Empty state if no pending approvals

#### Pending Approval Display
- [ ] Each approval shows:
  - Agent name
  - Full command
  - Target system
  - Risk level badge (color-coded)
  - Risk reason explanation
  - Requested timestamp
  - Expires in countdown
  - Approve button (green)
  - Reject button (red)
- [ ] Critical risk approvals have red border
- [ ] High risk approvals have orange indicator
- [ ] Medium risk approvals have yellow indicator

#### Approve Action
- [ ] Click "Approve" button
- [ ] Confirmation dialog may appear (optional)
- [ ] Loading state shows
- [ ] Success message appears
- [ ] Approval disappears from list
- [ ] Moves to "Approved" section
- [ ] Agent receives approval and proceeds
- [ ] Event logged in Approval History

#### Reject Action
- [ ] Click "Reject" button
- [ ] Rejection reason dialog appears
- [ ] Text area for entering reason (required)
- [ ] Cancel button available
- [ ] Submit button disabled until reason entered
- [ ] Click Submit
- [ ] Loading state shows
- [ ] Success message appears
- [ ] Approval disappears from list
- [ ] Moves to "Rejected" section
- [ ] Agent receives rejection
- [ ] Event logged in Approval History with reason

#### Expiration Handling
- [ ] Countdown timer shows time remaining
- [ ] Timer updates in real-time
- [ ] When expired:
  - Approval grays out
  - Buttons disable
  - Status shows "Expired"
  - Moves to expired section
  - Event logged in Approval History

#### Real-Time Updates
- [ ] New approvals appear automatically
- [ ] No page refresh needed
- [ ] WebSocket notification received
- [ ] Badge in notification bell updates
- [ ] Pending count updates

---

### 5. WebSocket Integration

#### Connection
- [ ] Open browser DevTools → Network → WS tab
- [ ] WebSocket connection established on page load
- [ ] Connection URL: `ws://localhost:5000` or `wss://` for production
- [ ] Connection status: "Connected" (check browser console)

#### Event Subscriptions
- [ ] Client subscribes to organization channel
- [ ] Client subscribes to evaluation channels
- [ ] Client subscribes to approval channels
- [ ] Subscriptions confirmed in console logs

#### Real-Time Events
- [ ] Create new approval → notification appears instantly
- [ ] Approve request → status updates across all clients
- [ ] Reject request → status updates across all clients
- [ ] New evaluation → notification appears
- [ ] Agent status change → notification appears

#### Reconnection
- [ ] Stop server → connection drops
- [ ] Start server → connection reestablishes automatically
- [ ] Missed events caught up after reconnection
- [ ] No data loss

---

## 🔒 Security Testing

### Authentication & Authorization
- [ ] Log out → redirected to login page
- [ ] Access `/remediation` without auth → redirected
- [ ] Access `/approvals/history` without auth → redirected
- [ ] Access `/approvals` without auth → redirected

### Role-Based Access Control (RBAC)
- [ ] Security Analyst: Can view Approval History (read-only)
- [ ] Security Analyst: Cannot configure Git in Remediation
- [ ] Security Engineer: Can create PRs
- [ ] Security Admin: Can configure Git
- [ ] Org Owner: Full access to all features
- [ ] Executive Viewer: Limited read-only access

### Input Validation
- [ ] Git token: Accept alphanumeric and special chars
- [ ] Git token: Reject empty input
- [ ] Repository URL: Accept valid GitHub/GitLab URLs
- [ ] Repository URL: Reject invalid URLs
- [ ] Rejection reason: Require non-empty text
- [ ] Search: Handle special characters safely (no XSS)

### Data Security
- [ ] Git tokens not visible in UI after configuration
- [ ] Git tokens not logged in browser console
- [ ] API responses don't expose sensitive data
- [ ] WebSocket messages are organization-scoped (no cross-tenant leaks)

---

## 🎨 UI/UX Testing

### Responsive Design
- [ ] Desktop (1920x1080): All features work
- [ ] Laptop (1366x768): Layout adjusts properly
- [ ] Tablet (768x1024): Sidebar collapses, features accessible
- [ ] Mobile (375x667): Responsive layout, touch-friendly

### Dark Mode
- [ ] Toggle theme → dark mode activates
- [ ] All new pages support dark mode
- [ ] Colors readable and accessible
- [ ] Notification bell badge visible
- [ ] Dialog backgrounds correct

### Loading States
- [ ] PR creation shows loading spinner
- [ ] Approval action shows loading state
- [ ] Data fetching shows skeleton or spinner
- [ ] No UI freezing during operations

### Error Handling
- [ ] Invalid Git token → error message displays
- [ ] Network error → user-friendly message
- [ ] PR creation fails → fallback message
- [ ] WebSocket disconnect → reconnection attempt

### Accessibility
- [ ] Keyboard navigation works (Tab, Enter, Esc)
- [ ] Focus indicators visible
- [ ] ARIA labels present on interactive elements
- [ ] Screen reader friendly
- [ ] Color contrast meets WCAG standards

---

## 📊 Performance Testing

### Load Times
- [ ] Remediation page loads in <2 seconds
- [ ] Approval History page loads in <2 seconds
- [ ] Approvals page loads in <2 seconds
- [ ] Notification popover opens instantly (<100ms)

### Data Handling
- [ ] Approval History with 1000+ records: pagination works
- [ ] Large CSV export completes successfully
- [ ] Filtering 1000+ records is responsive
- [ ] Search with 1000+ records is fast (<500ms)

### WebSocket Performance
- [ ] 100 notifications: scroll smooth
- [ ] Real-time updates don't cause lag
- [ ] Memory usage stable over time
- [ ] No memory leaks after prolonged use

---

## 🐛 Bug Testing

### Edge Cases
- [ ] No approvals pending: Empty state displays
- [ ] No PR history: Empty state displays
- [ ] Very long command (1000+ chars): Truncates properly
- [ ] Special characters in command: Display correctly
- [ ] Expired approval: Cannot approve/reject
- [ ] Already responded approval: Cannot duplicate response

### Concurrent Users
- [ ] User A approves → User B sees update
- [ ] User A and B approve simultaneously → only one succeeds
- [ ] Websocket disconnect/reconnect: state syncs correctly

### Data Integrity
- [ ] Approval logged in history immediately after action
- [ ] PR status reflects actual GitHub state
- [ ] Statistics match actual data counts
- [ ] Timestamps accurate across timezones

---

## ✅ Final Validation

### Documentation
- [ ] [NEW_FEATURES.md](./NEW_FEATURES.md) accurate
- [ ] [ENHANCEMENTS.md](./ENHANCEMENTS.md) complete
- [ ] Code comments present in complex sections
- [ ] API endpoints documented

### Code Quality
- [ ] No console errors in browser
- [ ] No console warnings (except known deprecations)
- [ ] TypeScript errors addressed (if applicable)
- [ ] ESLint rules passing
- [ ] No unused imports or variables

### Git & Deployment
- [ ] All changes committed
- [ ] Commit messages clear and descriptive
- [ ] Branch up to date with main
- [ ] Ready to merge/deploy

---

## 📝 Test Results Summary

| Feature | Status | Notes |
|---------|--------|-------|
| Remediation Center | ⏳ Pending | |
| Approval History | ⏳ Pending | |
| Enhanced Notifications | ⏳ Pending | |
| HITL Approval Flow | ⏳ Pending | |
| WebSocket Integration | ⏳ Pending | |
| Security & RBAC | ⏳ Pending | |
| UI/UX | ⏳ Pending | |
| Performance | ⏳ Pending | |

**Legend:**
- ✅ Passed
- ❌ Failed
- ⚠️ Issues Found
- ⏳ Pending
- 🚫 Blocked

---

## 🔧 Environment Setup Commands

```bash
# 1. Install dependencies
npm install

# 2. Set up PostgreSQL database
createdb odinforge
export DATABASE_URL=postgresql://user:pass@localhost:5432/odinforge

# 3. Run database migrations
npm run db:push

# 4. Set up Redis (macOS)
brew install redis
brew services start redis

# 5. Configure environment variables
cp .env.example .env
# Edit .env with your values

# 6. Start development server
npm run dev

# 7. Open browser
open http://localhost:5000
```

---

*Last Updated: February 7, 2026*
*Version: 1.1.0*
