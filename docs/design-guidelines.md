# AEV Platform Design Guidelines

## Design Approach

**Selected Framework**: Hybrid approach combining Material Design's component structure with custom cyber-security aesthetics inspired by cutting-edge security platforms like Wiz, Snyk, and modern SOC dashboards.

**Core Principles**:
- Data density with clarity - maximize information without overwhelming
- Real-time dynamism - everything feels live and responsive
- Technical credibility - designs that security professionals trust
- Visual boldness - stand out from traditional enterprise security tools

## Typography System

**Font Stack**: 
- Primary: "Inter" for UI text (clean, modern, excellent at small sizes)
- Monospace: "JetBrains Mono" for code, IDs, technical data
- Display: "Inter" at bold weights for headings

**Hierarchy**:
- Page Titles: 2xl (24px), bold, tight line-height (1.1)
- Section Headers: lg (18px), semibold 
- Card Titles: base (16px), semibold
- Body Text: sm (14px), regular
- Metadata/Labels: xs (12px), medium, uppercase tracking-wide
- Technical Data: sm (14px), mono font

## Layout System

**Spacing Scale**: Use Tailwind units of **4, 6, 8, 12, 16, 20, 24** for consistency
- Component padding: p-6 (cards), p-8 (major sections)
- Between sections: mb-8, gap-6
- Dense data areas: p-4, gap-4
- Page margins: p-6 to p-8

**Grid Patterns**:
- Dashboard stats: 5-column grid for metrics (grid-cols-5 gap-4)
- Evaluation cards: 3-column on desktop (grid-cols-1 md:grid-cols-2 lg:grid-cols-3)
- Detail pages: 2-column layout (main content 2/3, sidebar 1/3)
- Responsive: Always stack to single column on mobile

## Component Library

### Navigation
**Top Navigation Bar**:
- Full-width with logo left, navigation center, user menu right
- Height: h-16
- Sticky positioning with subtle backdrop blur
- Navigation items with icon + label pairs
- Active state indicators beneath items

### Dashboard Cards
**Stat Cards**:
- Compact, fixed height (h-24)
- Large numerical value (2xl font) with label beneath
- Icon in corner or integrated with layout
- Subtle border treatment

**Evaluation Table**:
- Sortable column headers with sort indicators
- Row height: py-3 for comfortable scanning
- Alternate row treatment for visual rhythm
- Status badges inline with clear visual hierarchy
- Hover state reveals action buttons

**Quick View Drawer**:
- Slides from right, 1/3 viewport width on desktop
- Shows summary info with "View Full Details" CTA
- Smooth slide-in animation (transition-transform duration-300)

### Attack Path Visualization
**Node Graph Layout**:
- Numbered circles (w-10 h-10) connected by lines
- Progressive reveal as stages complete
- Each node shows stage name + brief description
- Vertical flow for mobile, can be horizontal for desktop
- Visual distinction between completed/active/pending states

**Exploitability Gauge**:
- Semicircular gauge showing 0-100 score
- Segmented into risk zones (0-20, 20-40, 40-60, 60-80, 80-100)
- Large score number centered below arc
- Legend showing current risk level (Critical/High/Medium/Low/Minimal)

### Progress Modal
**Real-time Evaluation Modal**:
- Centered overlay with backdrop blur
- Compact width (max-w-lg)
- Top section: gradient header with asset info
- Progress bar: 2-pixel height, smooth animation
- Stage cards: 4 stages in vertical stack
- Each stage shows icon, name, description, status indicator
- Animated loader icon for active stage
- Completion view with summary stats (confidence %, risk score)

### Form Components
**New Evaluation Modal**:
- Centered, max-w-md
- Form sections with clear labels (text-xs uppercase)
- Select dropdowns for exposure type, module, priority
- Textarea for description (rows-4)
- Two-column layout for related fields
- Primary action button full-width at bottom

### Data Visualization
**Attack Path Diagram**:
- Step-by-step numbered flow (1 → 2 → 3)
- Connecting lines between steps
- Each step in a bordered card
- Conditional rendering based on exploitability

**Evidence Sections**:
- Collapsible accordions for detailed findings
- Code blocks with syntax highlighting
- Tabbed interface for multiple evidence types

**Impact Assessment Cards**:
- Grid of impact metrics (Confidentiality, Integrity, Availability)
- Icon + label + severity indicator
- Visual hierarchy emphasizing critical impacts

### Filtering & Sorting
**Filter Bar**:
- Horizontal button group for quick filters (All, Pending, Completed, Exploitable, Safe)
- Compact button sizing (px-3 py-1.5, text-xs)
- Clear active state treatment

**Sort Controls**:
- Inline with table headers
- Chevron indicators for sort direction
- Click to toggle ascending/descending

## Page Layouts

### Dashboard (AEVPage)
**Structure**:
1. Header row: Title + description left, action buttons right
2. Stats grid: 5 equal-width cards
3. Filter bar: Horizontal button array
4. Main content: Responsive table with infinite scroll
5. Modals: Progress overlay, new evaluation form

### Detail Page (AEVDetailPage)
**Structure**:
1. Breadcrumb/back link
2. Header: Title, status badge, metadata (created, duration)
3. Two-column grid:
   - Left (2/3 width): Exposure Summary, Attack Path
   - Right (1/3 width): Exploitability Scores, Recommendations
4. Each section in bordered card with icon header

### Evaluation Detail Sections
**Section 1 - Exposure Summary**:
- 2x2 grid of metadata fields
- Full-width description area beneath grid
- Each field: small label + larger value

**Section 2 - Exploitability Scores**:
- Large gauge visualization at top
- Confidence bar beneath
- Status indicators
- Risk classification label

**Section 3 - Attack Path**:
- Vertical step visualization
- Numbered nodes with connecting lines
- Text description for each step
- Empty state for non-exploitable findings

**Section 4 - Recommendations**:
- Two subsections: Remediation + Compensating Controls
- Each as numbered or bulleted list
- Priority indicators for recommendations

## Responsive Behavior
- **Desktop (lg+)**: Multi-column grids, side-by-side layouts
- **Tablet (md)**: 2-column max, reduced gutters
- **Mobile (base)**: Single column stack, full-width components, compact spacing (p-4)

## Animation Guidelines
**Minimal, Purposeful Animations**:
- Progress bars: Smooth width transitions (duration-500)
- Modal entry/exit: Slide and fade (duration-300)
- Loading states: Subtle spin on icons
- Hover states: Simple opacity/shadow changes
- **Avoid**: Excessive parallax, complex transitions, auto-playing animations

## Images
**Hero Section**: Not applicable - this is a utility dashboard application
**Icons**: Use Lucide React icon library exclusively via npm
**Logos/Branding**: Placeholder for company logo in navigation
**Visualization Graphics**: SVG-based gauges, charts, and diagrams (custom components)

## Accessibility
- All interactive elements have visible focus states
- Form inputs with associated labels
- Sufficient contrast ratios throughout
- Keyboard navigation support for all actions
- Screen reader friendly status announcements
- ARIA labels for icon-only buttons