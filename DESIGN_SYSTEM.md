# OdinForge Afterglow Design System

A comprehensive cybersecurity-themed UI design system with neon aesthetics, glassmorphism, and dynamic visual effects.

## 🎨 Color System

### Primary Colors
```css
--glow-red: 0 84% 50%      /* Critical/Danger/Alerts */
--glow-cyan: 189 94% 43%   /* Info/Active/Default */
--glow-green: 142 76% 45%  /* Safe/Success/Healthy */
--glow-purple: 271 81% 56% /* Admin/Elevated/New */
--glow-orange: 25 95% 53%  /* Warning/Medium */
```

### Semantic Usage
- **Red**: Critical alerts, exploitable vulnerabilities, danger
- **Cyan**: Information, active status, primary actions
- **Green**: Safe systems, successful operations, healthy status
- **Purple**: Administrative actions, elevated privileges, new items
- **Orange**: Warnings, medium priority, caution

## 🔮 Utility Classes

### Glow Effects
```css
.glow-red           /* Large red glow (20px/40px/60px) */
.glow-red-sm        /* Small red glow (10px/20px) */
.glow-cyan
.glow-cyan-sm
.glow-green
.glow-green-sm
.glow-purple
.glow-purple-sm
```

### Glassmorphism
```css
.glass              /* Translucent (50% opacity, 12px blur) */
.glass-strong       /* More opaque (70% opacity, 16px blur) */
```

### Animations
```css
.pulse-glow         /* Pulsing glow animation (2s) */
.border-glow-animated /* Animated gradient border on hover */
.scan-line          /* CRT-style scan line effect */
.holographic        /* Rainbow shimmer animation */
```

### Text Effects
```css
.text-neon-red      /* Glowing red text */
.text-neon-cyan     /* Glowing cyan text */
.text-neon-green    /* Glowing green text */
```

### Backgrounds
```css
.grid-bg            /* Cybersecurity grid pattern */
```

## 📦 Components

### OdinForgeLogo
Animated branding with neon red/cyan text and pulsing shield icon.

```tsx
<OdinForgeLogo
  size="md"          // sm | md | lg | xl
  animated={true}    // Enable animations
  showIcon={true}    // Show shield icon
/>
```

### GlowCard
Glassmorphic card with configurable glow colors.

```tsx
<GlowCard
  glowColor="cyan"   // red | cyan | green | purple | none
  glowIntensity="md" // sm | md | lg
  glass={true}       // Enable glassmorphism
  animated={true}    // Animated border
  scanLine={true}    // Scan line effect
>
  <GlowCardHeader>
    <GlowCardTitle>Title</GlowCardTitle>
  </GlowCardHeader>
  <GlowCardContent>Content</GlowCardContent>
</GlowCard>
```

### HolographicCard
Rainbow shimmer effect for premium feel.

```tsx
<HolographicCard
  variant="default"  // default | intense | subtle
  animated={true}    // Enable shimmer
  scanLine={true}    // Scan line effect
  borderGlow={true}  // Border glow on hover
>
  <HolographicCardContent>...</HolographicCardContent>
</HolographicCard>
```

### StatCard
Enhanced metric display with dynamic glows.

```tsx
<StatCard
  label="Critical Findings"
  value={stats.critical}
  icon={AlertTriangle}
  colorClass="text-red-400"
  critical={stats.critical > 0} // Triggers pulse-glow
  trend={{ value: 12, isPositive: false }}
/>
```

### Terminal
Interactive cybersecurity terminal.

```tsx
<Terminal
  prompt="odin@forge:~$"
  onCommand={async (cmd) => {
    // Handle command
    return "Command output";
  }}
  autoFocus={true}
  maxLines={100}
/>
```

### LoadingSpinner
Enhanced loading states.

```tsx
<LoadingSpinner
  variant="cyber"    // default | cyber | pulse
  size="md"          // sm | md | lg
  message="Scanning..."
/>
```

### GlowChartContainer
Chart wrapper with glow effects.

```tsx
<GlowChartContainer
  title="Risk Trends"
  glowColor="cyan"
>
  <YourChartComponent />
</GlowChartContainer>
```

### Animated Backgrounds

```tsx
// Particle system
<ParticleBackground
  particleCount={50}
  particleColor="#06b6d4"
  speed={0.5}
  opacity={0.3}
/>

// Gradient orbs
<GradientOrb
  color1="red"
  color2="orange"
  size="lg"
  className="top-10 right-10"
/>

// Grid background
<GridBackground className="opacity-20" />

// CRT scan lines
<ScanLines />

// Matrix rain
<MatrixRain />
```

## 🎵 Sound Effects

```tsx
import { useSound } from "@/lib/sounds";

function MyComponent() {
  const sound = useSound();

  return (
    <button onClick={() => sound.play("click")}>
      Click Me
    </button>
  );
}

// Available sounds:
sound.play("click");        // UI click
sound.play("success");      // Success notification
sound.play("error");        // Error alert
sound.play("warning");      // Warning
sound.play("scan");         // Scanning effect
sound.play("notification"); // General notification

// Custom frequency sweep
sound.playSweep(1000, 2000, 500); // startFreq, endFreq, duration

// Enable/disable
sound.setEnabled(true);
sound.setVolume(0.5); // 0-1
```

## 🏗️ Page Templates

### Dashboard Pattern
```tsx
<div className="space-y-6 relative">
  {/* Animated background */}
  <ParticleBackground />
  <GradientOrb color1="red" color2="cyan" />

  {/* Grid overlay */}
  <div className="absolute inset-0 grid-bg opacity-20" />

  {/* Header */}
  <div className="relative z-10">
    <h1 className="flex items-center gap-2">
      <Icon className="glow-cyan-sm" />
      <span className="text-neon-cyan">Title</span>
    </h1>
  </div>

  {/* Stats */}
  <div className="grid grid-cols-4 gap-4">
    <StatCard ... />
  </div>

  {/* Content */}
  <GlowCard>...</GlowCard>
</div>
```

### Risk Dashboard Pattern
```tsx
<div className="relative">
  <ParticleBackground particleCount={30} />
  <GradientOrb size="lg" className="top-10 right-10" />

  <div className="relative z-10">
    <HolographicCard className={critical && "pulse-glow"}>
      ...
    </HolographicCard>
  </div>
</div>
```

## 🎯 Best Practices

### Performance
- Limit particle count to 30-50 for smooth performance
- Use `pointer-events-none` on backgrounds
- Prefer CSS animations over JavaScript when possible
- Use `requestAnimationFrame` for smooth 60fps

### Accessibility
- Provide option to disable animations (prefers-reduced-motion)
- Ensure sufficient color contrast for text
- Don't rely solely on color to convey information
- Provide text alternatives for visual-only indicators

### Consistency
- Use glow effects sparingly for emphasis
- Match glow colors to semantic meanings
- Maintain consistent spacing (4px grid)
- Use tabular numbers for metrics
- Uppercase tracking for labels

### Z-Index Layers
```
50  - Modals, overlays
40  - Sticky headers
30  - Dropdowns, popovers
20  - Tooltips
10  - Content layer
0   - Background layer
-1  - Animated backgrounds, effects
```

## 📱 Responsive Design

All components are mobile-responsive:
- StatCards: 2 cols mobile → 3 cols tablet → 5 cols desktop
- Grid layouts: 1 col mobile → 2 cols tablet → 4 cols desktop
- Headers: Stack vertically on mobile
- Particle count: Reduce on small screens

## 🎨 Theme Customization

Override CSS variables in `index.css`:

```css
:root {
  --glow-red: 0 84% 50%;        /* Your red */
  --glow-cyan: 189 94% 43%;     /* Your cyan */
  --background: 0 0% 3%;        /* Your background */
  /* ... */
}
```

## 🚀 Getting Started

1. Import components:
```tsx
import { GlowCard } from "@/components/ui/glow-card";
import { ParticleBackground } from "@/components/ui/animated-background";
```

2. Add to your page:
```tsx
export default function MyPage() {
  return (
    <div className="relative">
      <ParticleBackground />
      <GlowCard glowColor="cyan">
        Your content
      </GlowCard>
    </div>
  );
}
```

3. Style with utilities:
```tsx
<div className="glass glow-cyan-sm scan-line">
  Cybersecurity content
</div>
```

## 📚 Examples

See implemented examples in:
- `client/src/components/Dashboard.tsx` - Full dashboard with stats
- `client/src/pages/Agents.tsx` - Enhanced metrics
- `client/src/pages/RiskDashboard.tsx` - Holographic cards with particles
- `client/src/components/OdinForgeLogo.tsx` - Animated branding

---

**Built for OdinForge AI** - Next-generation cybersecurity automation platform
