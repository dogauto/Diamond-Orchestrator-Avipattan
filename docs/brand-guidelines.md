# kósmos of Paradox — Brand Guidelines v1.0

> Last updated: 2026-11-16
> Status: Active
> Parent brand: **kósmos of Paradox** — *We exist nowhere but exist in everywhere.*

## Quick Reference

| Element | Value |
|---------|-------|
| Primary Color | #0B0E1A |
| Secondary Color | #7BE7FF |
| Accent Color | #FF6FC8 |
| Primary Font | Cinzel |
| Body Font | Inter |
| Voice | Mysterious, Precise, Weightless |

---

## 1. Color Palette

The palette is the visual statement of the brand: **black void, prismatic light, iridescent metal**. Nothing is flat; everything refracts.

### Primary Colors

| Name | Hex | RGB | Usage |
|------|-----|-----|-------|
| Void Black | #0B0E1A | rgb(11,14,26) | Page background, canvas, negative space |
| Deep Indigo | #141A33 | rgb(20,26,51) | Surfaces, cards, elevated panels |
| Prism White | #F4EDE4 | rgb(244,237,228) | Primary text on dark, light-wordmark |

### Secondary Colors

| Name | Hex | RGB | Usage |
|------|-----|-----|-------|
| Spectral Cyan | #7BE7FF | rgb(123,231,255) | Primary accent, focus states, links |
| Halo Blue | #A8C8FF | rgb(168,200,255) | Secondary glow, gradient midpoint |
| Signal Red | #E8453C | rgb(232,69,60) | Attention, the red orbital arc |

### Accent Colors

| Name | Hex | RGB | Usage |
|------|-----|-----|-------|
| Iridescent Pink | #FF6FC8 | rgb(255,111,200) | The butterfly, the dream layer, highlights |
| Amber Reflection | #FFC98B | rgb(255,201,139) | Warm flare, gold refraction, warmth in the void |
| Chromatic Violet | #9A6BFF | rgb(154,107,255) | Depth, dream-state gradient |

### Neutral Palette

| Name | Hex | RGB | Usage |
|------|-----|-----|-------|
| Void | #05060C | rgb(5,6,12) | Deepest background |
| Surface | #10162B | rgb(16,22,43) | Panels, footer bands |
| Text Primary | #F4EDE4 | rgb(244,237,228) | Headings, body |
| Text Secondary | #8C94AB | rgb(140,148,171) | Captions, metadata |
| Border | #232B45 | rgb(35,43,69) | Dividers, hairlines |

### Gradient Signatures

| Name | Stops | Usage |
|------|-------|-------|
| Prism Arc | #7BE7FF → #A8C8FF → #FF6FC8 | Hero light, orbital rings, dividers |
| Dream Bloom | #9A6BFF → #FF6FC8 → #FFC98B | The butterfly, accent motion |
| Event Horizon | #05060C → #141A33 → #0B0E1A | Backgrounds, vignettes |

### Accessibility

- Prism White on Void Black: **16.8:1** (AAA)
- Spectral Cyan on Void Black: **12.4:1** (AAA)
- Iridescent Pink on Void Black: **7.9:1** (AAA)
- Text Secondary on Void Black: **6.1:1** (AA)
- All interactive elements meet WCAG 2.1 AA minimum

---

## 2. Typography

### Font Stack

```css
--font-heading: 'Cinzel', 'Trajan Pro', Georgia, serif;
--font-body: 'Inter', system-ui, -apple-system, sans-serif;
--font-mono: 'JetBrains Mono', 'Fira Code', monospace;
```

**Cinzel** carries the carved-into-stone authority: a name that was always there.
**Inter** keeps the technical surface readable — the brand talks in whispers but writes clearly.

### Type Scale

| Element | Desktop | Mobile | Weight | Line Height | Tracking |
|---------|---------|--------|--------|-------------|----------|
| Display | 61px | 40px | 700 | 1.1 | 0.08em |
| H1 | 49px | 32px | 700 | 1.2 | 0.06em |
| H2 | 39px | 28px | 600 | 1.25 | 0.04em |
| H3 | 31px | 24px | 600 | 1.3 | 0.03em |
| Body Large | 18px | 18px | 400 | 1.6 | 0 |
| Body | 16px | 16px | 400 | 1.5 | 0 |
| Small | 14px | 14px | 400 | 1.5 | 0 |
| Caption | 12px | 12px | 400 | 1.4 | 0.05em |

### Font Loading

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@600;700&family=Inter:wght@400;500&display=swap" rel="stylesheet">
```

---

## 3. Logo Usage

### Variants

| Variant | File | Use Case |
|---------|------|----------|
| Full Color | dimond-logo.svg | Default on void backgrounds |
| Stacked | dimond-logo.svg | Square spaces, README hero |
| Icon Only | logos/icon-only/ | Favicons, avatars, small marks |
| Monochrome | logos/monochrome/ | Single-color print, embossing |

### Clear Space

Minimum clear space = height of the light core of the mark. The logo must breathe; the void around it is part of the identity.

### Minimum Size

| Context | Minimum Width |
|---------|---------------|
| Digital — Full Logo | 120px |
| Digital — Icon | 24px |
| Print — Full Logo | 35mm |
| Print — Icon | 10mm |

### Don'ts

- Don't rotate or skew the mark — the prism is already in motion
- Don't substitute colors outside the palette
- Don't add drop shadows — the glow is intrinsic
- Don't place on white without the void plate behind it
- Don't crop the prismatic flare

---

## 4. Voice & Tone

### Brand Personality

| Trait | Description |
|-------|-------------|
| **Mysterious** | Says less than it knows. The void does the talking. |
| **Precise** | Every word placed like a facet. No filler. |
| **Weightless** | Cosmic scale, zero effort. Never strained, never loud. |
| **Inevitable** | Not convincing you. Stating what already is. |

### Voice Chart

| Trait | We Are | We Are Not |
|-------|--------|------------|
| Mysterious | Suggestive, open-ended | Vague, evasive |
| Precise | Exact, evidenced | Mechanical, cold |
| Weightless | Calm, unhurried | Sluggish, passive |
| Inevitable | Assured | Arrogant, hyped |

### Tone by Context

| Context | Tone | Example |
|---------|------|---------|
| Marketing | Prophetic, minimal | "Where intelligence bends to intention." |
| Documentation | Clean, factual | "Run the command to start." |
| README hero | One line, no explanation | "We exist nowhere but exist in everywhere." |
| Error messages | Calm, direct | "That path is outside the workspace. Pick another." |
| Success | Quiet confirmation | "Recorded." |

### Prohibited Terms

| Avoid | Reason |
|-------|--------|
| Revolutionary | Overused, no meaning |
| Cutting-edge | Vague claim |
| Seamless | Overused |
| Synergy | Corporate jargon |
| Leverage | Use "use" |
| Unleash | Hype register |
| Game-changer | Hype register |

### Voice Samples

**Too loud:**
> We're thrilled to announce our revolutionary AI orchestration platform that will transform your workflows!

**On brand:**
> Diamond routes work to six providers. The ledger remembers what happened. Evidence decides what comes next.

---

## 5. Messaging

### Mission

We build systems that hold their own account of what happened, so intelligence can be directed without being trusted blindly.

### Tagline Ladder

| Level | Line |
|-------|------|
| Company | We exist nowhere but exist in everywhere. |
| Product | Where intelligence bends to intention. |
| Proof | Evidence, or it did not happen. |

### Message by Audience

| Audience | Pain | Message | CTA |
|----------|------|---------|-----|
| Engineers | AI work that can't be audited | Every attempt is recorded. Every claim is checked. | Read the ledger design |
| Operators | Unbounded agents | Bounded execution, reversible state | See the constraints |
| Collaborators | Unclear provenance | Exact bytes, exact evidence | Read the docs |

---

## 6. Imagery Guidelines

### Visual Language

The brand lives in **light against void**: prismatic refraction, holographic metal, orbital arcs, cosmic scale, and one living accent — the butterfly.

| Reference | Element | Rule |
|-----------|---------|------|
| Prismatic starburst | Lens flares, spectral dispersion | Always radiating from a bright core; never decorative noise |
| Chrome/organic figure | Translucent, iridescent, human-shaped but not human | Body as a material study, never a portrait |
| Dove / butterfly | Light-splitting, pixel-dissolving | Motion and transformation, never a literal animal photo |
| Orbital infinity | Thin glowing arcs on black | Precisely circular, perfectly symmetrical |
| Comet / feather trails | Particle tails | Long exposure feel, chromatic fringe |

### Photography / Render Style

- **Lighting:** single hard light source, strong chromatic dispersion, deep blacks
- **Subject:** abstract cosmic or material studies; no stock people
- **Color treatment:** high contrast, iridescent fringes, no flat fills
- **Composition:** centered radial symmetry or off-axis diagonal sweep; heavy negative space

### Visual Don'ts

| Avoid | Reason |
|-------|--------|
| Flat vector illustrations | Breaks the light-and-void principle |
| Generic neon glow on dark | Cheap, undifferentiated |
| Lens flare without a light source | Unmotivated effect |
| Literal stock photography | No mystique |
| Rainbow gradients without black | Loses the void |

### AI Image Base Prompt

```
dark void background (#0B0E1A), single intense light source with chromatic
dispersion and prismatic lens flare, iridescent chrome or translucent organic
subject, spectral cyan (#7BE7FF) and iridescent pink (#FF6FC8) light fringing,
warm amber refraction (#FFC98B) on edges, deep black negative space,
cinematic, high contrast, no text
```

---

## 7. Asset Organization

```
assets/
├── dimond-logo.svg            # Primary mark with breathing animation
├── dimond-logo.jpg            # Source raster (1080×1080)
└── logos/
    ├── full-horizontal/       # Wordmark + mark
    ├── icon-only/             # Favicons, avatars
    └── monochrome/            # Single-color print
```

Naming: `{type}_{campaign}_{description}_{YYYYMMDD}_{variant}.{ext}`

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-11-16 | Initial brand guidelines from 13 reference images |
