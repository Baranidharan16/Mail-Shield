# MailShield UI design system

Source: `DESIGN 1.md` (Todoist-style "paper planner" reference), chosen over the
coral/serif lifestyle reference because a forensic tool should feel calm and
professional rather than decorative.

## Rule: layout is unchanged

This theme changes **colour, type, borders and shadows only**. Page structure,
component arrangement, spacing, order of sections and all behaviour are exactly
as before. The switch is done at the token level in `src/index.css`:

- Every legacy palette used in markup (`lab`, `slate`, `phosphor`, `emerald`,
  `blue`, `purple`, ...) is remapped in `@theme`, so existing class names now
  render in the new palette.
- Dark-UI steps are inverted: `900/950` (old backgrounds) are now paper tones,
  `100–400` (old light text) are now ink tones.
- `white` means ink and `black` means paper, because in the old dark UI
  "white" was primary text and translucent white was hairlines/overlays.
  Use `text-snow` when real white text is needed on a filled button.
- The old glass classes (`glass-card`, `glass-section`, `btn-glass-*`, ...)
  keep their names but are now flat paper cards with hairline borders.

## Tokens

| Role | Value |
|------|-------|
| Canvas | `#f7f5f1` (page), `#fefdfc` paper (cards), `#fff6f0` cream wash (top band) |
| Text | `#25221e` ink, `#6f6c69` pencil (muted), `#94928f` graphite (faint) |
| Borders | `#e2dfda` hairline, `#d7d6d4` stone (inputs, secondary buttons) |
| Primary action | `#e34432` ember, hover `#cf3520`: one filled button per view |
| Safe / positive | forest `#446c3d`, wash `#f0f6df` |
| Info / links | cobalt `#0f66ae`, wash `#dceaff` |
| Severity | critical `#b9301f`, high `#e0712a`, medium `#d99a2b`, low cobalt |
| Secondary accent | teal dusk `#497d7e`; muted plum `#5d4b7c` for categorical data only |

- Type: Inter for UI and headings (slight negative tracking on headings);
  IBM Plex Mono only for data such as hashes, IPs and case IDs.
- Radius: 8px on cards, buttons, inputs and badges.
- Elevation: a 1px hairline shadow on cards; no glow, blur or neon.
- Badges: pale wash background with chromatic text, never a saturated fill.
