/**
 * MorphingSvgBackground
 * Quiet decorative background for the professional "paper planner" theme:
 * a warm cream wash with a few thin, unfilled wave strokes (teal dusk,
 * forest, ember) along the top edge. Purely decorative — never carries
 * content, sits behind every page, and keeps the same position/stacking
 * as the previous background so no layout changes.
 */
export default function MorphingSvgBackground() {
  return (
    <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden select-none" aria-hidden="true">
      {/* Warm cream band behind the top of the page */}
      <div
        className="absolute inset-x-0 top-0 h-[420px]"
        style={{ background: "linear-gradient(180deg, #fff6f0 0%, rgba(255,246,240,0.55) 55%, rgba(247,245,241,0) 100%)" }}
      />

      {/* Thin flowing strokes — the design's decorative wave system */}
      <svg
        className="absolute -top-6 left-0 w-full h-[260px]"
        viewBox="0 0 1440 260"
        preserveAspectRatio="none"
        fill="none"
      >
        <path d="M0 120 C 240 60, 420 190, 720 130 S 1200 60, 1440 140" stroke="#497d7e" strokeOpacity="0.22" strokeWidth="1.5" />
        <path d="M0 150 C 260 100, 460 210, 760 160 S 1180 100, 1440 170" stroke="#446c3d" strokeOpacity="0.16" strokeWidth="1.25" />
        <path d="M0 95 C 300 40, 520 150, 820 100 S 1220 40, 1440 105" stroke="#e34432" strokeOpacity="0.12" strokeWidth="1" />
      </svg>
    </div>
  );
}
