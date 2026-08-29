import { useEffect, useState } from "react";

/**
 * MorphingSvgBackground
 * Provides an organic, fluid cyber-forensic SVG background with continuous
 * morphing bezier paths, chromatic gradient meshes, and floating luminous orbs
 * that illuminate transparent glassmorphism panels.
 */
export default function MorphingSvgBackground() {
  const [phase, setPhase] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setPhase((prev) => (prev + 1) % 4);
    }, 3500);
    return () => clearInterval(timer);
  }, []);

  const paths = [
    "M 120,40 Q 240,10 380,80 T 640,120 Q 820,180 940,90 T 1200,160 L 1200,600 L 0,600 L 0,120 Z",
    "M 120,80 Q 280,140 420,50 T 700,90 Q 860,60 980,140 T 1200,100 L 1200,600 L 0,600 L 0,60 Z",
    "M 120,60 Q 220,90 360,130 T 660,70 Q 840,140 960,80 T 1200,140 L 1200,600 L 0,600 L 0,100 Z",
    "M 120,100 Q 260,40 400,90 T 680,130 Q 880,90 1000,60 T 1200,110 L 1200,600 L 0,600 L 0,80 Z",
  ];

  const shieldPaths = [
    "M 50 15 Q 85 10 100 25 Q 115 10 150 15 Q 155 70 100 135 Q 45 70 50 15 Z",
    "M 50 20 Q 80 15 100 20 Q 120 15 150 20 Q 160 75 100 140 Q 40 75 50 20 Z",
    "M 48 18 Q 82 8 100 22 Q 118 8 152 18 Q 158 72 100 138 Q 42 72 48 18 Z",
    "M 52 14 Q 86 12 100 24 Q 114 12 148 14 Q 154 68 100 136 Q 46 68 52 14 Z",
  ];

  return (
    <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden select-none">
      {/* ─── Cyber Grid Overlay ─── */}
      <div
        className="absolute inset-0 opacity-[0.07]"
        style={{
          backgroundImage: `
            linear-gradient(to right, rgba(255, 255, 255, 0.1) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(255, 255, 255, 0.1) 1px, transparent 1px)
          `,
          backgroundSize: "48px 48px",
        }}
      />

      {/* ─── Floating Ambient Luminous Orbs (creates visible glass refraction) ─── */}
      <div className="absolute -top-32 -left-32 w-[550px] h-[550px] rounded-full bg-gradient-to-br from-phosphor-500/20 via-cyan-500/15 to-transparent blur-[120px] animate-pulse" style={{ animationDuration: "8s" }} />
      
      <div className="absolute top-[20%] right-[-10%] w-[650px] h-[650px] rounded-full bg-gradient-to-bl from-purple-500/20 via-blue-600/15 to-transparent blur-[140px] animate-pulse" style={{ animationDuration: "11s" }} />
      
      <div className="absolute bottom-[-10%] left-[25%] w-[600px] h-[600px] rounded-full bg-gradient-to-tr from-amber-500/15 via-crimson-signal/15 to-transparent blur-[130px] animate-pulse" style={{ animationDuration: "9s" }} />

      <div className="absolute top-[55%] left-[-5%] w-[450px] h-[450px] rounded-full bg-gradient-to-r from-blue-500/15 to-purple-600/15 blur-[110px]" />

      {/* ─── Top Ambient Morphing Waves ─── */}
      <svg
        className="absolute -top-28 -left-20 w-[140vw] h-[520px] opacity-60"
        viewBox="0 0 1200 600"
        preserveAspectRatio="none"
      >
        <defs>
          <linearGradient id="cyberMeshGrad1" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="rgba(61, 220, 151, 0.22)" />
            <stop offset="45%" stopColor="rgba(59, 130, 246, 0.14)" />
            <stop offset="100%" stopColor="rgba(139, 92, 246, 0.08)" />
          </linearGradient>
          <linearGradient id="cyberMeshGrad2" x1="100%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="rgba(59, 130, 246, 0.18)" />
            <stop offset="60%" stopColor="rgba(61, 220, 151, 0.10)" />
            <stop offset="100%" stopColor="transparent" />
          </linearGradient>
          <filter id="svgGlow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="24" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        <path
          d={paths[phase]}
          fill="url(#cyberMeshGrad1)"
          filter="url(#svgGlow)"
          className="transition-all duration-700 ease-in-out"
        />
        <path
          d={paths[(phase + 1) % 4]}
          fill="url(#cyberMeshGrad2)"
          opacity="0.8"
          className="transition-all duration-700 ease-in-out"
        />
      </svg>

      {/* ─── Floating Morphing Holographic Nodes in Corners ─── */}
      <div className="absolute top-24 right-20 w-48 h-48 opacity-40">
        <svg viewBox="0 0 200 160" className="w-full h-full">
          <path
            d={shieldPaths[phase]}
            fill="none"
            stroke="rgba(61, 220, 151, 0.7)"
            strokeWidth="1.5"
            strokeDasharray="4 6"
            className="transition-all duration-700 ease-in-out"
          />
          <circle cx="100" cy="75" r="3" fill="#3ddc97" className="animate-ping" />
        </svg>
      </div>

      <div className="absolute bottom-28 left-16 w-60 h-60 opacity-35">
        <svg viewBox="0 0 200 160" className="w-full h-full">
          <path
            d={shieldPaths[(phase + 2) % 4]}
            fill="none"
            stroke="rgba(139, 92, 246, 0.6)"
            strokeWidth="1.5"
            className="transition-all duration-700 ease-in-out"
          />
        </svg>
      </div>
    </div>
  );
}
