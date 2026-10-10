/** The AVHSOL mark: three nodes and the synapses between them. Decorative; the wordmark carries the name. */
export function Logo({ size = 30 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id="lg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#4dd8ff" />
          <stop offset="1" stopColor="#8f80ff" />
        </linearGradient>
      </defs>
      <g stroke="url(#lg)" strokeWidth="1.6" strokeLinecap="round" fill="none">
        <path d="M16 5 L5.5 24 L26.5 24 Z" opacity="0.9" />
        <path d="M16 5 L16 17.5 M5.5 24 L16 17.5 M26.5 24 L16 17.5" opacity="0.55" />
      </g>
      <circle cx="16" cy="5" r="3" fill="#ff5577" />
      <circle cx="5.5" cy="24" r="3" fill="#8f80ff" />
      <circle cx="26.5" cy="24" r="3" fill="#35e3ac" />
      <circle cx="16" cy="17.5" r="2.2" fill="#4dd8ff" />
    </svg>
  );
}
