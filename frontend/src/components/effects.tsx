import type { CSSProperties, PointerEvent, ReactNode } from 'react'

// Dependency-free local equivalents of the spotlight, aurora and signal effects
// common in React Bits-style interfaces. No third-party component source is copied.

export function AmbientBackdrop() {
  return <div className="ambient-backdrop" aria-hidden="true">
    <span className="ambient-orb ambient-orb-cyan" />
    <span className="ambient-orb ambient-orb-violet" />
    <span className="ambient-grid" />
  </div>
}

export function SpotlightCard({ children, className = '' }: { children: ReactNode; className?: string }) {
  const trackPointer = (event: PointerEvent<HTMLElement>) => {
    const bounds = event.currentTarget.getBoundingClientRect()
    event.currentTarget.style.setProperty('--spot-x', `${event.clientX - bounds.left}px`)
    event.currentTarget.style.setProperty('--spot-y', `${event.clientY - bounds.top}px`)
  }

  return <article
    className={`spotlight-card ${className}`.trim()}
    onPointerMove={trackPointer}
    style={{ '--spot-x': '50%', '--spot-y': '50%' } as CSSProperties}
  >{children}</article>
}

export function SignalBeam() {
  return <span className="signal-beam" aria-hidden="true"><span /></span>
}
