// Small shared UI primitives, introduced in the Tier-1 polish pass. Keeping them
// here means the type scale, elevation and motion decisions live in one place
// and the pages compose from them instead of re-deriving the same classes.

import type { ReactNode } from 'react'

// ── Skeletons ──────────────────────────────────────────────────────────────
// A shimmering placeholder that matches content shape, replacing bare spinners.

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`skeleton rounded-md ${className}`} />
}

/** A stack of card-shaped skeletons, for list pages while they load. */
export function CardSkeletons({ count = 3 }: { count?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="rounded-lg border border-line/60 bg-surface2 p-4 shadow-card">
          <div className="flex items-center gap-3">
            <Skeleton className="h-4 w-40" />
            <Skeleton className="ml-auto h-4 w-16" />
          </div>
          <Skeleton className="mt-3 h-3 w-3/4" />
          <div className="mt-3 flex gap-2">
            <Skeleton className="h-5 w-14" />
            <Skeleton className="h-5 w-14" />
            <Skeleton className="h-5 w-14" />
          </div>
        </div>
      ))}
    </div>
  )
}

// ── Empty state ────────────────────────────────────────────────────────────
// One consistent shape for "nothing here yet": a tinted icon, a line of copy,
// and the primary next action.

export function EmptyState({
  icon, title, hint, action,
}: {
  icon: ReactNode
  title: string
  hint?: string
  action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center gap-3 py-16 text-center">
      <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-accent/10
                      text-accent shadow-card ring-1 ring-white/5">
        {icon}
      </div>
      <div>
        <p className="text-sm font-medium text-txt">{title}</p>
        {hint && <p className="mt-0.5 text-xs text-txt-3">{hint}</p>}
      </div>
      {action}
    </div>
  )
}
