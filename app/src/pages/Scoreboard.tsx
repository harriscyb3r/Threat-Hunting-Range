// The scoreboard: your hunt history, average score, and an ATT&CK coverage map.
// The coverage map is the portfolio view — which techniques you've hunted and
// identified, and which you have a saved detection for. A technique is only lit
// when you actually identified it in a scored hunt, so the map reflects skill,
// not attempts.

import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Trophy, Target, ShieldCheck, TrendingUp } from 'lucide-react'
import { api, huntApi, TACTIC_LABEL, type Technique } from '../lib/api'
import { EmptyState, Skeleton } from '../components/ui'

const GRADE_CLASS: Record<string, string> = {
  A: 'text-good', B: 'text-accent-light', C: 'text-conf-medium',
  D: 'text-decoy', F: 'text-mal', '—': 'text-txt-3',
}

export function Scoreboard() {
  const nav = useNavigate()
  const { data: board, isLoading } = useQuery({
    queryKey: ['scoreboard'],
    queryFn: huntApi.scoreboard,
    refetchInterval: 10000,
  })
  const { data: catalogue } = useQuery({ queryKey: ['techniques'], queryFn: api.techniques })

  if (isLoading || !board) {
    return (
      <div className="mx-auto max-w-4xl px-6 py-8">
        <Skeleton className="h-7 w-40" />
        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-20" />)}
        </div>
        <Skeleton className="mt-6 h-40" />
      </div>
    )
  }

  const played = board.hunts.filter((h) => h.overall > 0)

  if (board.hunts.length === 0) {
    return (
      <EmptyState
        icon={<Trophy size={26} />}
        title="No hunts scored yet"
        hint="Run a hunt end to end, then score it to see how you did."
        action={
          <button
            onClick={() => nav('/campaigns')}
            className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-black
                       hover:bg-accent-light hover:shadow-glow active:scale-[0.98]"
          >
            Start a hunt
          </button>
        }
      />
    )
  }

  return (
    <div className="mx-auto flex h-full max-w-4xl flex-col overflow-auto px-6 py-8">
      <h1 className="text-h1 text-txt">Scoreboard</h1>

      {/* Totals */}
      <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Tile icon={Trophy} label="Avg score" value={String(board.totals.avg_score)}
              sub={`${played.length} completed`} />
        <Tile icon={Target} label="Techniques found"
              value={String(board.totals.techniques_identified.length)}
              sub={`of ${catalogue?.implemented ?? '…'} playable`} />
        <Tile icon={ShieldCheck} label="With detection"
              value={String(board.totals.techniques_with_detection.length)}
              sub={`${board.totals.detections} detections`} />
        <Tile icon={TrendingUp} label="Hunts" value={String(board.totals.hunts)}
              sub="run so far" />
      </div>

      {/* ATT&CK coverage */}
      {catalogue && (
        <CoverageMap
          techniques={catalogue.techniques}
          identified={new Set(board.totals.techniques_identified)}
          detected={new Set(board.totals.techniques_with_detection)}
        />
      )}

      {/* Hunt history */}
      <h2 className="mt-8 text-sm font-semibold">Hunts</h2>
      <div className="mt-2 space-y-1.5">
        {board.hunts.map((h) => (
          <button
            key={h.hunt_id}
            onClick={() => nav(`/hunt/${h.hunt_id}`)}
            className="flex w-full items-center gap-3 rounded-lg border border-line/60 bg-surface2 shadow-card
                       px-4 py-2.5 text-left transition-all duration-200 hover:-translate-y-0.5 hover:border-line2 hover:shadow-raised"
          >
            <span className={`w-6 text-xl font-bold ${GRADE_CLASS[h.grade]}`}>{h.grade}</span>
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm text-txt">{h.title}</div>
              <div className="text-[11px] text-txt-3">
                {h.campaign_slug} · {h.phase}
                {h.outcome && ` · ${h.outcome}`}
              </div>
            </div>
            <div className="flex items-center gap-3 text-xs text-txt-2">
              <span title="technique recall">
                <Target size={11} className="mr-1 inline" />
                {Math.round(h.technique_recall * 100)}%
              </span>
              <span title="precision">
                <ShieldCheck size={11} className="mr-1 inline" />
                {Math.round(h.precision * 100)}%
              </span>
              <span className="w-8 text-right font-medium text-txt">{h.overall}</span>
            </div>
          </button>
        ))}
      </div>
    </div>
  )
}

function CoverageMap({
  techniques, identified, detected,
}: { techniques: Technique[]; identified: Set<string>; detected: Set<string> }) {
  const byTactic = useMemo(() => {
    const m = new Map<string, Technique[]>()
    for (const t of techniques) {
      if (!t.has_emitter) continue
      const list = m.get(t.tactic) ?? []
      list.push(t)
      m.set(t.tactic, list)
    }
    return [...m.entries()]
  }, [techniques])

  return (
    <div className="mt-6 rounded-lg border border-line bg-surface2 p-4 shadow-card">
      <div className="mb-3 flex items-center justify-between">
        <span className="text-sm font-medium">ATT&CK coverage</span>
        <div className="flex items-center gap-3 text-[10px] text-txt-3">
          <span className="flex items-center gap-1">
            <span className="h-3 w-3 rounded-sm bg-good/70" /> identified
          </span>
          <span className="flex items-center gap-1">
            <span className="h-3 w-3 rounded-sm bg-accent/40 ring-1 ring-accent" /> + detection
          </span>
          <span className="flex items-center gap-1">
            <span className="h-3 w-3 rounded-sm bg-surface3" /> not yet
          </span>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-3">
        {byTactic.map(([tactic, techs]) => (
          <div key={tactic}>
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-txt-3">
              {TACTIC_LABEL[tactic] ?? tactic}
            </div>
            <div className="flex flex-wrap gap-1">
              {techs.map((t) => {
                const found = identified.has(t.id)
                const det = detected.has(t.id)
                const cls = det
                  ? 'bg-accent/40 text-accent-light ring-1 ring-accent'
                  : found
                    ? 'bg-good/60 text-black'
                    : 'bg-surface3 text-txt-3'
                return (
                  <span
                    key={t.id}
                    title={`${t.id} ${t.name}${found ? ' — identified' : ''}${det ? ' + detection saved' : ''}`}
                    className={`rounded px-1.5 py-0.5 font-mono text-[10px] ${cls}`}
                  >
                    {t.id}
                  </span>
                )
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function Tile({
  icon: Icon, label, value, sub,
}: { icon: typeof Trophy; label: string; value: string; sub: string }) {
  return (
    <div className="rounded-lg border border-line bg-surface2 px-4 py-3">
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-txt-3">
        <Icon size={12} /> {label}
      </div>
      <div className="mt-1 text-2xl font-semibold text-txt">{value}</div>
      <div className="text-[10px] text-txt-3">{sub}</div>
    </div>
  )
}
