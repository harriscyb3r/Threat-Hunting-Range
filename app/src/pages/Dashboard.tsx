// The landing dashboard — the app's front door. It orients you and shows
// momentum: engine state, what you've built, how you're scoring, curriculum
// progress, and a way straight back into whatever you were doing. Composed
// entirely from data the other pages already fetch, so it adds no new backend.

import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  Crosshair, Terminal, GraduationCap, ShieldCheck, Trophy, Target, FolderSearch,
  ArrowRight, FlaskConical, Boxes,
} from 'lucide-react'
import { api, huntApi, detectionApi, learnApi, type Technique } from '../lib/api'

const GRADE_CLASS: Record<string, string> = {
  A: 'text-good', B: 'text-accent-light', C: 'text-conf-medium',
  D: 'text-decoy', F: 'text-mal', '—': 'text-txt-3',
}

export function Dashboard() {
  const nav = useNavigate()
  const { data: status } = useQuery({ queryKey: ['status'], queryFn: api.status })
  const { data: board } = useQuery({ queryKey: ['scoreboard'], queryFn: huntApi.scoreboard })
  const { data: curriculum } = useQuery({ queryKey: ['curriculum'], queryFn: learnApi.curriculum })
  const { data: detections } = useQuery({ queryKey: ['detections'], queryFn: () => detectionApi.list() })
  const { data: hunts } = useQuery({ queryKey: ['hunts-all'], queryFn: () => huntApi.list() })
  const { data: catalogue } = useQuery({ queryKey: ['techniques'], queryFn: api.techniques })

  const campaigns = (status?.campaigns ?? []).filter((c) => c.kind === 'campaign')
  const ready = campaigns.filter((c) => c.status === 'ready')
  const engineUp = status?.engine.up ?? false

  // The hunt to "continue": the most recently updated one not yet closed.
  const resumeHunt = useMemo(
    () => (hunts?.hunts ?? []).find((h) => h.phase !== 'closed'),
    [hunts],
  )

  const greeting = (() => {
    const h = new Date().getHours()
    if (h < 12) return 'Good morning'
    if (h < 18) return 'Good afternoon'
    return 'Good evening'
  })()

  const avg = board?.totals.avg_score ?? 0
  const identified = new Set(board?.totals.techniques_identified ?? [])
  const detected = new Set(board?.totals.techniques_with_detection ?? [])

  return (
    <div className="mx-auto flex h-full max-w-4xl flex-col overflow-auto px-6 py-8">
      {/* Hero */}
      <div className="flex items-end justify-between">
        <div>
          <div className="flex items-center gap-2 text-xs text-txt-3">
            <Crosshair size={13} className="text-accent" />
            {new Date().toLocaleDateString(undefined, {
              weekday: 'long', month: 'long', day: 'numeric',
            })}
          </div>
          <h1 className="mt-1 text-display">
            <span className="bg-gradient-to-r from-accent to-accent-light bg-clip-text
                             text-transparent">{greeting}.</span>{' '}
            <span className="text-txt">Ready to hunt?</span>
          </h1>
        </div>
        <div className="flex items-center gap-2 text-xs text-txt-2">
          <span className={`h-2 w-2 rounded-full ${engineUp ? 'bg-good' : 'bg-mal'}`} />
          {engineUp ? 'Engine ready' : 'Engine down'}
        </div>
      </div>

      {/* Stat tiles */}
      <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat icon={FolderSearch} label="Campaigns" value={ready.length}
              sub={`${campaigns.length - ready.length || 0} building`}
              onClick={() => nav('/campaigns')} />
        <Stat icon={Trophy} label="Avg score" value={avg || '—'}
              sub={`${board?.totals.hunts ?? 0} hunts`}
              onClick={() => nav('/scoreboard')} />
        <Stat icon={ShieldCheck} label="Detections" value={detections?.detections.length ?? 0}
              sub={`${detected.size} techniques`}
              onClick={() => nav('/detections')} />
        <Stat icon={GraduationCap} label="Lessons"
              value={`${curriculum?.completed ?? 0}/${curriculum?.total_lessons ?? 16}`}
              sub="SC-200 curriculum"
              onClick={() => nav('/learn')} />
      </div>

      {/* Continue + quick actions */}
      <div className="mt-6 grid gap-3 sm:grid-cols-2">
        <div className="rounded-lg border border-line/60 bg-surface2 p-4 shadow-card">
          <div className="mb-2 text-xs font-medium uppercase tracking-wide text-txt-3">
            Continue
          </div>
          {resumeHunt ? (
            <button
              onClick={() => nav(`/hunt/${resumeHunt.id}`)}
              className="group flex w-full items-center gap-3 rounded-md border border-line/60
                         bg-surface p-3 text-left transition-all hover:border-line2
                         hover:shadow-raised"
            >
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md
                               bg-accent/10 text-accent"><Target size={17} /></span>
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm text-txt">{resumeHunt.title}</div>
                <div className="text-[11px] capitalize text-txt-3">
                  {resumeHunt.campaign_slug} · {resumeHunt.phase} phase
                </div>
              </div>
              <ArrowRight size={15} className="text-txt-3 group-hover:text-accent" />
            </button>
          ) : (
            <div className="rounded-md border border-dashed border-line bg-surface p-3
                            text-xs text-txt-3">
              No hunt in progress. Build a campaign and start one.
            </div>
          )}
        </div>

        <div className="rounded-lg border border-line/60 bg-surface2 p-4 shadow-card">
          <div className="mb-2 text-xs font-medium uppercase tracking-wide text-txt-3">
            Jump in
          </div>
          <div className="grid grid-cols-2 gap-2">
            <Action icon={Crosshair} label="Hunt something" onClick={() => nav('/scenarios')} primary />
            <Action icon={Terminal} label="Query Lab" onClick={() => nav('/hunt')} />
            <Action icon={GraduationCap} label="Learn KQL" onClick={() => nav('/learn')} />
            <Action icon={Boxes} label="Techniques" onClick={() => nav('/techniques')} />
          </div>
        </div>
      </div>

      {/* Recent hunts */}
      {board && board.hunts.length > 0 && (
        <div className="mt-6">
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-h2 text-txt">Recent hunts</h2>
            <button onClick={() => nav('/scoreboard')}
                    className="text-xs text-txt-3 hover:text-txt">view all →</button>
          </div>
          <div className="space-y-1.5">
            {board.hunts.slice(0, 4).map((h) => (
              <button
                key={h.hunt_id}
                onClick={() => nav(`/hunt/${h.hunt_id}`)}
                className="flex w-full items-center gap-3 rounded-lg border border-line/60
                           bg-surface2 px-4 py-2.5 text-left shadow-card transition-all
                           duration-200 hover:-translate-y-0.5 hover:border-line2 hover:shadow-raised"
              >
                <span className={`w-6 text-lg font-bold tabular-nums ${GRADE_CLASS[h.grade]}`}>
                  {h.grade}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm text-txt">{h.title}</div>
                  <div className="text-[11px] text-txt-3">
                    {h.campaign_slug} · {h.phase}{h.outcome ? ` · ${h.outcome}` : ''}
                  </div>
                </div>
                <span className="text-xs tabular-nums text-txt-2">{h.overall}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* ATT&CK coverage mini-map */}
      {catalogue && (
        <MiniCoverage
          techniques={catalogue.techniques}
          identified={identified}
          detected={detected}
          onClick={() => nav('/scoreboard')}
        />
      )}
    </div>
  )
}

function Stat({
  icon: Icon, label, value, sub, onClick,
}: {
  icon: typeof Trophy; label: string; value: string | number; sub: string; onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className="rounded-lg border border-line/60 bg-surface2 px-4 py-3 text-left shadow-card
                 transition-all duration-200 hover:-translate-y-0.5 hover:border-line2
                 hover:shadow-raised"
    >
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-txt-3">
        <Icon size={12} /> {label}
      </div>
      <div className="mt-1 text-2xl font-semibold tabular-nums text-txt">{value}</div>
      <div className="text-[10px] text-txt-3">{sub}</div>
    </button>
  )
}

function Action({
  icon: Icon, label, onClick, primary,
}: { icon: typeof Trophy; label: string; onClick: () => void; primary?: boolean }) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 rounded-md px-3 py-2 text-xs font-medium transition-all ${
        primary
          ? 'bg-accent text-black hover:bg-accent-light hover:shadow-glow active:scale-[0.98]'
          : 'bg-surface3 text-txt hover:bg-line2'
      }`}
    >
      <Icon size={14} /> {label}
    </button>
  )
}

function MiniCoverage({
  techniques, identified, detected, onClick,
}: {
  techniques: Technique[]; identified: Set<string>; detected: Set<string>; onClick: () => void
}) {
  const playable = techniques.filter((t) => t.has_emitter)
  return (
    <button
      onClick={onClick}
      className="mt-6 w-full rounded-lg border border-line/60 bg-surface2 p-4 text-left shadow-card
                 transition-all hover:border-line2"
    >
      <div className="mb-2 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FlaskConical size={14} className="text-accent-light" />
          <span className="text-sm font-medium text-txt">ATT&amp;CK coverage</span>
        </div>
        <span className="text-xs text-txt-3">
          {identified.size}/{playable.length} identified
        </span>
      </div>
      <div className="flex flex-wrap gap-1">
        {playable.map((t) => {
          const det = detected.has(t.id)
          const found = identified.has(t.id)
          return (
            <span
              key={t.id}
              title={`${t.id} ${t.name}`}
              className={`h-2.5 w-2.5 rounded-sm ${
                det ? 'bg-accent ring-1 ring-accent-light'
                  : found ? 'bg-good/70' : 'bg-surface3'
              }`}
            />
          )
        })}
      </div>
    </button>
  )
}
