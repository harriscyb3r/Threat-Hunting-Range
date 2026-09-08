// The hunt debrief: the score, and the answer key. This is where you find out
// how you did — the objective grade against ground truth, plus what was actually
// planted so you can see what you caught, what fooled you, and what you missed.
//
// It's deliberately shown only on demand (a button in the Act phase), because
// revealing the answer key ends the blind hunt. Once you've seen it, you know
// the answers.

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Loader2, Target, ShieldAlert, Clock, Search, ListChecks, Check, X,
  TrendingUp, ChevronDown,
} from 'lucide-react'
import { huntApi, type AttackEvent } from '../lib/api'

// Stroke colour per grade — matched to the semantic palette (emerald/amber/rose).
const GRADE_STROKE: Record<string, string> = {
  A: '#10b981', B: '#34d399', C: '#fbbf24', D: '#f59e0b', F: '#f43f5e',
}

// The grade as a radial progress arc with the letter at its centre. The arc
// sweeps to `overall`% and draws in on reveal — the debrief's signature moment.
function GradeRing({ grade, overall }: { grade: string; overall: number }) {
  const R = 42
  const CIRC = 2 * Math.PI * R
  const pct = Math.max(0, Math.min(100, overall)) / 100
  const offset = CIRC * (1 - pct)
  const stroke = GRADE_STROKE[grade] ?? '#4d5b68'
  return (
    <div className="relative flex w-28 shrink-0 items-center justify-center">
      <svg viewBox="0 0 100 100" className="h-28 w-28 -rotate-90">
        <circle cx="50" cy="50" r={R} fill="none" stroke="#1e252c" strokeWidth="7" />
        <circle
          cx="50" cy="50" r={R} fill="none" stroke={stroke} strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={CIRC}
          strokeDashoffset={offset}
          className="ring-arc"
          style={{ ['--ring-circ' as string]: `${CIRC}` }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-3xl font-bold leading-none" style={{ color: stroke }}>{grade}</span>
        <span className="mt-0.5 text-xs tabular-nums text-txt-2">{overall}</span>
      </div>
    </div>
  )
}

export function HuntDebrief({ huntId }: { huntId: string }) {
  const { data: s, isLoading } = useQuery({
    queryKey: ['score', huntId],
    queryFn: () => huntApi.score(huntId),
  })

  if (isLoading || !s) {
    return (
      <div className="flex items-center justify-center py-8 text-txt-3">
        <Loader2 className="animate-spin" />
      </div>
    )
  }

  return (
    <div className="mt-4">
      {/* Grade + headline metrics */}
      <div className="flex items-stretch gap-4">
        <GradeRing grade={s.grade} overall={s.overall} />
        <div className="grid flex-1 grid-cols-2 gap-2 sm:grid-cols-4">
          <Metric icon={Target} label="Technique recall"
                  value={pct(s.technique_recall)}
                  sub={`${s.identified_techniques.length}/${s.planted_techniques.length} found`}
                  tone={s.technique_recall >= 1 ? 'good' : s.technique_recall > 0 ? 'warn' : 'bad'} />
          <Metric icon={ShieldAlert} label="Precision" value={pct(s.precision)}
                  sub={s.evidence_decoy + s.evidence_noise > 0
                    ? `${s.evidence_decoy + s.evidence_noise} false pin${s.evidence_decoy + s.evidence_noise === 1 ? '' : 's'}`
                    : 'no false pins'}
                  tone={s.precision >= 0.9 ? 'good' : s.precision >= 0.5 ? 'warn' : 'bad'} />
          <Metric icon={Clock} label="Time to detect"
                  value={s.time_to_detection_s != null ? dur(s.time_to_detection_s) : '—'}
                  sub="from hunt start" />
          <Metric icon={Search} label="Searches to find"
                  value={s.searches_to_first_tp != null ? String(s.searches_to_first_tp) : '—'}
                  sub={`${s.searches_total} total`} />
        </div>
      </div>

      {/* Fooled by */}
      {s.decoys_fooled_by.length > 0 && (
        <div className="mt-3 rounded-md border border-decoy/30 bg-decoy/5 p-3">
          <div className="flex items-center gap-2 text-xs font-medium text-decoy">
            <ShieldAlert size={13} /> You pinned {s.evidence_decoy + s.evidence_noise} benign
            look-alike{s.evidence_decoy + s.evidence_noise === 1 ? '' : 's'}
          </div>
          <div className="mt-1.5 space-y-1">
            {s.decoys_fooled_by.map((d) => (
              <div key={d.pattern} className="text-[11px] text-txt-2">
                <span className="font-mono text-decoy/90">{d.pattern}</span>
                {d.mimics && <span className="text-txt-3"> — a benign look-alike of {d.mimics}</span>}
                {d.count > 1 && <span className="text-txt-3"> (×{d.count})</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Answer key */}
      <div className="mt-4 rounded-lg border border-line bg-surface2 p-4 shadow-card">
        <div className="mb-2 flex items-center gap-2 text-sm font-medium">
          <ListChecks size={15} className="text-accent-light" />
          Answer key — what was planted
        </div>
        <div className="space-y-2">
          {s.answer_key.steps.map((step, i) => (
            <div key={i} className="flex items-center gap-3 rounded-md border border-line
                                    bg-surface px-3 py-2">
              {step.identified ? (
                <span className="flex h-5 w-5 items-center justify-center rounded-full
                                 bg-good/20 text-good"><Check size={13} /></span>
              ) : (
                <span className="flex h-5 w-5 items-center justify-center rounded-full
                                 bg-mal/20 text-mal"><X size={13} /></span>
              )}
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-txt-2">{step.technique_id}</span>
                  <span className="text-sm text-txt">{step.technique_name}</span>
                </div>
                <div className="text-[11px] text-txt-3">
                  variant <span className="text-txt-2">{step.variant_label || step.variant}</span>
                  {' · '}{step.events} events{step.host ? ` · on ${step.host}` : ''}
                </div>
              </div>
              <span className={`text-xs ${step.identified ? 'text-good' : 'text-mal'}`}>
                {step.identified ? 'found' : 'missed'}
              </span>
            </div>
          ))}
        </div>
        {s.attack_events_total > 0 && (
          <div className="mt-2 flex items-center gap-1.5 text-[11px] text-txt-3">
            <TrendingUp size={11} />
            You surfaced {s.attack_events_found} of {s.attack_events_total} planted attack events
            in evidence ({pct(s.event_recall)}).
          </div>
        )}

        <AttackEventList huntId={huntId} />
      </div>

      {/* Rigor checklist */}
      <div className="mt-3 rounded-lg border border-line bg-surface2 p-4 shadow-card">
        <div className="mb-2 text-sm font-medium">Method (rigor {pct(s.rigor_score)})</div>
        <div className="grid grid-cols-2 gap-x-4 gap-y-1">
          {Object.entries(s.rigor_checks).map(([k, v]) => (
            <div key={k} className="flex items-center gap-2 text-xs">
              {v ? <Check size={13} className="text-good" /> : <X size={13} className="text-txt-3" />}
              <span className={v ? 'text-txt-2' : 'text-txt-3'}>{k}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// The actual planted attack log rows, each marked found or missed. This is the
// concrete "here is exactly what you should have caught" — the specific events,
// on which host, at what time, that make a 0/10 recall actionable.
function AttackEventList({ huntId }: { huntId: string }) {
  const [open, setOpen] = useState(false)
  const { data, isLoading } = useQuery({
    queryKey: ['attack-events', huntId],
    queryFn: () => huntApi.attackEvents(huntId),
    enabled: open,
  })

  return (
    <div className="mt-3 border-t border-line pt-3">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 text-left text-xs font-medium text-accent-light"
      >
        <ChevronDown size={13} className={`transition ${open ? 'rotate-180' : ''}`} />
        Show the actual attack events — what you caught and what you missed
      </button>

      {open && (
        <div className="mt-2">
          {isLoading && (
            <div className="flex items-center gap-2 py-3 text-xs text-txt-3">
              <Loader2 size={13} className="animate-spin" /> Pulling the planted events…
            </div>
          )}
          {data && (
            <>
              <div className="mb-2 flex gap-4 text-[11px]">
                <span className="text-good">{data.found} caught</span>
                <span className="text-mal">{data.missed} missed</span>
                <span className="text-txt-3">{data.total} total</span>
              </div>
              {/* Horizontally scrollable: the detail column (command lines,
                  URLs) is long, so let the row extend and scroll across rather
                  than truncating what you missed. The header lives inside the
                  same min-w-max block so it scrolls in lock-step with the rows. */}
              <div className="overflow-x-auto rounded-md border border-line">
                <div className="min-w-max">
                  <EventHeader />
                  {data.events.map((e, i) => <EventRow key={i} e={e} />)}
                </div>
              </div>
              <p className="mt-2 text-[10px] text-txt-3">
                Each row is a real log event the attacker generated. A missed row is one you
                didn't pin as evidence — worth writing a query that would have surfaced it.
                Scroll across to read the full event.
              </p>
            </>
          )}
        </div>
      )}
    </div>
  )
}

// Shared column widths, applied identically to the header and every row so the
// two stay aligned as the block scrolls horizontally. `min-w` (not fixed `w`)
// with `shrink-0` lets a long value extend its cell — and the whole row — rather
// than clipping, which is the point: you can scroll across to read all of it.
const COL = {
  status: 'w-4 shrink-0',
  time: 'min-w-[8.5rem] shrink-0 whitespace-nowrap',
  table: 'min-w-[10rem] shrink-0 whitespace-nowrap',
  account: 'min-w-[11rem] shrink-0 whitespace-nowrap',
  detail: 'shrink-0 whitespace-nowrap pr-2',
}

function EventHeader() {
  return (
    <div className="flex items-center gap-2 border-b border-line bg-surface3 px-2 py-1.5
                    text-[10px] font-medium uppercase tracking-wide text-txt-3">
      <span className={COL.status} />
      <span className={COL.time}>Time</span>
      <span className={COL.table}>Table</span>
      <span className={COL.account}>Account</span>
      <span className={COL.detail}>Detail</span>
    </div>
  )
}

function EventRow({ e }: { e: AttackEvent }) {
  return (
    <div className={`flex items-center gap-2 border-b border-line/50 px-2 py-1.5 text-[11px]
                     last:border-0 ${e.found ? 'bg-good/5' : 'bg-mal/5'}`}>
      <span className={`flex h-4 items-center justify-center rounded-full ${COL.status}
                        ${e.found ? 'bg-good/20 text-good' : 'bg-mal/20 text-mal'}`}>
        {e.found ? <Check size={10} /> : <X size={10} />}
      </span>
      <span className={`${COL.time} font-mono text-txt-3`} title={e.time}>
        {e.time.replace('T', ' ').slice(0, 19)}
      </span>
      <span className={`${COL.table} font-mono text-amber-300/80`} title={e.table}>
        {e.table}
      </span>
      <span className={`${COL.account} text-txt-2`} title={e.account}>
        {e.account}
      </span>
      <span className={`${COL.detail} font-mono text-txt-2`} title={e.detail}>
        {e.detail}
      </span>
    </div>
  )
}

function Metric({
  icon: Icon, label, value, sub, tone,
}: {
  icon: typeof Target; label: string; value: string; sub: string
  tone?: 'good' | 'warn' | 'bad'
}) {
  const color = tone === 'good' ? 'text-good' : tone === 'warn' ? 'text-conf-medium'
    : tone === 'bad' ? 'text-mal' : 'text-txt'
  return (
    <div className="rounded-md border border-line bg-surface2 px-3 py-2">
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-txt-3">
        <Icon size={11} /> {label}
      </div>
      <div className={`mt-0.5 text-lg font-semibold ${color}`}>{value}</div>
      <div className="text-[10px] text-txt-3">{sub}</div>
    </div>
  )
}

function pct(n: number): string {
  return `${Math.round(n * 100)}%`
}
function dur(sec: number): string {
  if (sec < 60) return `${Math.round(sec)}s`
  if (sec < 3600) return `${Math.round(sec / 60)}m`
  return `${(sec / 3600).toFixed(1)}h`
}
