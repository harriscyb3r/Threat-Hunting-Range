// The technique catalogue: every emitter, its variants, and — crucially — what
// each variant *defeats*. Doubles as study material and as the reference for
// why a hunt is hard. The "defeats" column is the point: it names the naive
// query each variant is built to break.

import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search, ExternalLink, ShieldOff, Zap } from 'lucide-react'
import { api, TACTIC_LABEL, type Technique } from '../lib/api'

export function Techniques() {
  const { data } = useQuery({ queryKey: ['techniques'], queryFn: api.techniques })
  const [filter, setFilter] = useState('')
  const [onlyImpl, setOnlyImpl] = useState(true)

  const grouped = useMemo(() => {
    if (!data) return []
    const f = filter.toLowerCase()
    const filtered = data.techniques.filter((t) => {
      if (onlyImpl && !t.has_emitter) return false
      if (!f) return true
      return (
        t.id.toLowerCase().includes(f) ||
        t.name.toLowerCase().includes(f) ||
        t.summary.toLowerCase().includes(f) ||
        t.variants.some((v) => v.label.toLowerCase().includes(f))
      )
    })
    const byTactic = new Map<string, Technique[]>()
    for (const t of filtered) {
      const list = byTactic.get(t.tactic) ?? []
      list.push(t)
      byTactic.set(t.tactic, list)
    }
    return [...byTactic.entries()]
  }, [data, filter, onlyImpl])

  return (
    <div className="mx-auto flex h-full max-w-4xl flex-col overflow-auto px-6 py-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-h1 text-txt">Technique catalogue</h1>
          <p className="mt-1 text-sm text-txt-2">
            {data && (
              <>
                {data.implemented} of {data.count} ATT&CK techniques have working emitters, each
                with several variants.
              </>
            )}
          </p>
        </div>
      </div>

      <div className="mt-5 flex items-center gap-3">
        <div className="flex flex-1 items-center gap-2 rounded-lg border border-line bg-surface2
                        px-3 py-2 focus-within:border-accent">
          <Search size={15} className="text-txt-3" />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by technique, ID, or variant"
            className="w-full bg-transparent text-sm outline-none placeholder:text-txt-3"
          />
        </div>
        <label className="flex items-center gap-2 text-xs text-txt-2">
          <input
            type="checkbox"
            checked={onlyImpl}
            onChange={(e) => setOnlyImpl(e.target.checked)}
            className="accent-accent"
          />
          Only playable
        </label>
      </div>

      <div className="mt-6 space-y-6">
        {grouped.map(([tactic, techniques]) => (
          <div key={tactic}>
            <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-accent-light">
              {TACTIC_LABEL[tactic] ?? tactic}
            </h2>
            <div className="space-y-2">
              {techniques.map((t) => (
                <TechniqueCard key={t.id} t={t} />
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function TechniqueCard({ t }: { t: Technique }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="rounded-lg border border-line/60 bg-surface2 shadow-card transition-all duration-200 hover:border-line2 hover:shadow-raised">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-start gap-3 px-4 py-3 text-left"
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs text-txt-2">{t.id}</span>
            <span className="font-medium text-txt">{t.name}</span>
            {!t.has_emitter && (
              <span className="rounded bg-surface3 px-1.5 py-0.5 text-[10px] text-txt-3">
                no emitter
              </span>
            )}
            {t.has_emitter && (
              <span className="rounded bg-accent/10 px-1.5 py-0.5 text-[10px] text-accent-light">
                {t.variants.length} variants
              </span>
            )}
          </div>
          <div className="mt-0.5 text-xs text-txt-2">{t.summary}</div>
          <div className="mt-1.5 flex flex-wrap gap-1">
            {t.tables.map((tbl) => (
              <span
                key={tbl}
                className="rounded bg-surface px-1.5 py-0.5 font-mono text-[10px] text-amber-300/80"
              >
                {tbl}
              </span>
            ))}
          </div>
        </div>
        <a
          href={t.url}
          target="_blank"
          rel="noreferrer"
          onClick={(e) => e.stopPropagation()}
          className="mt-0.5 text-txt-3 hover:text-accent"
        >
          <ExternalLink size={13} />
        </a>
      </button>

      {open && t.variants.length > 0 && (
        <div className="border-t border-line px-4 py-3">
          <div className="space-y-2.5">
            {t.variants.map((v) => (
              <div key={v.key} className="text-xs">
                <div className="flex items-center gap-2">
                  <Zap size={12} className="text-accent-light" />
                  <span className="font-medium text-txt">{v.label}</span>
                </div>
                <div className="ml-5 mt-0.5 text-txt-2">{v.tells}</div>
                {v.defeats && (
                  <div className="ml-5 mt-1 flex items-start gap-1.5 text-mal/90">
                    <ShieldOff size={11} className="mt-0.5 shrink-0" />
                    <span>defeats: {v.defeats}</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
