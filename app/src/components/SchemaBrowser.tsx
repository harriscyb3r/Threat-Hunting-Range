// Schema browser: tables grouped by family, expandable to columns, with a
// filter and click-to-insert. Doubles as reference (the docs link) and as the
// completion source of truth for the editor.

import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ChevronRight, ExternalLink, Search, Layers } from 'lucide-react'

interface Column {
  name: string
  type: string
}
interface Table {
  name: string
  family: string
  description: string
  docs: string
  columns: Column[]
}
interface SchemaData {
  tables: Table[]
  asim: { name: string; schema: string; kind: string }[]
}

const FAMILY_LABEL: Record<string, string> = {
  entra: 'Entra ID / M365',
  defender: 'Defender XDR',
  windows: 'Windows',
  network: 'Network',
}

const TYPE_COLOR: Record<string, string> = {
  string: 'text-txt-3',
  datetime: 'text-sky-400/70',
  int: 'text-rose-300/70',
  long: 'text-rose-300/70',
  real: 'text-rose-300/70',
  bool: 'text-violet-400/70',
  dynamic: 'text-amber-300/70',
}

export function SchemaBrowser({ onInsert }: { onInsert: (text: string) => void }) {
  const { data } = useQuery({
    queryKey: ['schema'],
    queryFn: async () => {
      const res = await fetch('/api/range/schema')
      return res.json() as Promise<SchemaData>
    },
    staleTime: Infinity,
  })
  const [filter, setFilter] = useState('')
  const [open, setOpen] = useState<Set<string>>(new Set())

  const grouped = useMemo(() => {
    if (!data) return {}
    const f = filter.toLowerCase()
    const g: Record<string, Table[]> = {}
    for (const t of data.tables) {
      const matchTable = !f || t.name.toLowerCase().includes(f)
      const matchCol = f && t.columns.some((c) => c.name.toLowerCase().includes(f))
      if (matchTable || matchCol) {
        ;(g[t.family] ??= []).push(t)
      }
    }
    return g
  }, [data, filter])

  function toggle(name: string) {
    setOpen((o) => {
      const n = new Set(o)
      n.has(name) ? n.delete(name) : n.add(name)
      return n
    })
  }

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line p-2">
        <div className="flex items-center gap-2 rounded-md bg-surface px-2 py-1.5">
          <Search size={13} className="text-txt-3" />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter tables and columns"
            className="w-full bg-transparent text-xs text-txt outline-none placeholder:text-txt-3"
          />
        </div>
      </div>

      <div className="flex-1 overflow-auto p-1">
        {data?.asim && (
          <div className="mb-2">
            <div className="px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-accent-light">
              ASIM parsers
            </div>
            {data.asim.map((p) => (
              <button
                key={p.name}
                onClick={() => onInsert(p.name)}
                className="flex w-full items-center gap-2 rounded px-2 py-1 text-left text-xs
                           hover:bg-surface2"
                title={`ASIM ${p.schema} — normalized view`}
              >
                <Layers size={12} className="text-accent-light" />
                <span className="font-mono text-accent-light">{p.name}</span>
                <span className="ml-auto text-txt-3">{p.schema}</span>
              </button>
            ))}
          </div>
        )}

        {Object.entries(grouped).map(([family, tables]) => (
          <div key={family} className="mb-2">
            <div className="px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-txt-3">
              {FAMILY_LABEL[family] ?? family}
            </div>
            {tables.map((t) => (
              <div key={t.name}>
                <div className="group flex items-center">
                  <button
                    onClick={() => toggle(t.name)}
                    className="flex flex-1 items-center gap-1 rounded px-2 py-1 text-left text-xs
                               hover:bg-surface2"
                  >
                    <ChevronRight
                      size={12}
                      className={`shrink-0 text-txt-3 transition ${
                        open.has(t.name) ? 'rotate-90' : ''
                      }`}
                    />
                    <span
                      role="button"
                      tabIndex={0}
                      onClick={(e) => {
                        e.stopPropagation()
                        onInsert(t.name)
                      }}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.stopPropagation()
                          e.preventDefault()
                          onInsert(t.name)
                        }
                      }}
                      className="cursor-pointer font-mono text-amber-300 hover:underline"
                    >
                      {t.name}
                    </span>
                    <span className="ml-1 text-txt-3">{t.columns.length}</span>
                  </button>
                  <a
                    href={t.docs}
                    target="_blank"
                    rel="noreferrer"
                    className="mr-1 hidden text-txt-3 hover:text-accent group-hover:block"
                    title="Microsoft docs"
                  >
                    <ExternalLink size={11} />
                  </a>
                </div>
                {open.has(t.name) && (
                  <div className="ml-5 border-l border-line pl-2">
                    {t.description && (
                      <div className="px-2 py-1 text-[11px] italic text-txt-3">
                        {t.description}
                      </div>
                    )}
                    {t.columns.map((c) => (
                      <button
                        key={c.name}
                        onClick={() => onInsert(c.name)}
                        className="flex w-full items-center justify-between rounded px-2 py-0.5
                                   text-left text-[11px] hover:bg-surface2"
                      >
                        <span className="font-mono text-emerald-300/90">{c.name}</span>
                        <span className={`font-mono ${TYPE_COLOR[c.type] ?? 'text-txt-3'}`}>
                          {c.type}
                        </span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  )
}
