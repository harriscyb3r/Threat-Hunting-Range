// The Query Lab: schema browser, KQL editor, results grid, query history, and a
// native<->ASIM toggle. This is the surface an analyst spends the most time on,
// so the whole page is one keyboard-driven loop: pick a campaign, write KQL,
// Ctrl+Enter, read results, pivot.

import { useEffect, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { History, Database, X, Layers, ChevronDown } from 'lucide-react'
import { api, type QueryResult } from '../lib/api'
import { useSchema } from '../lib/useSchema'
import { KqlEditor } from '../components/KqlEditor'
import { ResultsGrid } from '../components/ResultsGrid'
import { SchemaBrowser } from '../components/SchemaBrowser'

interface HistoryEntry {
  csl: string
  db: string
  rows: number
  ms: number
  ok: boolean
  at: number
}

const STARTER = `// Pick a campaign, then hunt. Ctrl+Enter to run.
SigninLogs
| where ResultType != "0"
| summarize Failures = count() by UserPrincipalName
| top 10 by Failures`

export function QueryLab() {
  const schema = useSchema()
  const { data: status } = useQuery({ queryKey: ['status'], queryFn: api.status })
  const campaigns = (status?.campaigns ?? []).filter((c) => c.status === 'ready')
  // Event totals per campaign db, shown in the dropdown. Refetched when the set
  // of ready campaigns changes (a new build finishing) so counts stay current.
  const readyKey = campaigns.map((c) => c.db_name).join(',')
  const { data: countData } = useQuery({
    queryKey: ['campaign-counts', readyKey],
    queryFn: api.campaignCounts,
    enabled: campaigns.length > 0,
  })
  const counts = countData?.counts ?? {}

  const [db, setDb] = useState('')
  const [csl, setCsl] = useState(STARTER)
  const [result, setResult] = useState<QueryResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [history, setHistory] = useState<HistoryEntry[]>([])
  const [showHistory, setShowHistory] = useState(false)

  // Default to the first ready campaign once it loads.
  useEffect(() => {
    if (!db && campaigns.length) setDb(campaigns[0].db_name)
  }, [campaigns, db])

  // A lesson can hand off a query to run here — it stashes {csl, campaignSlug}
  // in sessionStorage and navigates. Pick it up once, then clear it so a manual
  // refresh doesn't keep re-loading the lesson query.
  useEffect(() => {
    const raw = sessionStorage.getItem('hr.lessonQuery')
    if (!raw) return
    try {
      const { csl: q, campaignSlug } = JSON.parse(raw)
      if (q) setCsl(q)
      if (campaignSlug) {
        const match = campaigns.find((c) => c.slug === campaignSlug)
        if (match) setDb(match.db_name)
      }
    } catch { /* ignore */ }
    sessionStorage.removeItem('hr.lessonQuery')
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [campaigns])

  const run = useMutation({
    mutationFn: () => api.runQuery(db, csl),
    onSuccess: (r) => {
      setResult(r)
      setError(null)
      setHistory((h) =>
        [{ csl, db, rows: r.row_count, ms: r.elapsed_ms, ok: r.ok, at: Date.now() },
          ...h].slice(0, 50),
      )
    },
    onError: (e: Error) => {
      setError(e.message)
      setResult(null)
    },
  })

  function doRun() {
    if (!db) {
      setError('Select a campaign database first.')
      return
    }
    run.mutate()
  }

  // Insert text at the editor caret (from schema browser clicks). We keep a
  // simple append-with-space behaviour: good enough, and predictable.
  function insertToken(text: string) {
    setCsl((c) => {
      const needsSpace = c.length > 0 && !/\s$/.test(c)
      return c + (needsSpace ? ' ' : '') + text
    })
  }

  // Swap the leading table for its ASIM parser and back, so the same hunt can be
  // written both ways. A one-way map plus reverse lookup; only the first token
  // of the query is rewritten.
  const ASIM_MAP: Record<string, string> = {
    SigninLogs: '_Im_Authentication',
    DeviceProcessEvents: '_Im_ProcessCreate',
    DnsEvents: '_Im_Dns',
    DeviceNetworkEvents: '_Im_NetworkSession',
  }
  function toggleAsim(current: string): string {
    // Skip leading whitespace and // comment lines, then grab the first token.
    const m = current.match(/^((?:\s*\/\/[^\n]*\n)*\s*)([A-Za-z_][A-Za-z0-9_]*)/)
    if (!m) return current
    const [, lead, first] = m
    const rest = current.slice(m[0].length)
    const forward = ASIM_MAP[first]
    if (forward) return lead + forward + rest
    const reverse = Object.entries(ASIM_MAP).find(([, v]) => v === first)
    if (reverse) return lead + reverse[0] + rest
    return current
  }

  return (
    <div className="flex h-full">
      {/* Schema browser */}
      <aside className="w-64 shrink-0 border-r border-line bg-surface">
        <SchemaBrowser onInsert={insertToken} />
      </aside>

      {/* Main column */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Toolbar */}
        <div className="flex items-center gap-3 border-b border-line bg-surface px-4 py-2">
          <div className="relative flex items-center">
            <Database size={14} className="pointer-events-none absolute left-2.5 text-txt-3" />
            <select
              value={db}
              onChange={(e) => setDb(e.target.value)}
              className="appearance-none rounded-md border border-line bg-surface2 py-1 pl-8 pr-8
                         text-sm text-txt outline-none transition hover:border-line2
                         focus:border-accent"
            >
              <option value="">Select campaign…</option>
              {campaigns.map((c) => {
                const n = counts[c.db_name]
                const events = typeof n === 'number' ? ` (${n.toLocaleString()} events)` : ''
                // Only add "(twin)" when the name doesn't already say so — the
                // twin's display_name already ends in "(clean twin)".
                const twin = c.kind === 'clean_twin' && !/twin/i.test(c.display_name)
                  ? ' (twin)' : ''
                return (
                  <option key={c.db_name} value={c.db_name}>
                    {c.display_name}{twin}{events}
                  </option>
                )
              })}
            </select>
            <ChevronDown size={14} className="pointer-events-none absolute right-2 text-txt-3" />
          </div>
          {campaigns.length === 0 && (
            <span className="text-xs text-txt-3">
              No campaigns yet — build one in Scenarios.
            </span>
          )}
          <button
            onClick={() => setCsl(toggleAsim)}
            title="Rewrite the leading table to/from its ASIM parser"
            className="ml-auto flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs text-txt-2
                       transition hover:bg-surface2"
          >
            <Layers size={13} />
            native &harr; ASIM
          </button>
          <button
            onClick={() => setShowHistory((s) => !s)}
            className={`flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs transition ${
              showHistory ? 'bg-surface3 text-txt' : 'text-txt-2 hover:bg-surface2'
            }`}
          >
            <History size={13} />
            History
          </button>
        </div>

        {/* Editor */}
        <div className="border-b border-line bg-surface2">
          <KqlEditor
            value={csl}
            onChange={setCsl}
            onRun={doRun}
            running={run.isPending}
            tables={schema.tables}
            columns={schema.columns}
            columnTables={schema.columnTables}
          />
        </div>

        {/* Results */}
        <div className="min-h-0 flex-1 bg-surface">
          <ResultsGrid result={result} error={error} onPin={() => {}} />
        </div>
      </div>

      {/* History drawer */}
      {showHistory && (
        <aside className="flex w-80 shrink-0 flex-col border-l border-line bg-surface">
          <div className="flex items-center justify-between border-b border-line px-3 py-2">
            <span className="text-sm font-medium">Query history</span>
            <button onClick={() => setShowHistory(false)} className="text-txt-3 hover:text-txt">
              <X size={15} />
            </button>
          </div>
          <div className="flex-1 overflow-auto">
            {history.length === 0 && (
              <div className="p-4 text-xs text-txt-3">No queries yet this session.</div>
            )}
            {history.map((h, i) => (
              <button
                key={i}
                onClick={() => {
                  setCsl(h.csl)
                  setDb(h.db)
                }}
                className="block w-full border-b border-line/50 px-3 py-2 text-left
                           hover:bg-surface2"
              >
                <pre className="truncate font-mono text-[11px] text-txt-2">
                  {h.csl.replace(/\s+/g, ' ').trim()}
                </pre>
                <div className="mt-0.5 flex items-center gap-2 text-[10px] text-txt-3">
                  <span className={h.ok ? 'text-good' : 'text-mal'}>
                    {h.ok ? `${h.rows} rows` : 'error'}
                  </span>
                  <span>{h.ms.toFixed(0)} ms</span>
                </div>
              </button>
            ))}
          </div>
        </aside>
      )}
    </div>
  )
}
