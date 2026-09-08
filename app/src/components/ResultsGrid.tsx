// Virtualized results grid for query output. Large result sets are the norm in

// a hunt, so rows are windowed. A dynamic cell can be big JSON, so cells are
// single-line with a hover title and a click-to-pin affordance for evidence.

import { type CSSProperties, useEffect, useMemo, useRef, useState } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { AlertCircle, Flag, Clock, ChevronUp } from 'lucide-react'
import type { QueryResult } from '../lib/api'

interface Props {
  result: QueryResult | null
  error: string | null
  // Evidence pinning (used by the hunt workspace in later phases; harmless here).
  onPin?: (row: Record<string, unknown>) => void
  pinnedKeys?: Set<string>
}

function fmt(v: unknown): string {
  if (v === null || v === undefined) return ''
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

// The single source of column width, used by BOTH the header cell and every
// body cell. Because it is one constant applied identically, the columns can't
// drift apart — which was the alignment bug.
const CELL_STYLE: CSSProperties = {
  flex: '1 1 0',
  minWidth: 130,
  maxWidth: 360,
  overflow: 'hidden',
}

export function ResultsGrid({ result, error, onPin, pinnedKeys }: Props) {
  const parentRef = useRef<HTMLDivElement>(null)
  const [sortCol, setSortCol] = useState<number | null>(null)
  const [sortDesc, setSortDesc] = useState(false)
  // Per-column manual widths (by column index). A column with an explicit width
  // is fixed and can be dragged wider to read a long value; columns without one
  // keep the flex default and share the remaining space.
  const [colWidths, setColWidths] = useState<Record<number, number>>({})

  const columnKey = (result?.ok ? result.columns : []).join('|')
  // A new result with different columns should start from clean widths, or a
  // width set for "column 3" of the old query would wrongly apply to a totally
  // different column 3 of the new one.
  useEffect(() => setColWidths({}), [columnKey])

  function cellStyle(ci: number): CSSProperties {
    const w = colWidths[ci]
    if (w != null) {
      return { width: w, minWidth: w, maxWidth: w, flex: 'none', overflow: 'hidden' }
    }
    return CELL_STYLE
  }

  function startResize(ci: number, e: React.MouseEvent) {
    e.preventDefault()
    e.stopPropagation()
    // Seed from the header cell's current rendered width, so the drag continues
    // smoothly from wherever the column happens to be.
    const headerCell = (e.currentTarget as HTMLElement).parentElement
    const startW = colWidths[ci] ?? headerCell?.getBoundingClientRect().width ?? 160
    const startX = e.clientX
    document.body.style.cursor = 'col-resize'
    const move = (ev: MouseEvent) => {
      const w = Math.max(60, Math.round(startW + (ev.clientX - startX)))
      setColWidths((prev) => ({ ...prev, [ci]: w }))
    }
    const up = () => {
      document.body.style.cursor = ''
      window.removeEventListener('mousemove', move)
      window.removeEventListener('mouseup', up)
    }
    window.addEventListener('mousemove', move)
    window.addEventListener('mouseup', up)
  }

  const rows = useMemo(() => {
    if (!result?.ok) return []
    if (sortCol === null) return result.rows
    const copy = [...result.rows]
    copy.sort((a, b) => {
      const x = a[sortCol]
      const y = b[sortCol]
      const nx = Number(x)
      const ny = Number(y)
      let cmp: number
      if (!Number.isNaN(nx) && !Number.isNaN(ny)) cmp = nx - ny
      else cmp = fmt(x).localeCompare(fmt(y))
      return sortDesc ? -cmp : cmp
    })
    return copy
  }, [result, sortCol, sortDesc])

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 30,
    overscan: 20,
  })

  if (error) {
    return (
      <div className="flex items-start gap-3 p-4 text-sm">
        <AlertCircle size={18} className="mt-0.5 shrink-0 text-mal" />
        <div>
          <div className="font-medium text-mal">Query failed</div>
          <pre className="mt-1 whitespace-pre-wrap font-mono text-xs text-txt-2">{error}</pre>
        </div>
      </div>
    )
  }

  if (!result) {
    return (
      <div className="flex h-full items-center justify-center text-sm text-txt-3">
        Run a query to see results.
      </div>
    )
  }

  if (!result.ok) {
    return (
      <div className="flex items-start gap-3 p-4 text-sm">
        <AlertCircle size={18} className="mt-0.5 shrink-0 text-mal" />
        <div className="min-w-0">
          <div className="font-medium text-mal">
            {result.error?.code ?? 'Query error'}
          </div>
          <pre className="mt-1 whitespace-pre-wrap break-words font-mono text-xs text-txt-2">
            {result.error?.message}
          </pre>
        </div>
      </div>
    )
  }

  const { columns, column_types } = result

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b border-line px-4 py-1.5 text-xs">
        <span className="inline-flex items-center gap-1 rounded-full bg-surface3 px-2 py-0.5">
          <span className="font-medium tabular-nums text-txt">{result.row_count.toLocaleString()}</span>
          <span className="text-txt-3">rows</span>
        </span>
        {(() => {
          // Green under 250ms, amber under 1s, rose beyond — a quick read on how
          // heavy the query was.
          const ms = result.elapsed_ms
          const tone = ms < 250 ? 'bg-good/10 text-good'
            : ms < 1000 ? 'bg-conf-medium/10 text-conf-medium' : 'bg-mal/10 text-mal'
          return (
            <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 tabular-nums ${tone}`}>
              <Clock size={11} />
              {ms.toFixed(0)} ms
            </span>
          )
        })()}
        {result.row_count === 0 && <span className="text-txt-3">no rows matched</span>}
      </div>

      {/* Header and rows are BOTH flex with identical per-cell sizing, so the
          columns line up. A <table> header sizes by content while the
          virtualized flex rows size by flex-basis — mixing the two is what
          made the headers drift out of alignment with the cells. `min-w-max`
          lets a wide result scroll horizontally as one unit, header included. */}
      <div ref={parentRef} className="flex-1 overflow-auto text-xs">
        <div className="min-w-max">
          {/* Header */}
          <div className="sticky top-0 z-10 flex border-b border-line bg-surface2">
            {onPin && <div className="w-8 shrink-0" />}
            {columns.map((col, ci) => (
              <div key={col} style={cellStyle(ci)} className="group relative flex">
                <button
                  onClick={() => {
                    if (sortCol === ci) setSortDesc((d) => !d)
                    else {
                      setSortCol(ci)
                      setSortDesc(false)
                    }
                  }}
                  title={`${col} (${column_types[ci]})`}
                  className="flex min-w-0 flex-1 cursor-pointer select-none items-baseline gap-1
                             truncate px-3 py-2 text-left font-medium text-txt hover:bg-surface3"
                >
                  <span className="truncate">{col}</span>
                  {/* Active sort: a solid accent chevron that flips for asc/desc.
                      Otherwise a faint one appears on hover to signal sortability. */}
                  <ChevronUp
                    size={12}
                    className={`shrink-0 transition-all duration-200 ${
                      sortCol === ci
                        ? `text-accent ${sortDesc ? 'rotate-180' : ''}`
                        : 'text-txt-3 opacity-0 group-hover:opacity-60'
                    }`}
                  />
                  <span className="truncate text-txt-3">{column_types[ci]}</span>
                </button>
                {/* Drag to resize; double-click to reset to auto width. */}
                <div
                  onMouseDown={(e) => startResize(ci, e)}
                  onDoubleClick={(e) => {
                    e.stopPropagation()
                    setColWidths((prev) => {
                      const next = { ...prev }
                      delete next[ci]
                      return next
                    })
                  }}
                  title="Drag to resize · double-click to reset"
                  className="absolute right-0 top-0 h-full w-1.5 cursor-col-resize
                             bg-transparent hover:bg-accent/50 group-hover:bg-line2"
                />
              </div>
            ))}
          </div>

          {/* Virtualized rows */}
          <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
            {virtualizer.getVirtualItems().map((vi) => {
              const row = rows[vi.index]
              const itemId = String(row[columns.indexOf('_ItemId')] ?? '')
              const isPinned = !!itemId && !!pinnedKeys?.has(itemId)
              return (
                <div
                  key={vi.key}
                  className={`absolute flex w-full border-b transition-colors ${
                    isPinned
                      ? 'border-accent/30 bg-accent/10 hover:bg-accent/15'
                      : 'border-line/50 hover:bg-surface2'
                  }`}
                  style={{ transform: `translateY(${vi.start}px)`, height: vi.size }}
                >
                  {/* An accent bar on the left edge marks a pinned row at a glance. */}
                  {isPinned && (
                    <div className="absolute left-0 top-0 h-full w-0.5 bg-accent" />
                  )}
                  {onPin && (
                    <div className="flex w-8 shrink-0 items-center justify-center">
                      {(() => {
                        return (
                          <button
                            onClick={() =>
                              onPin(Object.fromEntries(columns.map((c, i) => [c, row[i]])))
                            }
                            title={isPinned ? 'Already flagged' : 'Flag as evidence'}
                            className={isPinned ? 'text-accent' : 'text-txt-3 hover:text-accent'}
                          >
                            <Flag size={12} className={isPinned ? 'fill-accent' : ''} />
                          </button>
                        )
                      })()}
                    </div>
                  )}
                  {row.map((cell, ci) => {
                    const s = fmt(cell)
                    return (
                      <div
                        key={ci}
                        title={s}
                        style={cellStyle(ci)}
                        className="truncate px-3 py-1.5 font-mono text-txt-2"
                      >
                        {s}
                      </div>
                    )
                  })}
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
