// A lightweight KQL editor: a transparent textarea over a syntax-highlighted
// <pre>, plus schema-aware completion. The overlay-textarea technique keeps
// native editing (selection, undo, IME) while giving us full control of the
// colours — and avoids shipping a megabyte of Monaco to highlight a query.

import { useEffect, useMemo, useRef, useState } from 'react'
import { Play, Loader2 } from 'lucide-react'
import { TOKEN_CLASS, tokenizeLine, KQL_OPERATORS, KQL_FUNCTIONS } from '../lib/kql'

interface Props {
  value: string
  onChange: (v: string) => void
  onRun: () => void
  running: boolean
  tables: Set<string>
  columns: Set<string>
  // column name -> table names, for completion ranking
  columnTables: Map<string, string[]>
}

interface Suggestion {
  text: string
  kind: 'table' | 'column' | 'operator' | 'function'
  detail?: string
}

const OPERATOR_SUGGESTIONS = KQL_OPERATORS.map((t) => ({ text: t, kind: 'operator' as const }))
const FUNCTION_SUGGESTIONS = KQL_FUNCTIONS.map((t) => ({ text: t, kind: 'function' as const }))

export function KqlEditor({
  value, onChange, onRun, running, tables, columns, columnTables,
}: Props) {
  const taRef = useRef<HTMLTextAreaElement>(null)
  const preRef = useRef<HTMLPreElement>(null)
  const gutterRef = useRef<HTMLDivElement>(null)
  const measureRef = useRef<HTMLSpanElement>(null)
  const [suggestions, setSuggestions] = useState<Suggestion[]>([])
  const [selected, setSelected] = useState(0)
  const [caret, setCaret] = useState(0)
  // Pixel position + height of the completion popup, anchored to the caret so it
  // never covers the text you're editing (the old fixed top-left corner did).
  // It floats over whatever is below the editor, so its height is bounded by the
  // viewport, not by the short editor box.
  const [popup, setPopup] = useState({ top: 0, left: 0, maxHeight: 240 })

  // Character width of the monospace font, measured once. Monospace means every
  // glyph is this wide, so a caret column maps to an exact x with no per-char
  // measurement.
  const charW = useRef(7.8)
  useEffect(() => {
    if (measureRef.current) {
      charW.current = measureRef.current.getBoundingClientRect().width / 40 || 7.8
    }
  }, [])

  // Editor geometry — must match the textarea's Tailwind classes below
  // (pl-12 = 48 to clear the line-number gutter, py-3 = 12, leading-6 = 24px
  // line height, text-[13px]).
  const PAD_X = 48, PAD_Y = 12, LINE_H = 24, POPUP_W = 288

  function computePopupPos() {
    const ta = taRef.current
    if (!ta) return
    const before = value.slice(0, caret)
    const nl = before.lastIndexOf('\n')
    const col = caret - (nl + 1)
    const line = (before.match(/\n/g) || []).length
    // Caret position relative to the editor's top-left, accounting for scroll.
    const caretY = PAD_Y + line * LINE_H - ta.scrollTop
    const caretX = PAD_X + col * charW.current - ta.scrollLeft

    // The popup floats over content below the editor, so bound its height by the
    // real viewport space, not the ~160px editor. Flip above the caret line only
    // when there genuinely isn't room below in the window.
    const box = ta.getBoundingClientRect()
    const spaceBelow = window.innerHeight - (box.top + caretY + LINE_H) - 12
    const spaceAbove = box.top + caretY - 12
    const above = spaceBelow < 140 && spaceAbove > spaceBelow
    const maxHeight = Math.max(120, Math.min(240, above ? spaceAbove : spaceBelow))
    const top = above ? caretY - maxHeight : caretY + LINE_H
    const left = Math.max(4, Math.min(caretX, ta.clientWidth - POPUP_W - 8))
    setPopup({ top, left, maxHeight })
  }

  const tableList = useMemo(
    () => [...tables].sort().map((t) => ({ text: t, kind: 'table' as const })),
    [tables],
  )
  const columnList = useMemo(
    () =>
      [...columns].sort().map((c) => ({
        text: c,
        kind: 'column' as const,
        detail: columnTables.get(c)?.slice(0, 2).join(', '),
      })),
    [columns, columnTables],
  )

  // Keep the highlight scroll in sync with the textarea, and move the popup with
  // it so it stays glued to the caret line while scrolling.
  function syncScroll() {
    if (preRef.current && taRef.current) {
      preRef.current.scrollTop = taRef.current.scrollTop
      preRef.current.scrollLeft = taRef.current.scrollLeft
    }
    // The gutter scrolls vertically with the text but never horizontally.
    if (gutterRef.current && taRef.current) {
      gutterRef.current.style.transform = `translateY(${-taRef.current.scrollTop}px)`
    }
    if (suggestions.length) computePopupPos()
  }

  // The word immediately left of the caret, for completion.
  function currentWord(): { word: string; start: number } {
    const upto = value.slice(0, caret)
    const m = upto.match(/[A-Za-z_][A-Za-z0-9_]*$/)
    return m ? { word: m[0], start: caret - m[0].length } : { word: '', start: caret }
  }

  useEffect(() => {
    const { word } = currentWord()
    if (word.length < 2) {
      setSuggestions([])
      return
    }
    const lower = word.toLowerCase()
    // Rank: exact prefix on table/column first, then operators, then functions.
    const pool = [...tableList, ...columnList, ...OPERATOR_SUGGESTIONS, ...FUNCTION_SUGGESTIONS]
    const hits = pool
      .filter((s) => s.text.toLowerCase().startsWith(lower))
      .slice(0, 12)
    // Also allow fuzzy contains if few prefix hits.
    if (hits.length < 4) {
      for (const s of pool) {
        if (hits.length >= 12) break
        if (!hits.includes(s) && s.text.toLowerCase().includes(lower)) hits.push(s)
      }
    }
    setSuggestions(hits)
    setSelected(0)
    computePopupPos()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caret, value])

  function applySuggestion(s: Suggestion) {
    const { start } = currentWord()
    const next = value.slice(0, start) + s.text + value.slice(caret)
    onChange(next)
    setSuggestions([])
    // Restore caret just after the inserted text.
    requestAnimationFrame(() => {
      if (taRef.current) {
        const pos = start + s.text.length
        taRef.current.setSelectionRange(pos, pos)
        taRef.current.focus()
        setCaret(pos)
      }
    })
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    // Ctrl/Cmd+Enter runs, regardless of the suggestion popup.
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault()
      setSuggestions([])
      onRun()
      return
    }
    if (suggestions.length) {
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        setSelected((s) => (s + 1) % suggestions.length)
        return
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault()
        setSelected((s) => (s - 1 + suggestions.length) % suggestions.length)
        return
      }
      if (e.key === 'Enter' || e.key === 'Tab') {
        e.preventDefault()
        applySuggestion(suggestions[selected])
        return
      }
      if (e.key === 'Escape') {
        e.preventDefault()
        setSuggestions([])
        return
      }
    }
    // Tab inserts spaces rather than moving focus.
    if (e.key === 'Tab') {
      e.preventDefault()
      const ta = taRef.current!
      const s = ta.selectionStart
      const next = value.slice(0, s) + '  ' + value.slice(ta.selectionEnd)
      onChange(next)
      requestAnimationFrame(() => ta.setSelectionRange(s + 2, s + 2))
    }
  }

  const lines = value.split('\n')

  return (
    <div className="relative flex flex-col">
      <div className="relative flex-1">
        {/* Line-number gutter. A separate non-scrolling column whose inner block
            is translated to match the textarea's scrollTop — real editors have
            them, and it reads as a serious tool. */}
        <div className="pointer-events-none absolute left-0 top-0 z-[1] h-full w-10 overflow-hidden
                        border-r border-line/60 bg-surface/40">
          <div ref={gutterRef} className="py-3 pr-2 text-right font-mono text-[13px] leading-6
                                          text-txt-3/70">
            {lines.map((_, li) => <div key={li}>{li + 1}</div>)}
          </div>
        </div>
        <pre
          ref={preRef}
          aria-hidden
          className="pointer-events-none absolute inset-0 m-0 overflow-auto whitespace-pre
                     py-3 pl-12 pr-4 font-mono text-[13px] leading-6"
        >
          {lines.map((line, li) => {
            const toks = tokenizeLine(line, tables, columns)
            return (
              <div key={li}>
                {toks.length === 0 ? (
                  <span> </span>
                ) : (
                  toks.map((t, ti) => (
                    <span key={ti} className={TOKEN_CLASS[t.kind]}>
                      {t.text}
                    </span>
                  ))
                )}
              </div>
            )
          })}
        </pre>
        <textarea
          ref={taRef}
          value={value}
          spellCheck={false}
          autoCapitalize="off"
          autoComplete="off"
          onChange={(e) => {
            onChange(e.target.value)
            setCaret(e.target.selectionStart)
          }}
          onKeyDown={onKeyDown}
          onKeyUp={(e) => setCaret((e.target as HTMLTextAreaElement).selectionStart)}
          onClick={(e) => setCaret((e.target as HTMLTextAreaElement).selectionStart)}
          onScroll={syncScroll}
          className="relative z-[2] h-full w-full resize-none overflow-auto bg-transparent py-3
                     pl-12 pr-4 font-mono text-[13px] leading-6 text-transparent caret-accent-light
                     outline-none selection:bg-accent/25"
          style={{ minHeight: 160 }}
        />
        {/* Hidden probe: 40 monospace chars, to measure exact glyph width. */}
        <span
          ref={measureRef}
          aria-hidden
          className="pointer-events-none invisible absolute left-0 top-0 whitespace-pre
                     font-mono text-[13px]"
        >
          0000000000000000000000000000000000000000
        </span>
        {suggestions.length > 0 && (
          <div
            style={{ top: popup.top, left: popup.left, width: POPUP_W, maxHeight: popup.maxHeight }}
            className="absolute z-20 overflow-auto rounded-md border border-line2 bg-surface3
                       py-1 shadow-2xl"
          >
            {suggestions.map((s, i) => (
              <button
                key={`${s.kind}-${s.text}`}
                onMouseDown={(e) => {
                  e.preventDefault()
                  applySuggestion(s)
                }}
                className={`flex w-full items-center justify-between px-3 py-1 text-left text-xs
                            ${i === selected ? 'bg-accent/20' : 'hover:bg-surface2'}`}
              >
                <span className="flex items-center gap-2">
                  <KindDot kind={s.kind} />
                  <span className="font-mono text-txt">{s.text}</span>
                </span>
                <span className="text-txt-3">{s.detail ?? s.kind}</span>
              </button>
            ))}
          </div>
        )}
      </div>
      <div className="flex items-center justify-between border-t border-line px-4 py-2">
        <span className="text-xs text-txt-3">
          <kbd className="rounded bg-surface3 px-1.5 py-0.5 font-mono">Ctrl</kbd>
          <span className="mx-0.5">+</span>
          <kbd className="rounded bg-surface3 px-1.5 py-0.5 font-mono">Enter</kbd>
          <span className="ml-2">to run</span>
        </span>
        <button
          onClick={onRun}
          disabled={running}
          className="flex items-center gap-2 rounded-md bg-accent px-4 py-1.5 text-sm
                     font-medium text-black transition hover:bg-accent-light hover:shadow-glow active:scale-[0.98]
                     disabled:opacity-50"
        >
          {running ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />}
          {running ? 'Running' : 'Run'}
        </button>
      </div>
    </div>
  )
}

function KindDot({ kind }: { kind: Suggestion['kind'] }) {
  const color = {
    table: 'bg-amber-300',
    column: 'bg-emerald-300',
    operator: 'bg-accent-light',
    function: 'bg-violet-400',
  }[kind]
  return <span className={`h-2 w-2 rounded-full ${color}`} />
}
