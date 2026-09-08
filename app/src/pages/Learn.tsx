// The Learn page: a guided KQL curriculum aligned to Microsoft SC-200. Modules
// group lessons by SC-200 objective; each lesson pairs an explanation with a
// runnable query and an exercise, practised against a real campaign in the
// range. "Open in Query Lab" hands the query off to the editor; "Reveal
// solution" shows a worked answer; a checkbox tracks progress.

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useToast } from '../components/toast'
import { useNavigate } from 'react-router-dom'
import {
  GraduationCap, ChevronDown, Play, Eye, EyeOff, Check, Copy, BookOpen,
  Target, CircleCheck, Circle,
} from 'lucide-react'
import { learnApi, type Lesson, type CurriculumModule } from '../lib/api'
import { Skeleton } from '../components/ui'

export function Learn() {
  const { data } = useQuery({ queryKey: ['curriculum'], queryFn: learnApi.curriculum })

  if (!data) {
    return (
      <div className="mx-auto max-w-3xl px-6 py-8">
        <Skeleton className="h-7 w-40" />
        <div className="mt-6 space-y-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-16" />)}
        </div>
      </div>
    )
  }

  const pct = data.total_lessons ? Math.round((data.completed / data.total_lessons) * 100) : 0

  return (
    <div className="mx-auto flex h-full max-w-3xl flex-col overflow-auto px-6 py-8">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-h1 text-txt">
            <GraduationCap size={20} className="text-accent" /> Learn KQL
          </h1>
          <p className="mt-1 text-sm text-txt-2">
            A guided curriculum aligned to Microsoft SC-200. Every lesson runs against real data
            in the range — read the concept, run the query, then do the exercise yourself.
          </p>
        </div>
        <div className="shrink-0 text-right">
          <div className="text-2xl font-semibold text-accent-light">{pct}%</div>
          <div className="text-[11px] text-txt-3">{data.completed}/{data.total_lessons} lessons</div>
        </div>
      </div>

      <div className="mt-6 space-y-4">
        {data.modules.map((m, i) => <ModuleCard key={m.id} module={m} index={i + 1} />)}
      </div>
    </div>
  )
}

function ModuleCard({ module: m, index }: { module: CurriculumModule; index: number }) {
  const done = m.lessons.filter((l) => l.completed).length
  const [open, setOpen] = useState(index === 1)

  return (
    <div className="rounded-lg border border-line/60 bg-surface2 shadow-card">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-3 px-4 py-3 text-left"
      >
        <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full
                         bg-surface3 text-xs font-medium text-txt-2">{index}</span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium text-txt">{m.title}</div>
          <div className="truncate text-[11px] text-txt-3">SC-200 · {m.sc200_area}</div>
        </div>
        <span className="text-xs text-txt-3">{done}/{m.lessons.length}</span>
        <ChevronDown size={16} className={`text-txt-3 transition ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="border-t border-line px-4 py-3">
          <p className="mb-3 text-xs text-txt-2">{m.summary}</p>
          <div className="space-y-2">
            {m.lessons.map((l) => <LessonRow key={l.id} lesson={l} />)}
          </div>
        </div>
      )}
    </div>
  )
}

function LessonRow({ lesson: l }: { lesson: Lesson }) {
  const qc = useQueryClient()
  const nav = useNavigate()
  const [open, setOpen] = useState(false)
  const [showSolution, setShowSolution] = useState(false)
  const [copied, setCopied] = useState('')

  const { toast } = useToast()
  const toggle = useMutation({
    mutationFn: () => learnApi.setProgress(l.id, !l.completed),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['curriculum'] })
      if (!l.completed) {
        toast({ kind: 'success', title: 'Lesson complete', description: l.title })
      }
    },
  })

  function openInLab(query: string) {
    sessionStorage.setItem(
      'hr.lessonQuery', JSON.stringify({ csl: query, campaignSlug: l.campaign }))
    nav('/hunt')
  }

  function copy(text: string, which: string) {
    navigator.clipboard.writeText(text)
    setCopied(which)
    setTimeout(() => setCopied(''), 1500)
  }

  return (
    <div className="rounded-md border border-line bg-surface transition-colors duration-200
                    hover:border-line2">
      <div className="flex items-center gap-2 px-3 py-2">
        <button
          onClick={(e) => { e.stopPropagation(); toggle.mutate() }}
          title={l.completed ? 'Mark not done' : 'Mark done'}
          className={l.completed ? 'text-good' : 'text-txt-3 hover:text-accent'}
        >
          {l.completed ? <CircleCheck size={16} /> : <Circle size={16} />}
        </button>
        <button onClick={() => setOpen((o) => !o)} className="flex flex-1 items-center gap-2 text-left">
          <span className="text-sm text-txt">{l.title}</span>
          <ChevronDown size={14} className={`ml-auto text-txt-3 transition ${open ? 'rotate-180' : ''}`} />
        </button>
      </div>

      {open && (
        <div className="border-t border-line px-3 py-3 text-xs">
          <div className="mb-2 flex items-center gap-1.5 text-[11px] text-accent-light">
            <Target size={12} /> {l.objective}
          </div>
          <p className="mb-3 leading-relaxed text-txt-2">{renderConcept(l.concept)}</p>

          {/* Starter query */}
          <div className="mb-1 flex items-center gap-2">
            <BookOpen size={12} className="text-txt-3" />
            <span className="text-[11px] font-medium text-txt-2">Run this and read it</span>
          </div>
          <QueryBlock
            query={l.starter}
            onCopy={() => copy(l.starter, 'starter')}
            copied={copied === 'starter'}
            onOpen={() => openInLab(l.starter)}
          />

          {/* Task */}
          <div className="mt-3 rounded border border-accent/20 bg-accent/5 px-3 py-2">
            <div className="mb-0.5 flex items-center gap-1.5 text-[11px] font-medium text-accent-light">
              <Play size={11} /> Your turn
            </div>
            <p className="text-txt-2">{l.task}</p>
          </div>

          {/* Solution */}
          <button
            onClick={() => setShowSolution((s) => !s)}
            className="mt-3 flex items-center gap-1.5 text-[11px] text-txt-3 hover:text-txt"
          >
            {showSolution ? <EyeOff size={12} /> : <Eye size={12} />}
            {showSolution ? 'Hide solution' : 'Reveal solution'}
          </button>
          {showSolution && (
            <div className="mt-2">
              <QueryBlock
                query={l.solution}
                onCopy={() => copy(l.solution, 'solution')}
                copied={copied === 'solution'}
                onOpen={() => openInLab(l.solution)}
              />
            </div>
          )}

          {l.campaign && (
            <div className="mt-3 text-[10px] text-txt-3">
              Best practised on the <span className="text-txt-2">{l.campaign}</span> campaign —
              build it from the Scenarios library if you haven't.
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function QueryBlock({
  query, onCopy, copied, onOpen,
}: { query: string; onCopy: () => void; copied: boolean; onOpen: () => void }) {
  return (
    <div className="relative rounded border border-line bg-surface2">
      <pre className="overflow-x-auto p-2.5 pr-16 font-mono text-[11px] leading-relaxed text-txt-2">
        {query}
      </pre>
      <div className="absolute right-1.5 top-1.5 flex gap-1">
        <button
          onClick={onCopy}
          title="Copy"
          className="rounded p-1 text-txt-3 hover:bg-surface3 hover:text-txt"
        >
          {copied ? <Check size={12} className="text-good" /> : <Copy size={12} />}
        </button>
        <button
          onClick={onOpen}
          title="Open in Query Lab"
          className="rounded p-1 text-txt-3 hover:bg-surface3 hover:text-accent"
        >
          <Play size={12} />
        </button>
      </div>
    </div>
  )
}

// Render `backtick` spans in the concept text as inline code, everything else
// as plain text. Keeps the lessons readable without a full markdown dependency.
function renderConcept(text: string) {
  const parts = text.split(/(`[^`]+`)/g)
  return parts.map((p, i) =>
    p.startsWith('`') && p.endsWith('`') ? (
      <code key={i} className="rounded bg-surface3 px-1 py-0.5 font-mono text-[11px] text-accent-light">
        {p.slice(1, -1)}
      </code>
    ) : (
      <span key={i}>{p}</span>
    ),
  )
}
