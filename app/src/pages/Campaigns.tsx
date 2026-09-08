// Campaign list: what's built, its status, and the Study-mode answer key. A
// campaign is blind by default — you're told the hypothesis and nothing else.
// Study mode reveals the planted steps and ground-truth counts, for when you're
// learning a technique rather than testing yourself.

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  Loader2, Trash2, Terminal, Eye, EyeOff, Target, Shield,
} from 'lucide-react'
import { api, huntApi, type AnswerKey, type Hunt } from '../lib/api'
import { EmptyState } from '../components/ui'

// Filled-dot + subtle-tint badge per status. A coloured dot reads faster than
// coloured text alone, and the tinted pill gives it presence.
const STATUS_STYLE: Record<string, { dot: string; pill: string }> = {
  ready: { dot: 'bg-good', pill: 'bg-good/10 text-good' },
  building: { dot: 'bg-conf-medium', pill: 'bg-conf-medium/10 text-conf-medium' },
  failed: { dot: 'bg-mal', pill: 'bg-mal/10 text-mal' },
  empty: { dot: 'bg-txt-3', pill: 'bg-surface3 text-txt-3' },
  missing: { dot: 'bg-mal', pill: 'bg-mal/10 text-mal' },
}

export function Campaigns() {
  const qc = useQueryClient()
  const nav = useNavigate()
  const { data: status } = useQuery({
    queryKey: ['status'],
    queryFn: api.status,
    refetchInterval: (q) => {
      // Poll fast while anything is building.
      const building = q.state.data?.campaigns.some((c) => c.status === 'building')
      return building ? 1500 : 8000
    },
  })

  const del = useMutation({
    mutationFn: (slug: string) => api.deleteCampaign(slug),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['status'] }),
  })

  // Only show the primary campaigns; twins are attached to their parent.
  const campaigns = (status?.campaigns ?? []).filter((c) => c.kind === 'campaign')
  const twinOf = new Set(
    (status?.campaigns ?? []).filter((c) => c.kind === 'clean_twin').map((c) => c.twin_of),
  )

  if (campaigns.length === 0) {
    return (
      <EmptyState
        icon={<Target size={26} />}
        title="No campaigns yet"
        hint="Build a hunt from a technique, a threat report, or the library."
        action={
          <button
            onClick={() => nav('/scenarios')}
            className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-black
                       hover:bg-accent-light hover:shadow-glow active:scale-[0.98]"
          >
            Build your first hunt
          </button>
        }
      />
    )
  }

  return (
    <div className="mx-auto flex h-full max-w-3xl flex-col overflow-auto px-6 py-8">
      <h1 className="text-h1 text-txt">Campaigns</h1>
      <div className="mt-5 space-y-3">
        {campaigns.map((c) => (
          <CampaignCard
            key={c.slug}
            slug={c.slug}
            name={c.display_name}
            status={c.status}
            dbName={c.db_name}
            hasTwin={twinOf.has(c.slug)}
            onHunt={() => nav('/hunt')}
            onDelete={() => del.mutate(c.slug)}
            deleting={del.isPending && del.variables === c.slug}
          />
        ))}
      </div>
    </div>
  )
}

function CampaignCard({
  slug, name, status, dbName, hasTwin, onHunt, onDelete, deleting,
}: {
  slug: string; name: string; status: string; dbName: string
  hasTwin: boolean; onHunt: () => void; onDelete: () => void; deleting: boolean
}) {
  const [study, setStudy] = useState(false)
  const { data: key } = useQuery({
    queryKey: ['answer-key', slug],
    queryFn: () => api.answerKey(slug),
    enabled: study && status === 'ready',
  })

  const st = STATUS_STYLE[status] ?? STATUS_STYLE.empty
  return (
    <div className="rounded-lg border border-line/70 bg-surface2 p-4 shadow-card transition-all
                    duration-200 hover:border-line2 hover:shadow-raised">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-medium text-txt">{name}</span>
            <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px]
                              capitalize ${st.pill}`}>
              {status === 'building'
                ? <Loader2 size={10} className="animate-spin" />
                : <span className={`h-1.5 w-1.5 rounded-full ${st.dot}`} />}
              {status}
            </span>
            {hasTwin && (
              <span className="flex items-center gap-1 rounded bg-surface3 px-1.5 py-0.5
                               text-[10px] text-txt-3">
                <Shield size={9} /> twin
              </span>
            )}
          </div>
          <div className="mt-0.5 font-mono text-[11px] text-txt-3">{dbName}</div>
        </div>
        <div className="flex items-center gap-1">
          {status === 'ready' && (
            <>
              <button
                onClick={() => setStudy((s) => !s)}
                title={study ? 'Hide answer key' : 'Study mode — reveal answer key'}
                className={`rounded p-1.5 transition ${
                  study ? 'bg-surface3 text-conf-medium' : 'text-txt-3 hover:bg-surface3'
                }`}
              >
                {study ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
              <button
                onClick={onHunt}
                title="Quick query in the Query Lab"
                className="rounded-md bg-surface3 px-3 py-1.5 text-xs text-txt hover:bg-line2"
              >
                <Terminal size={13} className="inline" /> Query
              </button>
            </>
          )}
          <button
            onClick={onDelete}
            disabled={deleting}
            title="Delete campaign"
            className="rounded p-1.5 text-txt-3 hover:bg-surface3 hover:text-mal disabled:opacity-40"
          >
            {deleting ? <Loader2 size={15} className="animate-spin" /> : <Trash2 size={15} />}
          </button>
        </div>
      </div>

      {study && key && <AnswerKeyPanel k={key} />}
      {study && !key && status === 'ready' && (
        <div className="mt-3 text-xs text-txt-3">
          <Loader2 size={12} className="mr-1 inline animate-spin" /> Loading answer key…
        </div>
      )}
      {status === 'ready' && <HuntsSection slug={slug} name={name} />}
    </div>
  )
}

function HuntsSection({ slug, name }: { slug: string; name: string }) {
  const nav = useNavigate()
  const qc = useQueryClient()
  const { data } = useQuery({
    queryKey: ['hunts', slug],
    queryFn: () => huntApi.list(slug),
  })
  const [title, setTitle] = useState('')
  const [naming, setNaming] = useState(false)
  const create = useMutation({
    // One click: a sensible default title, a pre-seeded hypothesis, straight
    // into the workspace. Name it first only if you want to.
    mutationFn: () => huntApi.create(slug, title.trim() || `${name} hunt`),
    onSuccess: (h: Hunt) => {
      qc.invalidateQueries({ queryKey: ['hunts', slug] })
      nav(`/hunt/${h.id}`)
    },
  })
  const hunts = data?.hunts ?? []

  return (
    <div className="mt-4 border-t border-line pt-3">
      <div className="mb-2 flex items-center gap-2">
        <Target size={12} className="text-txt-3" />
        <span className="text-xs font-medium text-txt-2">PEAK hunts</span>
      </div>
      <div className="space-y-1">
        {hunts.map((h) => (
          <button
            key={h.id}
            onClick={() => nav(`/hunt/${h.id}`)}
            className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-xs
                       hover:bg-surface3"
          >
            <span className="flex-1 truncate text-txt">{h.title}</span>
            <span className="rounded bg-surface3 px-1.5 py-0.5 text-[10px] capitalize text-txt-2">
              {h.phase}
            </span>
            {h.outcome && (
              <span className="text-[10px] text-accent-light">{h.outcome}</span>
            )}
          </button>
        ))}
      </div>
      <div className="mt-2 flex items-center gap-2">
        {naming && (
          <input
            autoFocus
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && create.mutate()}
            placeholder={`${name} hunt`}
            className="flex-1 rounded border border-line bg-surface2 px-2 py-1 text-xs outline-none
                       focus:border-accent"
          />
        )}
        <button
          onClick={() => create.mutate()}
          disabled={create.isPending}
          className="flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-medium
                     text-black hover:bg-accent-light hover:shadow-glow active:scale-[0.98]
                     disabled:opacity-40"
        >
          {create.isPending ? <Loader2 size={12} className="animate-spin" /> : <Target size={12} />}
          Start a hunt
        </button>
        {!naming && (
          <button
            onClick={() => setNaming(true)}
            className="rounded px-2 py-1.5 text-[11px] text-txt-3 hover:text-txt"
          >
            name it first
          </button>
        )}
      </div>
    </div>
  )
}

function AnswerKeyPanel({ k }: { k: AnswerKey }) {
  const gt = k.ground_truth
  return (
    <div className="mt-4 rounded-md border border-conf-medium/20 bg-conf-medium/5 p-3">
      <div className="mb-2 flex items-center gap-2 text-xs font-medium text-conf-medium">
        <Eye size={13} /> Answer key
      </div>
      <p className="mb-3 text-xs italic text-txt-2">{k.spec.hypothesis}</p>

      <div className="mb-3 flex gap-4 text-xs">
        <Stat label="attack" value={gt.attack ?? 0} className="text-mal" />
        <Stat label="decoy" value={gt.decoy ?? 0} className="text-decoy" />
        <Stat label="noise" value={gt.noise ?? 0} className="text-noise" />
      </div>

      <div className="space-y-1.5">
        {k.steps.map((s, i) => (
          <div key={i} className="flex items-center gap-2 text-xs">
            <span className="font-mono text-txt-2">{s.technique_id}</span>
            <span className="text-txt">{s.technique_name}</span>
            <span className="rounded bg-surface3 px-1.5 py-0.5 text-[10px] text-accent-light">
              {s.variant_label}
            </span>
            <span className="ml-auto text-txt-3">
              {s.labelled} events · {s.host}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

function Stat({ label, value, className }: { label: string; value: number; className: string }) {
  return (
    <div>
      <span className={`text-sm font-semibold ${className}`}>{value}</span>
      <span className="ml-1 text-txt-3">{label}</span>
    </div>
  )
}
