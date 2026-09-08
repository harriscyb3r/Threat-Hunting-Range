// Behaviour-first campaign builder: type what to hunt, disambiguate, review the
// spec, build. The disambiguation step is deliberately not skippable when the
// resolver is unsure — "WMI abuse" is three different hunts and choosing between
// them is part of the training, not an obstacle to route around.

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { useToast } from '../components/toast'
import {
  Search, Loader2, ArrowRight, Check, AlertTriangle, Sparkles, FileText,
  Crosshair, UserRound, Library, Swords,
} from 'lucide-react'
import {
  api, huntApi, learnApi, TACTIC_LABEL, type Candidate, type ScenarioSpec, type TechniqueHit,
  type LibraryCampaign,
} from '../lib/api'

const SAMPLE_REPORT = `APT29 (aka Cozy Bear) conducted a targeted intrusion. Initial access via a \
spearphishing link delivered a payload. The actor ran encoded PowerShell to stage a \
second-stage implant, dumped credentials from LSASS with comsvcs.dll MiniDump, and \
performed kerberoasting against service accounts. They moved laterally using \
pass-the-hash and remote WMI execution, established persistence via a scheduled task, \
and exfiltrated data to cloud storage before deploying ransomware and deleting shadow \
copies with vssadmin. C2 beaconed to 185.220.101.9 and cdn-sync-update.com over HTTPS.`

const EXAMPLES = [
  'kerberoasting',
  'pass the hash',
  'WMI abuse',
  'dns tunnelling exfil',
  'adding credentials to a service principal',
  'ransomware',
]

const CONF_CLASS: Record<string, string> = {
  high: 'text-conf-high border-conf-high/40 bg-conf-high/10',
  medium: 'text-conf-medium border-conf-medium/40 bg-conf-medium/10',
  low: 'text-conf-low border-conf-low/40 bg-conf-low/10',
}

type Stage = 'input' | 'choose' | 'review' | 'building'

export function Scenarios() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [mode, setMode] = useState<'behaviour' | 'cti' | 'library'>('behaviour')
  const [text, setText] = useState('')
  const [report, setReport] = useState('')
  const [stage, setStage] = useState<Stage>('input')
  const [chosen, setChosen] = useState<Set<string>>(new Set())
  const [spec, setSpec] = useState<ScenarioSpec | null>(null)
  const [slug, setSlug] = useState('')
  const [depth, setDepth] = useState<'isolated' | 'contextual' | 'full-chain'>('contextual')
  const [loudness, setLoudness] = useState(3)
  const [withTwin, setWithTwin] = useState(true)
  const [events, setEvents] = useState(200000)
  // Set from a CTI draft, shown above the spec review so you can see what was
  // extracted from the report (actor, techniques, what couldn't be planted).
  const [draftMeta, setDraftMeta] = useState<{
    actor: string; techniques: TechniqueHit[]; unresolved: string[]
    iocs: { ips: number; domains: number; hashes: number }
  } | null>(null)

  const draft = useMutation({
    mutationFn: (t: string) => api.draft(t, { loudness }),
    onSuccess: (d) => {
      setSpec(d.spec)
      setSlug(suggestSlug(d.spec.name))
      setDraftMeta({
        actor: d.actor, techniques: d.techniques,
        unresolved: d.unresolved, iocs: d.ioc_counts,
      })
      setStage('review')
    },
  })

  const resolve = useMutation({
    mutationFn: (t: string) => api.resolve(t),
    onSuccess: (r) => {
      // Preselect the strong matches.
      const strong = r.candidates.filter((c) => c.score >= 0.6).map((c) => c.id)
      setChosen(new Set(strong.length ? [strong[0]] : r.candidates.slice(0, 1).map((c) => c.id)))
      setStage('choose')
    },
  })

  const makeSpec = useMutation({
    mutationFn: (ids: string[]) =>
      api.makeSpec(ids, { context_depth: depth, loudness }),
    onSuccess: (r) => {
      setSpec(r.spec)
      if (!slug) setSlug(suggestSlug(r.spec.name))
      setStage('review')
    },
  })

  const build = useMutation({
    mutationFn: () =>
      api.build({
        slug,
        spec: spec!,
        target_events: events,
        with_twin: withTwin,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['status'] })
      toast({ kind: 'pending', title: 'Building campaign',
              description: 'Generating telemetry — this takes about a minute.' })
      // Stay put and track the build, so "Start hunting" is one click away when
      // it's ready — no hop to Campaigns and back.
      setStage('building')
    },
    onError: (e: Error) =>
      toast({ kind: 'error', title: 'Build failed', description: e.message }),
  })

  const candidates = resolve.data?.candidates ?? []
  const ambiguous = resolve.data?.ambiguous ?? false

  function toggle(id: string) {
    setChosen((s) => {
      const n = new Set(s)
      n.has(id) ? n.delete(id) : n.add(id)
      return n
    })
  }

  function reset() {
    setStage('input')
    setSpec(null)
    setDraftMeta(null)
  }

  return (
    <div className="mx-auto flex h-full max-w-3xl flex-col overflow-auto px-6 py-8">
      {/* Mode toggle: behaviour-first vs actor-first */}
      <div className="mb-5 flex w-fit rounded-lg border border-line bg-surface2 p-0.5">
        <button
          onClick={() => { setMode('behaviour'); reset() }}
          className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm transition ${
            mode === 'behaviour' ? 'bg-surface3 text-txt' : 'text-txt-2 hover:text-txt'
          }`}
        >
          <Crosshair size={14} /> Describe a technique
        </button>
        <button
          onClick={() => { setMode('cti'); reset() }}
          className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm transition ${
            mode === 'cti' ? 'bg-surface3 text-txt' : 'text-txt-2 hover:text-txt'
          }`}
        >
          <FileText size={14} /> Paste a threat report
        </button>
        <button
          onClick={() => { setMode('library'); reset() }}
          className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm transition ${
            mode === 'library' ? 'bg-surface3 text-txt' : 'text-txt-2 hover:text-txt'
          }`}
        >
          <Library size={14} /> Library
        </button>
      </div>

      {mode === 'library' && <LibraryGrid />}

      {mode !== 'library' && (mode === 'behaviour' ? (
        <>
          <h1 className="text-h1 text-txt">What do you want to hunt?</h1>
          <p className="mt-1 text-sm text-txt-2">
            Describe a technique in plain language. The range builds a campaign with the attack
            buried in realistic noise and technique-specific decoys.
          </p>

          <form
            onSubmit={(e) => {
              e.preventDefault()
              if (text.trim()) resolve.mutate(text.trim())
            }}
            className="mt-5"
          >
            <div className="flex items-center gap-2 rounded-lg border border-line bg-surface2 px-3
                            py-2 focus-within:border-accent">
              <Search size={16} className="text-txt-3" />
              <input
                value={text}
                onChange={(e) => setText(e.target.value)}
                placeholder="e.g. kerberoasting, WMI abuse, pass the hash then ransomware"
                className="w-full bg-transparent text-sm outline-none placeholder:text-txt-3"
                autoFocus
              />
              <button
                type="submit"
                disabled={!text.trim() || resolve.isPending}
                className="flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-sm
                           font-medium text-black hover:bg-accent-light disabled:opacity-40"
              >
                {resolve.isPending
                  ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
                Resolve
              </button>
            </div>
          </form>

          <div className="mt-3 flex flex-wrap gap-1.5">
            {EXAMPLES.map((ex) => (
              <button
                key={ex}
                onClick={() => { setText(ex); resolve.mutate(ex) }}
                className="rounded-full border border-line bg-surface2 px-3 py-1 text-xs text-txt-2
                           hover:border-line2 hover:text-txt"
              >
                {ex}
              </button>
            ))}
          </div>
        </>
      ) : (
        <>
          <h1 className="text-h1 text-txt">Paste a threat report</h1>
          <p className="mt-1 text-sm text-txt-2">
            Paste a CTI report, actor profile, or advisory. The range extracts the ATT&amp;CK
            techniques it names and drafts a full kill-chain campaign — no data leaves your machine.
          </p>

          <textarea
            value={report}
            onChange={(e) => setReport(e.target.value)}
            rows={9}
            placeholder="Paste the report text here…"
            className="mt-5 w-full rounded-lg border border-line bg-surface2 px-3 py-2 text-sm
                       outline-none focus:border-accent placeholder:text-txt-3"
          />
          <div className="mt-3 flex items-center gap-3">
            <button
              onClick={() => report.trim() && draft.mutate(report.trim())}
              disabled={!report.trim() || draft.isPending}
              className="flex items-center gap-1.5 rounded-md bg-accent px-4 py-1.5 text-sm
                         font-medium text-black hover:bg-accent-light disabled:opacity-40"
            >
              {draft.isPending
                ? <Loader2 size={14} className="animate-spin" /> : <Sparkles size={14} />}
              Extract &amp; draft
            </button>
            <button
              onClick={() => setReport(SAMPLE_REPORT)}
              className="text-xs text-txt-3 hover:text-txt"
            >
              use a sample report
            </button>
            {draft.isError && (
              <span className="text-xs text-mal">{(draft.error as Error).message}</span>
            )}
          </div>
        </>
      ))}

      {/* Draft summary — what was extracted from the report */}
      {stage === 'review' && draftMeta && (
        <div className="mt-6 rounded-lg border border-line bg-surface2 p-4 shadow-card">
          <div className="flex items-center gap-2 text-sm font-medium">
            <FileText size={15} className="text-accent-light" /> Extracted from the report
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-txt-2">
            {draftMeta.actor && (
              <span className="flex items-center gap-1.5 rounded bg-surface3 px-2 py-1">
                <UserRound size={12} className="text-accent-light" />
                {draftMeta.actor}
              </span>
            )}
            <span className="text-txt-3">
              IOCs: {draftMeta.iocs.ips} IP · {draftMeta.iocs.domains} domain ·
              {' '}{draftMeta.iocs.hashes} hash
            </span>
          </div>
          <div className="mt-3 space-y-1">
            {draftMeta.techniques.map((h) => (
              <div key={h.id} className="flex items-center gap-2 text-xs">
                {h.has_emitter
                  ? <Check size={12} className="text-good" />
                  : <span title="Named in the report but the range can't plant it yet"
                          className="text-txt-3">○</span>}
                <span className="font-mono text-txt-2">{h.id}</span>
                <span className={h.has_emitter ? 'text-txt' : 'text-txt-3'}>{h.name}</span>
                <span className="ml-auto text-[10px] text-txt-3">
                  {TACTIC_LABEL[h.tactic] ?? h.tactic}
                </span>
              </div>
            ))}
          </div>
          {draftMeta.unresolved.length > 0 && (
            <div className="mt-2 text-[11px] text-txt-3">
              {draftMeta.unresolved.length} technique
              {draftMeta.unresolved.length === 1 ? '' : 's'} named in the report can't be planted
              yet and were left out of the campaign.
            </div>
          )}
        </div>
      )}

      {/* Choose */}
      {stage !== 'input' && candidates.length > 0 && (
        <div className="mt-8">
          {ambiguous && (
            <div className="mb-3 flex items-start gap-2 rounded-md border border-conf-medium/30
                            bg-conf-medium/5 px-3 py-2 text-xs text-conf-medium">
              <AlertTriangle size={14} className="mt-0.5 shrink-0" />
              <span>
                <span className="font-medium">{text}</span> could mean several different hunts.
                These map to different techniques and different queries — pick the one(s) you want.
              </span>
            </div>
          )}
          <div className="space-y-1.5">
            {candidates.map((c) => (
              <CandidateRow
                key={c.id}
                c={c}
                selected={chosen.has(c.id)}
                onToggle={() => toggle(c.id)}
              />
            ))}
          </div>
          <div className="mt-4 flex items-center justify-between">
            <span className="text-xs text-txt-3">
              {chosen.size} technique{chosen.size === 1 ? '' : 's'} selected
            </span>
            <button
              onClick={() => makeSpec.mutate([...chosen])}
              disabled={chosen.size === 0 || makeSpec.isPending}
              className="flex items-center gap-1.5 rounded-md bg-accent px-4 py-1.5 text-sm
                         font-medium text-black hover:bg-accent-light disabled:opacity-40"
            >
              Build spec <ArrowRight size={14} />
            </button>
          </div>
        </div>
      )}

      {stage !== 'input' && !resolve.isPending && candidates.length === 0 && (
        <div className="mt-8 rounded-md border border-line bg-surface2 px-4 py-3 text-sm text-txt-2">
          Couldn't resolve that to a technique. Try a technique name, an ID like{' '}
          <code className="text-accent-light">T1558.003</code>, or a phrase like{' '}
          <code className="text-accent-light">kerberoasting</code>.
        </div>
      )}

      {/* Review + build */}
      {stage === 'review' && spec && (
        <div className="mt-8 rounded-lg border border-line bg-surface2 p-5 shadow-card">
          <div className="flex items-center gap-2 text-accent-light">
            <Sparkles size={15} />
            <span className="text-sm font-medium">Campaign spec</span>
          </div>
          <div className="mt-3 space-y-3 text-sm">
            <Field label="Name">
              <input
                value={spec.name}
                onChange={(e) => setSpec({ ...spec, name: e.target.value })}
                className="w-full rounded border border-line bg-surface px-2 py-1 outline-none
                           focus:border-accent"
              />
            </Field>
            <Field label="Hypothesis">
              <textarea
                value={spec.hypothesis}
                onChange={(e) => setSpec({ ...spec, hypothesis: e.target.value })}
                rows={2}
                className="w-full rounded border border-line bg-surface px-2 py-1 text-txt-2
                           outline-none focus:border-accent"
              />
            </Field>
            <Field label="Kill chain">
              <div className="flex flex-wrap items-center gap-1.5">
                {spec.steps.map((s, i) => (
                  <span key={i} className="flex items-center gap-1.5">
                    <span className="rounded bg-surface3 px-2 py-0.5 font-mono text-xs text-txt">
                      {s.technique_id}
                    </span>
                    {i < spec.steps.length - 1 && (
                      <ArrowRight size={11} className="text-txt-3" />
                    )}
                  </span>
                ))}
              </div>
            </Field>

            <div className="grid grid-cols-2 gap-3 pt-1">
              <Field label="Slug">
                <input
                  value={slug}
                  onChange={(e) => setSlug(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '-'))}
                  className="w-full rounded border border-line bg-surface px-2 py-1 font-mono text-xs
                             outline-none focus:border-accent"
                />
              </Field>
              <Field label="Context depth">
                <select
                  value={depth}
                  onChange={(e) => setDepth(e.target.value as typeof depth)}
                  className="w-full rounded border border-line bg-surface px-2 py-1 text-xs
                             outline-none focus:border-accent"
                >
                  <option value="isolated">Isolated — technique + decoys only</option>
                  <option value="contextual">Contextual — some surrounding activity</option>
                  <option value="full-chain">Full chain — full intrusion</option>
                </select>
              </Field>
              <Field label={`Loudness — ${['','careful','quiet','normal','loud','smash'][loudness]}`}>
                <input
                  type="range"
                  min={1}
                  max={5}
                  value={loudness}
                  onChange={(e) => setLoudness(Number(e.target.value))}
                  className="w-full accent-accent"
                />
              </Field>
              <Field label={`Haystack — ${events.toLocaleString()} events`}>
                <input
                  type="range"
                  min={40000}
                  max={500000}
                  step={20000}
                  value={events}
                  onChange={(e) => setEvents(Number(e.target.value))}
                  className="w-full accent-accent"
                />
              </Field>
            </div>

            <label className="flex items-center gap-2 pt-1 text-xs text-txt-2">
              <input
                type="checkbox"
                checked={withTwin}
                onChange={(e) => setWithTwin(e.target.checked)}
                className="accent-accent"
              />
              Build the clean twin too (needed for false-positive testing)
            </label>
          </div>

          {build.isError && (
            <div className="mt-3 text-xs text-mal">{(build.error as Error).message}</div>
          )}

          <button
            onClick={() => build.mutate()}
            disabled={!slug || build.isPending}
            className="mt-4 flex w-full items-center justify-center gap-2 rounded-md bg-accent
                       px-4 py-2 text-sm font-medium text-black hover:bg-accent-light hover:shadow-glow active:scale-[0.98]
                       disabled:opacity-40"
          >
            {build.isPending ? <Loader2 size={15} className="animate-spin" /> : <Check size={15} />}
            Generate campaign
          </button>
          <p className="mt-2 text-center text-[11px] text-txt-3">
            Generation runs in the background (~1 min). You can start hunting the moment it's ready.
          </p>
        </div>
      )}

      {/* Build tracker → one-click straight into a hunt when ready. */}
      {stage === 'building' && (
        <BuildAndHunt slug={slug} name={spec?.name || slug} onReset={reset} />
      )}
    </div>
  )
}

// Polls the just-built campaign to ready, then offers a single click into a
// pre-seeded hunt — the "build and hunt" flow, without a detour through
// Campaigns.
function BuildAndHunt({ slug, name, onReset }: {
  slug: string; name: string; onReset: () => void
}) {
  const nav = useNavigate()
  const { toast } = useToast()
  const { data: status } = useQuery({
    queryKey: ['status'],
    queryFn: api.status,
    refetchInterval: (q) => {
      const c = q.state.data?.campaigns.find((x) => x.slug === slug)
      return c && c.status !== 'building' ? false : 1500
    },
  })
  const campaign = status?.campaigns.find((c) => c.slug === slug)
  const ready = campaign?.status === 'ready'
  const failed = campaign?.status === 'failed'

  const start = useMutation({
    mutationFn: () => huntApi.create(slug, `${name} hunt`),
    onSuccess: (h) => nav(`/hunt/${h.id}`),
    onError: (e: Error) => toast({ kind: 'error', title: "Couldn't start hunt", description: e.message }),
  })

  return (
    <div className="mt-8 rounded-lg border border-line bg-surface2 p-6 text-center shadow-card">
      {failed ? (
        <>
          <AlertTriangle size={26} className="mx-auto text-mal" />
          <div className="mt-3 text-sm font-medium text-txt">Build failed</div>
          <p className="mt-1 text-xs text-txt-3">Something went wrong generating {name}.</p>
          <button onClick={onReset}
            className="mt-4 rounded-md bg-surface3 px-4 py-2 text-sm text-txt hover:bg-line2">
            Try again
          </button>
        </>
      ) : ready ? (
        <>
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl
                          bg-good/10 text-good"><Check size={24} /></div>
          <div className="mt-3 text-h2 text-txt">{name} is ready</div>
          <p className="mt-1 text-xs text-txt-3">
            The hunt opens on a pre-drafted hypothesis and the right starting query.
          </p>
          <div className="mt-4 flex items-center justify-center gap-2">
            <button
              onClick={() => start.mutate()}
              disabled={start.isPending}
              className="flex items-center gap-2 rounded-md bg-accent px-5 py-2 text-sm font-medium
                         text-black hover:bg-accent-light hover:shadow-glow active:scale-[0.98]
                         disabled:opacity-40"
            >
              {start.isPending ? <Loader2 size={15} className="animate-spin" /> : <Crosshair size={15} />}
              Start hunting
            </button>
            <button onClick={() => nav('/campaigns')}
              className="rounded-md bg-surface3 px-4 py-2 text-sm text-txt hover:bg-line2">
              Open in Campaigns
            </button>
          </div>
          <button onClick={onReset} className="mt-3 text-[11px] text-txt-3 hover:text-txt">
            build another
          </button>
        </>
      ) : (
        <>
          <Loader2 size={26} className="mx-auto animate-spin text-accent-light" />
          <div className="mt-3 text-sm font-medium text-txt">Building {name}…</div>
          <p className="mt-1 text-xs text-txt-3">
            Generating schema-faithful telemetry and planting the attack — about a minute.
          </p>
          <button onClick={() => nav('/campaigns')}
            className="mt-4 text-[11px] text-txt-3 hover:text-txt">
            watch it in Campaigns instead →
          </button>
        </>
      )}
    </div>
  )
}

function CandidateRow({
  c, selected, onToggle,
}: { c: Candidate; selected: boolean; onToggle: () => void }) {
  return (
    <button
      onClick={onToggle}
      className={`flex w-full items-start gap-3 rounded-lg border px-4 py-3 text-left transition ${
        selected ? 'border-accent bg-accent/5' : 'border-line bg-surface2 hover:border-line2'
      }`}
    >
      <div
        className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded border ${
          selected ? 'border-accent bg-accent text-black' : 'border-line2'
        }`}
      >
        {selected && <Check size={11} />}
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs text-txt-2">{c.id}</span>
          <span className="font-medium text-txt">{c.name}</span>
          <span className={`rounded border px-1.5 py-0.5 text-[10px] ${CONF_CLASS[c.confidence]}`}>
            {c.confidence}
          </span>
        </div>
        <div className="mt-0.5 text-xs text-txt-2">{c.summary}</div>
        <div className="mt-1 flex items-center gap-2 text-[10px] text-txt-3">
          <span className="rounded bg-surface3 px-1.5 py-0.5">
            {TACTIC_LABEL[c.tactic] ?? c.tactic}
          </span>
          <span>{c.reason}</span>
        </div>
      </div>
    </button>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-[11px] uppercase tracking-wide text-txt-3">{label}</span>
      {children}
    </label>
  )
}


const DIFF_CLASS: Record<string, { dot: string; pill: string }> = {
  starter: { dot: 'bg-good', pill: 'bg-good/10 text-good' },
  intermediate: { dot: 'bg-conf-medium', pill: 'bg-conf-medium/10 text-conf-medium' },
  operator: { dot: 'bg-mal', pill: 'bg-mal/10 text-mal' },
}

function LibraryGrid() {
  const qc = useQueryClient()
  const nav = useNavigate()
  const { toast } = useToast()
  const { data } = useQuery({ queryKey: ['library'], queryFn: learnApi.library })
  const build = useMutation({
    mutationFn: async (c: LibraryCampaign) => {
      const { spec } = await learnApi.librarySpec(c.slug)
      return api.build({ slug: c.slug, spec, target_events: c.events, with_twin: true })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['status'] })
      qc.invalidateQueries({ queryKey: ['library'] })
      toast({ kind: 'pending', title: 'Building campaign',
              description: 'Generating telemetry — this takes about a minute.' })
      nav('/campaigns')
    },
    onError: (e: Error) =>
      toast({ kind: 'error', title: 'Build failed', description: e.message }),
  })
  const campaigns = data?.campaigns ?? []

  return (
    <div>
      <h1 className="text-h1 text-txt">Campaign library</h1>
      <p className="mt-1 text-sm text-txt-2">
        Ready-made hunts modelled on real threat activity — from a single-technique drill to a full
        APT kill chain. Each builds the same way every time, so they pair with the Learn curriculum.
      </p>
      <div className="mt-5 grid gap-3 sm:grid-cols-2">
        {campaigns.map((c) => (
          <div key={c.slug} className="flex flex-col rounded-lg border border-line/60 bg-surface2 p-4 shadow-card transition-all duration-200 hover:-translate-y-0.5 hover:border-line2 hover:shadow-raised">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <Swords size={14} className="shrink-0 text-accent-light" />
                  <span className="truncate font-medium text-txt">{c.name}</span>
                </div>
                <div className="mt-0.5 text-[11px] text-txt-3">{c.actor}</div>
              </div>
              <span className={`inline-flex shrink-0 items-center gap-1.5 rounded-full px-2 py-0.5
                                text-[10px] capitalize ${(DIFF_CLASS[c.difficulty] ?? DIFF_CLASS.starter).pill}`}>
                <span className={`h-1.5 w-1.5 rounded-full ${(DIFF_CLASS[c.difficulty] ?? DIFF_CLASS.starter).dot}`} />
                {c.difficulty}
              </span>
            </div>
            <p className="mt-2 flex-1 text-xs text-txt-2">{c.description}</p>
            <div className="mt-3 flex flex-wrap gap-1">
              {c.techniques.slice(0, 6).map((t) => (
                <span key={t} className="rounded bg-surface3 px-1.5 py-0.5 font-mono text-[10px] text-txt-3">
                  {t}
                </span>
              ))}
              {c.techniques.length > 6 && (
                <span className="text-[10px] text-txt-3">+{c.techniques.length - 6}</span>
              )}
            </div>
            <div className="mt-3 flex items-center justify-between">
              <span className="text-[10px] text-txt-3">
                {c.techniques.length} technique{c.techniques.length === 1 ? '' : 's'} ·
                {' '}{(c.events / 1000).toFixed(0)}k events
              </span>
              {c.built ? (
                <button
                  onClick={() => nav('/campaigns')}
                  className="rounded-md bg-surface3 px-3 py-1.5 text-xs text-txt hover:bg-line2"
                >
                  Built — go hunt
                </button>
              ) : (
                <button
                  onClick={() => build.mutate(c)}
                  disabled={build.isPending}
                  className="flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs
                             font-medium text-black hover:bg-accent-light disabled:opacity-40"
                >
                  {build.isPending && build.variables?.slug === c.slug
                    ? <Loader2 size={12} className="animate-spin" /> : <Sparkles size={12} />}
                  Build
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function suggestSlug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 30)
}
