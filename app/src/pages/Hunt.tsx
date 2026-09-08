// The PEAK hunt workspace: Prepare (ABLE hypothesis) -> Execute (query + pin
// evidence + promote findings) -> Act (write-up + save detection + Sigma).
//
// The three phases are tabs, but Prepare gates Execute: the ABLE fields must be
// filled before the phase advances, because a hunt without a hypothesis is just
// poking at data. That gate is the discipline PEAK is teaching, so the UI
// enforces it rather than treating it as optional paperwork.

import { useEffect, useMemo, useRef, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ClipboardList, Terminal, FileCheck, ArrowRight, Check, Loader2, Flag,
  Trash2, Target, ChevronLeft, Lightbulb, Search, ShieldOff, ChevronDown,
  ExternalLink, Wand2, Trophy, Eye,
} from 'lucide-react'
import {
  api, huntApi, TACTIC_LABEL, type Evidence, type Hunt, type QueryResult, type Technique,
} from '../lib/api'
import { useSchema } from '../lib/useSchema'
import { KqlEditor } from '../components/KqlEditor'
import { ResultsGrid } from '../components/ResultsGrid'
import { SaveDetectionDialog } from '../components/SaveDetectionDialog'
import { HuntDebrief } from '../components/HuntDebrief'

const PHASES = [
  { key: 'prepare', label: 'Prepare', icon: ClipboardList },
  { key: 'execute', label: 'Execute', icon: Terminal },
  { key: 'act', label: 'Act', icon: FileCheck },
] as const

export function Hunt() {
  const { id } = useParams<{ id: string }>()
  const nav = useNavigate()
  const qc = useQueryClient()
  const { data, isLoading } = useQuery({
    queryKey: ['hunt', id],
    queryFn: () => huntApi.get(id!),
    enabled: !!id,
  })
  // Lifted here so the header's "Score & answers" button can jump straight to
  // the debrief from any phase. Declared BEFORE the early return below — hooks
  // must run in the same order every render, so it cannot sit after a return.
  const [showScore, setShowScore] = useState(false)

  if (isLoading || !data) {
    return (
      <div className="flex h-full items-center justify-center text-txt-3">
        <Loader2 className="animate-spin" />
      </div>
    )
  }

  const hunt = data.hunt
  const phase = hunt.phase === 'closed' ? 'act' : hunt.phase

  function setPhase(p: Hunt['phase']) {
    huntApi.patch(id!, { phase: p }).then(() => qc.invalidateQueries({ queryKey: ['hunt', id] }))
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-3 border-b border-line bg-surface px-4 py-2">
        <button onClick={() => nav('/campaigns')} className="text-txt-3 hover:text-txt">
          <ChevronLeft size={18} />
        </button>
        <div className="min-w-0">
          <div className="truncate text-sm font-medium">{hunt.title}</div>
          <div className="text-[11px] text-txt-3">
            {hunt.campaign_slug} · {hunt.hunt_type}
          </div>
        </div>
        <nav className="ml-6 flex items-center">
          {PHASES.map(({ key, label, icon: Icon }, i) => {
            const idx = PHASES.findIndex((p) => p.key === phase)
            const active = phase === key
            const done = i < idx
            return (
              <div key={key} className="flex items-center">
                {i > 0 && (
                  // Connector fills once the step to its left is complete.
                  <span className={`mx-1.5 h-px w-6 transition-colors duration-300 ${
                    i <= idx ? 'bg-accent/60' : 'bg-line2'}`} />
                )}
                <button
                  onClick={() => setPhase(key)}
                  className={`group flex items-center gap-1.5 rounded-md py-1 pl-1 pr-2.5 text-sm transition ${
                    active ? 'text-txt' : done ? 'text-accent-light hover:text-txt'
                      : 'text-txt-3 hover:text-txt-2'
                  }`}
                >
                  <span className={`flex h-6 w-6 items-center justify-center rounded-full border
                                    text-[11px] font-semibold transition-all duration-200 ${
                    active ? 'border-accent bg-accent/15 text-accent-light shadow-glow'
                      : done ? 'border-accent/40 bg-accent/10 text-accent-light'
                        : 'border-line2 bg-surface2 text-txt-3'
                  }`}>
                    {done ? <Check size={13} /> : active ? <Icon size={13} /> : i + 1}
                  </span>
                  {label}
                </button>
              </div>
            )
          })}
        </nav>
        {/* Always-visible entry to the score + answer key. */}
        <button
          onClick={() => {
            setShowScore(true)
            setPhase('act')
          }}
          title="Grade this hunt and reveal the answer key"
          className="ml-auto flex items-center gap-1.5 rounded-md border border-accent/40
                     bg-accent/10 px-3 py-1.5 text-sm font-medium text-accent-light
                     hover:bg-accent/20"
        >
          <Trophy size={14} /> Score &amp; answers
        </button>
      </div>

      <div className="min-h-0 flex-1">
        {phase === 'prepare' && <Prepare hunt={hunt} onAdvance={() => setPhase('execute')} />}
        {phase === 'execute' && <Execute detail={data} />}
        {phase === 'act' && (
          <Act detail={data} showScore={showScore} setShowScore={setShowScore} />
        )}
      </div>
    </div>
  )
}

// ── Prepare: the ABLE hypothesis ──────────────────────────────────────────

const ABLE = [
  {
    key: 'actor', label: 'Actor',
    hint: 'Who — the threat actor, or the assumption about them',
    eg: 'e.g. "an adversary with a foothold on a user workstation, credentials unknown"',
  },
  {
    key: 'behavior', label: 'Behavior',
    hint: 'What they do — the technique in observable terms',
    eg: 'e.g. "requests service tickets (4769) in bulk, with RC4 downgrade, to crack offline"',
  },
  {
    key: 'location', label: 'Location',
    hint: 'Where it shows up — hosts, logs, identities',
    eg: 'e.g. "on the domain controllers, sourced from a non-server host"',
  },
  {
    key: 'evidence_expected', label: 'Evidence',
    hint: 'What you would see if the hypothesis holds',
    eg: 'e.g. "one non-service account requesting tickets for many distinct SPNs in a short window"',
  },
] as const

// Turn a catalogue technique into a first-draft ABLE hypothesis the analyst then
// edits. This is legitimate hunt prep, not the answer key — it's the same public
// technique reference as the Techniques page, phrased as a starting hypothesis.
// What's actually planted (which host, how many) stays hidden in Study mode.
function starterFromTechnique(t: import('../lib/api').Technique) {
  const tables = t.tables.length ? t.tables.join(', ') : 'the relevant tables'
  const tells = t.variants.map((v) => v.tells).filter(Boolean).slice(0, 2)
  return {
    actor: 'An adversary operating with valid access, assumed post-compromise.',
    behavior: t.summary,
    location: `Expected in ${tables}.`,
    evidence_expected: tells.length
      ? tells.join('; ')
      : `Telemetry consistent with ${t.name}.`,
  }
}

function Prepare({ hunt, onAdvance }: { hunt: Hunt; onAdvance: () => void }) {
  const qc = useQueryClient()
  const [fields, setFields] = useState({
    actor: hunt.actor, behavior: hunt.behavior, location: hunt.location,
    evidence_expected: hunt.evidence_expected, scope: hunt.scope,
    success_criteria: hunt.success_criteria,
  })
  // Scope + success criteria matter, but they shouldn't stand between you and
  // the data — tucked away, open on demand.
  const [showAdvanced, setShowAdvanced] = useState(
    !!(hunt.scope || hunt.success_criteria))
  const save = useMutation({
    mutationFn: (patch: Partial<Hunt>) => huntApi.patch(hunt.id, patch),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunt', hunt.id] }),
  })
  const ableComplete = ABLE.every((f) => fields[f.key].trim().length > 0)
  // The gate is now a single idea: name the behaviour you're testing. A hunt
  // without a stated behaviour is just poking at data; everything else sharpens
  // it but shouldn't block the first query. (The fields arrive pre-drafted from
  // the campaign's technique, so this is usually already satisfied.)
  const canStart = fields.behavior.trim().length > 0

  function blur() {
    save.mutate(fields)
  }

  function applyStarter(t: import('../lib/api').Technique) {
    // Only fill fields that are still empty, so it never clobbers your own words.
    const starter = starterFromTechnique(t)
    setFields((s) => {
      const next = { ...s }
      for (const k of ['actor', 'behavior', 'location', 'evidence_expected'] as const) {
        if (!next[k].trim()) next[k] = starter[k]
      }
      return next
    })
    save.mutate({ techniques: [t.id] })
  }

  return (
    <div className="mx-auto max-w-2xl overflow-auto px-6 py-8" style={{ height: '100%' }}>
      <h2 className="text-h2 text-txt">Frame the hypothesis</h2>
      <p className="mt-1 text-sm text-txt-2">
        PEAK hunts start from a testable hypothesis. Fill in ABLE — Actor, Behavior, Location,
        Evidence — before you start querying.
      </p>

      <HuntReference onApply={applyStarter} />

      <div className="mt-6 space-y-4">
        {ABLE.map((f) => (
          <label key={f.key} className="block">
            <span className="mb-1 flex items-center gap-2 text-sm font-medium">
              {f.label}
              {fields[f.key].trim() && <Check size={13} className="text-good" />}
            </span>
            <span className="mb-1 block text-[11px] text-txt-3">{f.hint}</span>
            <textarea
              value={fields[f.key]}
              onChange={(e) => setFields((s) => ({ ...s, [f.key]: e.target.value }))}
              onBlur={blur}
              rows={2}
              placeholder={f.eg}
              className="w-full rounded-md border border-line bg-surface2 px-3 py-2 text-sm
                         outline-none placeholder:text-txt-3/60 focus:border-accent"
            />
          </label>
        ))}
        {/* Scope + success criteria, out of the way until you want them. */}
        <div className="rounded-md border border-line bg-surface2">
          <button
            onClick={() => setShowAdvanced((a) => !a)}
            className="flex w-full items-center gap-2 px-3 py-2 text-left"
          >
            <ChevronDown size={14}
              className={`text-txt-3 transition ${showAdvanced ? 'rotate-180' : ''}`} />
            <span className="text-sm font-medium">Scope &amp; success criteria</span>
            <span className="text-[11px] text-txt-3">optional — sharpens the hunt</span>
          </button>
          {showAdvanced && (
            <div className="grid grid-cols-2 gap-4 border-t border-line px-3 py-3">
              <label className="block">
                <span className="mb-1 block text-sm font-medium">Scope</span>
                <input
                  value={fields.scope}
                  onChange={(e) => setFields((s) => ({ ...s, scope: e.target.value }))}
                  onBlur={blur}
                  placeholder="time window, hosts, data sources"
                  className="w-full rounded-md border border-line bg-surface px-3 py-2 text-sm
                             outline-none focus:border-accent"
                />
              </label>
              <label className="block">
                <span className="mb-1 block text-sm font-medium">Success criteria</span>
                <input
                  value={fields.success_criteria}
                  onChange={(e) => setFields((s) => ({ ...s, success_criteria: e.target.value }))}
                  onBlur={blur}
                  placeholder="what proves or disproves it"
                  className="w-full rounded-md border border-line bg-surface px-3 py-2 text-sm
                             outline-none focus:border-accent"
                />
              </label>
            </div>
          )}
        </div>
      </div>

      <div className="mt-6 flex items-center justify-between">
        {!canStart ? (
          <span className="text-xs text-txt-3">
            Name the behaviour you're testing to begin.
          </span>
        ) : ableComplete ? (
          <span className="text-xs text-good">Hypothesis ready.</span>
        ) : (
          <span className="text-xs text-conf-medium">
            Good to go — filling the rest of ABLE sharpens the hunt.
          </span>
        )}
        <button
          onClick={() => {
            save.mutate(fields)
            onAdvance()
          }}
          disabled={!canStart}
          className="flex items-center gap-1.5 rounded-md bg-accent px-4 py-1.5 text-sm
                     font-medium text-black hover:bg-accent-light hover:shadow-glow
                     active:scale-[0.98] disabled:opacity-40"
        >
          Start hunting <ArrowRight size={14} />
        </button>
      </div>
    </div>
  )
}

// ── Hunt reference: technique guidance to seed the hypothesis ──────────────
//
// Not the answer key. This is public ATT&CK reference — the same material on the
// Techniques page — surfaced here so you can research the technique while
// framing the hypothesis, the way a real hunter would. It offers to pre-fill a
// first-draft ABLE from the technique, which you then rewrite in your own terms.

function HuntReference({ onApply }: { onApply: (t: Technique) => void }) {
  const [open, setOpen] = useState(true)
  const [text, setText] = useState('')
  const [selected, setSelected] = useState<Technique | null>(null)

  const { data: catalogue } = useQuery({ queryKey: ['techniques'], queryFn: api.techniques })
  const resolve = useMutation({ mutationFn: (t: string) => api.resolve(t) })

  const candidates = resolve.data?.candidates ?? []
  const byId = useMemo(() => {
    const m = new Map<string, Technique>()
    for (const t of catalogue?.techniques ?? []) m.set(t.id, t)
    return m
  }, [catalogue])

  return (
    <div className="mt-5 rounded-lg border border-line bg-surface2">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-4 py-2.5 text-left"
      >
        <Lightbulb size={15} className="text-conf-medium" />
        <span className="text-sm font-medium">Need a starting point?</span>
        <span className="text-xs text-txt-3">
          Look up the technique you're hunting for guidance and a draft hypothesis.
        </span>
        <ChevronDown
          size={15}
          className={`ml-auto text-txt-3 transition ${open ? 'rotate-180' : ''}`}
        />
      </button>

      {open && (
        <div className="border-t border-line px-4 py-3">
          <form
            onSubmit={(e) => {
              e.preventDefault()
              if (text.trim()) {
                setSelected(null)
                resolve.mutate(text.trim())
              }
            }}
            className="flex items-center gap-2 rounded-md border border-line bg-surface px-2 py-1.5
                       focus-within:border-accent"
          >
            <Search size={14} className="text-txt-3" />
            <input
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="e.g. kerberoasting, pass the hash, WMI abuse, T1558.003"
              className="w-full bg-transparent text-sm outline-none placeholder:text-txt-3"
            />
            <button
              type="submit"
              disabled={resolve.isPending}
              className="rounded bg-surface3 px-2.5 py-1 text-xs text-txt hover:bg-line2"
            >
              {resolve.isPending ? '…' : 'Look up'}
            </button>
          </form>

          {/* Candidate chips (resolver may return several — e.g. "WMI abuse"). */}
          {candidates.length > 0 && !selected && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {candidates.map((c) => (
                <button
                  key={c.id}
                  onClick={() => setSelected(byId.get(c.id) ?? null)}
                  disabled={!byId.has(c.id)}
                  title={byId.has(c.id) ? c.summary : 'No emitter for this technique yet'}
                  className="rounded-full border border-line bg-surface px-3 py-1 text-xs
                             text-txt-2 hover:border-line2 hover:text-txt disabled:opacity-40"
                >
                  <span className="font-mono text-[10px] text-txt-3">{c.id}</span> {c.name}
                </button>
              ))}
            </div>
          )}
          {resolve.isSuccess && candidates.length === 0 && (
            <div className="mt-3 text-xs text-txt-3">
              No technique matched — try a name, a phrase, or an ID like T1558.003.
            </div>
          )}

          {selected && <TechniqueGuidance t={selected} onApply={onApply} onBack={() => setSelected(null)} />}
        </div>
      )}
    </div>
  )
}

function TechniqueGuidance({
  t, onApply, onBack,
}: { t: Technique; onApply: (t: Technique) => void; onBack: () => void }) {
  return (
    <div className="mt-3 rounded-md border border-line bg-surface p-3">
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs text-txt-2">{t.id}</span>
            <span className="text-sm font-medium">{t.name}</span>
            <a href={t.url} target="_blank" rel="noreferrer" className="text-txt-3 hover:text-accent">
              <ExternalLink size={12} />
            </a>
          </div>
          <div className="text-[11px] text-txt-3">{TACTIC_LABEL[t.tactic] ?? t.tactic}</div>
        </div>
        <button onClick={onBack} className="text-xs text-txt-3 hover:text-txt">back</button>
      </div>

      <p className="mt-2 text-xs text-txt-2">{t.summary}</p>

      <div className="mt-2">
        <div className="text-[10px] uppercase tracking-wide text-txt-3">Query these tables</div>
        <div className="mt-1 flex flex-wrap gap-1">
          {t.tables.map((tbl) => (
            <span key={tbl} className="rounded bg-surface3 px-1.5 py-0.5 font-mono text-[10px]
                                       text-amber-300/80">
              {tbl}
            </span>
          ))}
        </div>
      </div>

      {t.variants.length > 0 && (
        <div className="mt-3">
          <div className="text-[10px] uppercase tracking-wide text-txt-3">
            How it looks in telemetry — and the naive queries it defeats
          </div>
          <div className="mt-1 space-y-1.5">
            {t.variants.map((v) => (
              <div key={v.key} className="text-[11px]">
                <span className="text-txt">{v.label}</span>
                <span className="text-txt-2"> — {v.tells}</span>
                {v.defeats && (
                  <span className="ml-1 inline-flex items-center gap-1 text-mal/80">
                    <ShieldOff size={10} /> defeats {v.defeats}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      <button
        onClick={() => onApply(t)}
        className="mt-3 flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs
                   font-medium text-black hover:bg-accent-light hover:shadow-glow active:scale-[0.98]"
      >
        <Wand2 size={13} /> Draft ABLE from this technique
      </button>
      <p className="mt-1.5 text-[10px] text-txt-3">
        Fills the empty fields with a first draft you should rewrite in your own words. It won't
        overwrite anything you've already typed.
      </p>
    </div>
  )
}

// ── Execute: query + evidence + findings ──────────────────────────────────

// Canonical first-pivot queries for the techniques with an obvious starting
// point. Everything else falls back to a table-scoped starter built from the
// technique's own tables. Each keeps _ItemId so pinned rows map to ground truth.
const CANONICAL_STARTER: Record<string, string> = {
  'T1558.003': 'SecurityEvent\n| where EventID == 4769\n| project TimeGenerated, Account, ServiceName, TicketEncryptionType, Computer, _ItemId',
  'T1003.001': 'DeviceProcessEvents\n| where ProcessCommandLine has "lsass" or FileName in~ ("procdump.exe","rundll32.exe","taskmgr.exe")\n| project Timestamp, DeviceName, FileName, ProcessCommandLine, _ItemId',
  'T1550.002': 'SecurityEvent\n| where EventID == 4624 and LogonType == 3 and AuthenticationPackageName == "NTLM"\n| project TimeGenerated, Account, Computer, IpAddress, _ItemId',
  'T1047': 'DeviceProcessEvents\n| where FileName =~ "wmic.exe" or InitiatingProcessFileName =~ "wmiprvse.exe"\n| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, _ItemId',
  'T1071.001': 'DeviceNetworkEvents\n| summarize conns=count() by RemoteUrl, RemoteIP, bin(Timestamp, 1h)\n| order by conns desc',
  'T1486': 'DeviceFileEvents\n| where ActionType == "FileModified"\n| summarize files=count() by InitiatingProcessFileName, bin(Timestamp, 5m)\n| order by files desc',
  'T1110.003': 'SigninLogs\n| where ResultType != "0"\n| summarize failures=count() by UserPrincipalName, IPAddress\n| order by failures desc',
  'T1087.002': 'DeviceProcessEvents\n| where FileName in~ ("net.exe","nltest.exe","dsquery.exe") or ProcessCommandLine has "Get-ADUser"\n| project Timestamp, DeviceName, ProcessCommandLine, _ItemId',
}

function headerCsl(hunt: Hunt): string {
  return `// Hunt: ${hunt.behavior || hunt.title}\n`
    + '// Ctrl+Enter to run. Keep _ItemId in your projection so pinned rows map to ground truth.\n'
}

// Starter queries offered as chips: the canonical pivot first (when there is
// one), then a plain table-scoped starter per table the technique touches.
function starterQueries(hunt: Hunt, t?: Technique): { label: string; csl: string }[] {
  const out: { label: string; csl: string }[] = []
  if (t && CANONICAL_STARTER[t.id]) {
    out.push({ label: `${t.name}`, csl: headerCsl(hunt) + CANONICAL_STARTER[t.id] })
  }
  const tables = (t?.tables?.length ? t.tables : ['SecurityEvent']).slice(0, 3)
  for (const tbl of tables) {
    out.push({ label: tbl, csl: `${headerCsl(hunt)}${tbl}\n| take 100` })
  }
  return out
}

// A compact, always-available reference for the technique being hunted: the
// tables to query and how each variant shows up in telemetry (and what naive
// query it defeats). The same public material as the Techniques page, kept
// beside the editor so you don't have to leave the hunt to consult it.
function TechniqueRail({ t }: { t: Technique }) {
  return (
    <div className="mx-4 mb-2 rounded-md border border-conf-medium/25 bg-conf-medium/5 p-3">
      <div className="flex items-center gap-2">
        <span className="font-mono text-xs text-txt-2">{t.id}</span>
        <span className="text-sm font-medium">{t.name}</span>
        <a href={t.url} target="_blank" rel="noreferrer" className="text-txt-3 hover:text-accent">
          <ExternalLink size={12} />
        </a>
        <span className="ml-auto text-[11px] text-txt-3">{TACTIC_LABEL[t.tactic] ?? t.tactic}</span>
      </div>
      <p className="mt-1.5 text-xs text-txt-2">{t.summary}</p>
      <div className="mt-2 flex flex-wrap gap-1">
        {t.tables.map((tbl) => (
          <span key={tbl} className="rounded bg-surface3 px-1.5 py-0.5 font-mono text-[10px]
                                     text-amber-300/80">{tbl}</span>
        ))}
      </div>
      {t.variants.length > 0 && (
        <div className="mt-2 space-y-1">
          {t.variants.map((v) => (
            <div key={v.key} className="text-[11px]">
              <span className="text-txt">{v.label}</span>
              <span className="text-txt-2"> — {v.tells}</span>
              {v.defeats && (
                <span className="ml-1 inline-flex items-center gap-1 text-mal/80">
                  <ShieldOff size={10} /> defeats {v.defeats}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function Execute({ detail }: { detail: import('../lib/api').HuntDetail }) {
  const hunt = detail.hunt
  const qc = useQueryClient()
  const schema = useSchema()
  const { data: status } = useQuery({ queryKey: ['status'], queryFn: api.status })
  const { data: catalogue } = useQuery({ queryKey: ['techniques'], queryFn: api.techniques })
  const campaign = status?.campaigns.find((c) => c.slug === hunt.campaign_slug)
  const db = campaign?.db_name ?? ''

  // The technique this hunt was seeded from — drives the starter queries and the
  // reference rail, so the Execute phase opens on the right table, not a fixed
  // template.
  const primaryTech = useMemo(
    () => catalogue?.techniques.find((t) => t.id === hunt.techniques?.[0]),
    [catalogue, hunt.techniques],
  )
  const starters = useMemo(() => starterQueries(hunt, primaryTech), [hunt, primaryTech])

  const [csl, setCsl] = useState(() => headerCsl(hunt))
  // Once the catalogue resolves, seed the editor from the technique's best
  // starter — but only while the editor is still untouched, so it never clobbers
  // a query you've started writing.
  const seeded = useRef(false)
  useEffect(() => {
    if (!seeded.current && starters.length && csl === headerCsl(hunt)) {
      setCsl(starters[0].csl)
      seeded.current = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [starters])

  const [result, setResult] = useState<(QueryResult & { search_id?: string }) | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showRef, setShowRef] = useState(false)

  const run = useMutation({
    mutationFn: () => huntApi.search(hunt.id, db, csl),
    onSuccess: (r) => {
      setResult(r)
      setError(null)
      qc.invalidateQueries({ queryKey: ['hunt', hunt.id] })
    },
    onError: (e: Error) => {
      setError(e.message)
      setResult(null)
    },
  })

  const pin = useMutation({
    mutationFn: (row: Record<string, unknown>) =>
      huntApi.pin(hunt.id, row, result?.search_id ?? ''),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunt', hunt.id] }),
  })

  const pinnedItemIds = useMemo(
    () => new Set(detail.evidence.map((e) => e.item_id).filter(Boolean)),
    [detail.evidence],
  )

  return (
    <div className="flex h-full">
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="border-b border-line bg-surface2">
          <div className="flex items-center gap-2 px-4 py-1.5 text-xs text-txt-3">
            <span>{detail.searches.length} searches run · {db || 'no campaign db'}</span>
            {primaryTech && (
              <button
                onClick={() => setShowRef((s) => !s)}
                className="ml-auto flex items-center gap-1 rounded px-1.5 py-0.5 text-conf-medium
                           hover:bg-surface3"
              >
                <Lightbulb size={12} />
                {showRef ? 'Hide' : 'Show'} technique reference
              </button>
            )}
          </div>

          {/* #5 — the technique's guidance, on hand while you query. */}
          {showRef && primaryTech && <TechniqueRail t={primaryTech} />}

          {/* #4 — starter queries so you launch on the right table, not a blank
              editor. Clicking a chip loads it into the editor. */}
          {starters.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5 px-4 pb-2">
              <span className="text-[11px] text-txt-3">Starters:</span>
              {starters.map((s, i) => (
                <button
                  key={i}
                  onClick={() => setCsl(s.csl)}
                  className="rounded-full border border-line bg-surface px-2.5 py-0.5 font-mono
                             text-[11px] text-txt-2 hover:border-line2 hover:text-txt"
                >
                  {s.label}
                </button>
              ))}
            </div>
          )}

          <KqlEditor
            value={csl}
            onChange={setCsl}
            onRun={() => db && run.mutate()}
            running={run.isPending}
            tables={schema.tables}
            columns={schema.columns}
            columnTables={schema.columnTables}
          />
        </div>
        <div className="min-h-0 flex-1 bg-surface">
          <ResultsGrid
            result={result}
            error={error}
            onPin={(row) => pin.mutate(row)}
            pinnedKeys={pinnedItemIds}
          />
        </div>
      </div>

      {/* Evidence + findings rail */}
      <aside className="flex w-80 shrink-0 flex-col border-l border-line bg-surface">
        <EvidencePanel detail={detail} />
        <FindingsPanel detail={detail} />
      </aside>
    </div>
  )
}

function EvidencePanel({ detail }: { detail: import('../lib/api').HuntDetail }) {
  const qc = useQueryClient()
  const unpin = useMutation({
    mutationFn: (eid: string) => huntApi.unpin(eid),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunt', detail.hunt.id] }),
  })
  return (
    <div className="flex min-h-0 flex-1 flex-col border-b border-line">
      <div className="flex items-center gap-2 border-b border-line px-3 py-2">
        <Flag size={13} className="text-accent" />
        <span className="text-sm font-medium">Evidence</span>
        <span className="ml-auto text-xs text-txt-3">{detail.evidence.length}</span>
      </div>
      <div className="flex-1 overflow-auto">
        {detail.evidence.length === 0 && (
          <div className="p-3 text-xs text-txt-3">
            Flag result rows to collect evidence for a finding.
          </div>
        )}
        {detail.evidence.map((e) => (
          <div key={e.id} className="group border-b border-line/50 px-3 py-2">
            <div className="flex items-start justify-between gap-2">
              <span className="font-mono text-[10px] text-amber-300/80">{e.table_name}</span>
              <button
                onClick={() => unpin.mutate(e.id)}
                className="text-txt-3 opacity-0 hover:text-mal group-hover:opacity-100"
              >
                <Trash2 size={12} />
              </button>
            </div>
            <EvidenceSummary e={e} />
          </div>
        ))}
      </div>
    </div>
  )
}

function EvidenceSummary({ e }: { e: Evidence }) {
  // Show the two or three most identifying fields, not the whole row.
  const keys = ['Account', 'AccountName', 'UserPrincipalName', 'DeviceName', 'Computer',
    'ServiceName', 'ProcessCommandLine', 'FileName', 'RemoteUrl', 'TimeGenerated']
  const shown = keys.filter((k) => e.row[k] != null).slice(0, 3)
  return (
    <div className="mt-1 space-y-0.5">
      {shown.map((k) => (
        <div key={k} className="truncate font-mono text-[10px] text-txt-2" title={String(e.row[k])}>
          <span className="text-txt-3">{k}=</span>
          {String(e.row[k])}
        </div>
      ))}
    </div>
  )
}

function FindingsPanel({ detail }: { detail: import('../lib/api').HuntDetail }) {
  const qc = useQueryClient()
  const [adding, setAdding] = useState(false)
  const [title, setTitle] = useState('')
  const [technique, setTechnique] = useState('')
  const add = useMutation({
    mutationFn: () =>
      huntApi.addFinding(detail.hunt.id, {
        title, technique, confidence: 'high',
        evidence_ids: detail.evidence.map((e) => e.id),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['hunt', detail.hunt.id] })
      setAdding(false)
      setTitle('')
      setTechnique('')
    },
  })
  const del = useMutation({
    mutationFn: (fid: string) => huntApi.delFinding(fid),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunt', detail.hunt.id] }),
  })

  return (
    <div className="flex max-h-[45%] min-h-0 flex-col">
      <div className="flex items-center gap-2 border-b border-line px-3 py-2">
        <Target size={13} className="text-mal" />
        <span className="text-sm font-medium">Findings</span>
        <button
          onClick={() => setAdding((a) => !a)}
          className="ml-auto text-xs text-accent-light hover:underline"
        >
          + add
        </button>
      </div>
      <div className="flex-1 overflow-auto">
        {adding && (
          <div className="space-y-2 border-b border-line p-3">
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Finding title"
              className="w-full rounded border border-line bg-surface2 px-2 py-1 text-xs
                         outline-none focus:border-accent"
            />
            <input
              value={technique}
              onChange={(e) => setTechnique(e.target.value.toUpperCase())}
              placeholder="Technique (e.g. T1558.003)"
              className="w-full rounded border border-line bg-surface2 px-2 py-1 font-mono text-xs
                         outline-none focus:border-accent"
            />
            <button
              onClick={() => add.mutate()}
              disabled={!title || add.isPending}
              className="w-full rounded bg-accent px-2 py-1 text-xs font-medium text-black
                         disabled:opacity-40"
            >
              Add finding ({detail.evidence.length} evidence)
            </button>
            {add.isError && (
              <div className="text-[10px] text-mal">{(add.error as Error).message}</div>
            )}
          </div>
        )}
        {detail.findings.map((f) => (
          <div key={f.id} className="group border-b border-line/50 px-3 py-2">
            <div className="flex items-start justify-between gap-2">
              <span className="text-xs font-medium text-txt">{f.title}</span>
              <button
                onClick={() => del.mutate(f.id)}
                className="text-txt-3 opacity-0 hover:text-mal group-hover:opacity-100"
              >
                <Trash2 size={12} />
              </button>
            </div>
            <div className="mt-0.5 flex items-center gap-2 text-[10px] text-txt-3">
              {f.technique && (
                <span className="rounded bg-surface3 px-1.5 py-0.5 font-mono text-accent-light">
                  {f.technique}
                </span>
              )}
              <span>{f.confidence}</span>
              <span>{f.evidence_ids.length} evidence</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Act: write-up + detections ────────────────────────────────────────────

function Act({
  detail, showScore, setShowScore,
}: {
  detail: import('../lib/api').HuntDetail
  showScore: boolean
  setShowScore: (v: boolean) => void
}) {
  const hunt = detail.hunt
  const qc = useQueryClient()
  const [writeup, setWriteup] = useState(hunt.writeup)
  const [outcome, setOutcome] = useState(hunt.outcome || 'proven')
  const [saveOpen, setSaveOpen] = useState(false)
  const debriefRef = useRef<HTMLDivElement>(null)

  // When scoring is triggered from the header (any phase), scroll the debrief
  // into view so it's obvious it appeared.
  useEffect(() => {
    if (showScore) debriefRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, [showScore])

  const save = useMutation({
    mutationFn: () => huntApi.patch(hunt.id, { writeup, outcome }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunt', hunt.id] }),
  })

  // Suggest the last successful search as the detection query.
  const lastGood = [...detail.searches].reverse().find((s) => s.ok)

  return (
    <div className="mx-auto max-w-3xl overflow-auto px-6 py-8" style={{ height: '100%' }}>
      <h2 className="text-h2 text-txt">Write it up</h2>
      <p className="mt-1 text-sm text-txt-2">
        Record what you found, then save the query that found it as a detection.
      </p>

      <div className="mt-5 flex items-center gap-3">
        <span className="text-sm">Outcome</span>
        {['proven', 'disproven', 'inconclusive'].map((o) => (
          <button
            key={o}
            onClick={() => {
              setOutcome(o)
              save.mutate()
            }}
            className={`rounded-md px-3 py-1 text-xs transition ${
              outcome === o ? 'bg-surface3 text-txt' : 'bg-surface2 text-txt-2 hover:text-txt'
            }`}
          >
            {o}
          </button>
        ))}
      </div>

      <textarea
        value={writeup}
        onChange={(e) => setWriteup(e.target.value)}
        onBlur={() => save.mutate()}
        rows={8}
        placeholder="What did you hunt, what did you find, what would you do next?"
        className="mt-4 w-full rounded-md border border-line bg-surface2 px-3 py-2 text-sm
                   outline-none focus:border-accent"
      />

      <div className="mt-6 rounded-lg border border-line bg-surface2 p-4 shadow-card">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm font-medium">Detections</div>
            <div className="text-xs text-txt-3">
              Save a successful query as a reusable, ATT&CK-tagged detection with a Sigma export.
            </div>
          </div>
          <button
            onClick={() => setSaveOpen(true)}
            disabled={!lastGood}
            className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-black
                       hover:bg-accent-light disabled:opacity-40"
          >
            Save a detection
          </button>
        </div>
      </div>

      {saveOpen && lastGood && (
        <SaveDetectionDialog
          initialCsl={lastGood.csl}
          campaignSlug={hunt.campaign_slug}
          huntId={hunt.id}
          suggestedTechniques={hunt.techniques}
          onClose={() => setSaveOpen(false)}
        />
      )}

      {/* Debrief — reveal the score and answer key on demand. Kept behind a
          button because seeing the answer key ends the blind hunt. */}
      <div ref={debriefRef} className="mt-6 rounded-lg border border-line bg-surface2 p-4 shadow-card">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm font-medium">Score & debrief</div>
            <div className="text-xs text-txt-3">
              Grade this hunt against ground truth and reveal what was planted — what you caught,
              what fooled you, what you missed.
            </div>
          </div>
          {!showScore && (
            <button
              onClick={() => setShowScore(true)}
              className="flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-sm
                         font-medium text-black hover:bg-accent-light hover:shadow-glow active:scale-[0.98]"
            >
              <Trophy size={14} /> Score this hunt
            </button>
          )}
        </div>
        {!showScore && (
          <div className="mt-2 flex items-center gap-1.5 text-[11px] text-decoy">
            <Eye size={12} /> This reveals the answer key — do it when you're done hunting.
          </div>
        )}
        {showScore && <HuntDebrief huntId={hunt.id} />}
      </div>
    </div>
  )
}
