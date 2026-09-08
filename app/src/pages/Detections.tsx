// Saved detections, each validatable against the clean twin. The validation
// result is the honest scorecard: true positives on the campaign (does it catch
// the attack?) and false positives on the twin (does it fire on benign
// activity?). A detection that catches the attacker but lights up the twin is a
// pager at 3am, and this page makes that visible.

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ShieldCheck, Trash2, FlaskConical, Loader2, Code2, X, Copy, Check,
  AlertTriangle, TrendingUp, TrendingDown,
} from 'lucide-react'
import { detectionApi, type Detection, type ValidationResult, type SigmaResult } from '../lib/api'
import { EmptyState, CardSkeletons } from '../components/ui'
import { useToast } from '../components/toast'

// Filled-dot + tint per severity, so the level registers at a glance.
const SEV_CLASS: Record<string, { dot: string; pill: string }> = {
  critical: { dot: 'bg-mal', pill: 'bg-mal/10 text-mal' },
  high: { dot: 'bg-mal/80', pill: 'bg-mal/10 text-mal/90' },
  medium: { dot: 'bg-decoy', pill: 'bg-decoy/10 text-decoy' },
  low: { dot: 'bg-conf-low', pill: 'bg-surface3 text-conf-low' },
  informational: { dot: 'bg-txt-3', pill: 'bg-surface3 text-txt-3' },
}

export function Detections() {
  const { data, isLoading } = useQuery({ queryKey: ['detections'], queryFn: () => detectionApi.list() })
  const detections = data?.detections ?? []

  if (!isLoading && detections.length === 0) {
    return (
      <EmptyState
        icon={<ShieldCheck size={26} />}
        title="No detections saved yet"
        hint="Complete a hunt and save the query that found something."
      />
    )
  }

  return (
    <div className="mx-auto flex h-full max-w-3xl flex-col overflow-auto px-6 py-8">
      <h1 className="text-h1 text-txt">Detections</h1>
      <p className="mt-1 text-sm text-txt-2">
        {detections.length} saved. Validate a detection to measure it against the campaign (true
        positives) and its clean twin (false positives).
      </p>
      <div className="mt-5 space-y-3">
        {isLoading
          ? <CardSkeletons count={3} />
          : detections.map((d) => <DetectionCard key={d.id} d={d} />)}
      </div>
    </div>
  )
}

function DetectionCard({ d }: { d: Detection }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [validation, setValidation] = useState<ValidationResult | null>(null)
  const [sigma, setSigma] = useState<SigmaResult | null>(null)
  const [showSigma, setShowSigma] = useState(false)

  const validate = useMutation({
    mutationFn: () => detectionApi.validate(d.id),
    onSuccess: (r) => {
      setValidation(r)
      qc.invalidateQueries({ queryKey: ['detections'] })
      toast({
        kind: r.fp_count === 0 ? 'success' : 'info',
        title: r.fp_count === 0 ? 'Clean on the twin' : `${r.fp_count} false positives`,
        description: r.fp_count === 0
          ? 'This detection did not fire on benign activity.'
          : 'Fires on benign rows — tune it before enabling.',
      })
    },
    onError: (e: Error) =>
      toast({ kind: 'error', title: 'Validation failed', description: e.message }),
  })
  const loadSigma = useMutation({
    mutationFn: () => detectionApi.sigma(d.id),
    onSuccess: (r) => {
      setSigma(r)
      setShowSigma(true)
    },
  })
  const del = useMutation({
    mutationFn: () => detectionApi.del(d.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['detections'] }),
  })

  const sev = SEV_CLASS[d.severity] ?? SEV_CLASS.informational
  return (
    <div className="rounded-lg border border-line/70 bg-surface2 p-4 shadow-card transition-all
                    duration-200 hover:border-line2 hover:shadow-raised">
      <div className="flex items-start justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-txt">{d.title}</span>
            <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[10px]
                              capitalize ${sev.pill}`}>
              <span className={`h-1.5 w-1.5 rounded-full ${sev.dot}`} />
              {d.severity}
            </span>
          </div>
          {d.description && <div className="mt-0.5 text-xs text-txt-2">{d.description}</div>}
          <div className="mt-1.5 flex flex-wrap gap-1">
            {d.techniques.map((t) => (
              <span key={t} className="rounded bg-surface3 px-1.5 py-0.5 font-mono text-[10px]
                                       text-accent-light">
                {t}
              </span>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={() => loadSigma.mutate()}
            title="View Sigma"
            className="rounded p-1.5 text-txt-3 hover:bg-surface3 hover:text-txt"
          >
            {loadSigma.isPending ? <Loader2 size={15} className="animate-spin" /> : <Code2 size={15} />}
          </button>
          <button
            onClick={() => validate.mutate()}
            disabled={validate.isPending}
            title="Validate against the clean twin"
            className="flex items-center gap-1.5 rounded-md bg-surface3 px-3 py-1.5 text-xs
                       text-txt hover:bg-line2 disabled:opacity-40"
          >
            {validate.isPending ? (
              <Loader2 size={13} className="animate-spin" />
            ) : (
              <FlaskConical size={13} />
            )}
            Validate
          </button>
          <button
            onClick={() => del.mutate()}
            className="rounded p-1.5 text-txt-3 hover:bg-surface3 hover:text-mal"
          >
            <Trash2 size={15} />
          </button>
        </div>
      </div>

      <pre className="mt-3 max-h-24 overflow-auto rounded border border-line bg-surface p-2
                      font-mono text-[11px] text-txt-2">{d.csl}</pre>

      {validate.isError && (
        <div className="mt-2 text-xs text-mal">{(validate.error as Error).message}</div>
      )}
      {validation && <ValidationPanel v={validation} fpNotes={d.fp_notes} />}

      {showSigma && sigma && (
        <SigmaModal sigma={sigma} onClose={() => setShowSigma(false)} />
      )}
    </div>
  )
}

function ValidationPanel({ v, fpNotes }: { v: ValidationResult; fpNotes: string }) {
  const fpRate = v.twin_total_rows
  return (
    <div className="mt-3 rounded-md border border-line bg-surface p-3">
      <div className="grid grid-cols-3 gap-3 text-center">
        <Metric
          icon={TrendingUp}
          label="True positives"
          value={v.can_grade_tp ? `${v.tp_count}/${v.total_attack_events}` : '—'}
          sub={v.recall != null ? `${(v.recall * 100).toFixed(0)}% recall` : 'not gradable'}
          good={v.can_grade_tp && v.tp_count > 0}
        />
        <Metric
          icon={TrendingDown}
          label="False positives"
          value={String(fpRate)}
          sub="hits on the clean twin"
          good={fpRate === 0}
          bad={fpRate > 0}
        />
        <Metric
          icon={ShieldCheck}
          label="On campaign"
          value={String(v.campaign_rows)}
          sub="total rows returned"
        />
      </div>
      {!v.can_grade_tp && (
        <div className="mt-2 flex items-start gap-1.5 text-[11px] text-txt-3">
          <AlertTriangle size={12} className="mt-0.5 shrink-0 text-decoy" />
          This query aggregates rows away, so individual true positives can't be graded against
          ground truth. False-positive volume on the twin is still measured.
        </div>
      )}
      {fpRate > 0 && (
        <div className="mt-2 text-[11px] text-decoy">
          Fires on {fpRate} benign row{fpRate === 1 ? '' : 's'} — tune it before enabling.
          {fpNotes && <span className="text-txt-3"> ({fpNotes})</span>}
        </div>
      )}
    </div>
  )
}

function Metric({
  icon: Icon, label, value, sub, good, bad,
}: {
  icon: typeof TrendingUp; label: string; value: string; sub: string
  good?: boolean; bad?: boolean
}) {
  const color = good ? 'text-good' : bad ? 'text-mal' : 'text-txt'
  return (
    <div>
      <div className="flex items-center justify-center gap-1 text-[10px] uppercase tracking-wide text-txt-3">
        <Icon size={11} />
        {label}
      </div>
      <div className={`mt-1 text-h1 text-txt ${color}`}>{value}</div>
      <div className="text-[10px] text-txt-3">{sub}</div>
    </div>
  )
}

function SigmaModal({ sigma, onClose }: { sigma: SigmaResult; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6"
         onClick={onClose}>
      <div
        onClick={(e) => e.stopPropagation()}
        className="flex max-h-[85vh] w-full max-w-2xl flex-col overflow-hidden rounded-xl
                   border border-line2 bg-surface shadow-2xl"
      >
        <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
          <span className="text-sm font-medium">Sigma rule</span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                navigator.clipboard.writeText(sigma.yaml)
                setCopied(true)
                setTimeout(() => setCopied(false), 1500)
              }}
              className="flex items-center gap-1 text-xs text-txt-2 hover:text-txt"
            >
              {copied ? <Check size={12} /> : <Copy size={12} />}
              {copied ? 'copied' : 'copy'}
            </button>
            <button onClick={onClose} className="text-txt-3 hover:text-txt">
              <X size={16} />
            </button>
          </div>
        </div>
        {!sigma.complete && (
          <div className="flex items-start gap-2 border-b border-line bg-decoy/5 px-4 py-2
                          text-[11px] text-decoy">
            <AlertTriangle size={13} className="mt-0.5 shrink-0" />
            <span>Partial translation — this rule needs completing by hand before use.</span>
          </div>
        )}
        <pre className="flex-1 overflow-auto bg-surface2 p-4 font-mono text-[11px] text-txt-2">
          {sigma.yaml}
        </pre>
      </div>
    </div>
  )
}
