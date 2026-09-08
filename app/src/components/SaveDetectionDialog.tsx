// Save-a-detection modal, with a live Sigma preview. The preview is the point:
// it shows the analyst the Sigma equivalent — and, when the query uses
// summarize/join/etc., the warnings that say the translation is partial. Better
// to see "this is incomplete, finish it by hand" than to save a rule that looks
// done and isn't.

import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { X, Loader2, AlertTriangle, Check, Copy } from 'lucide-react'
import { detectionApi } from '../lib/api'
import { useToast } from './toast'

const SEVERITIES = ['informational', 'low', 'medium', 'high', 'critical']

export function SaveDetectionDialog({
  initialCsl, campaignSlug, huntId, suggestedTechniques, onClose,
}: {
  initialCsl: string
  campaignSlug: string
  huntId?: string
  suggestedTechniques?: string[]
  onClose: () => void
}) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [title, setTitle] = useState('')
  const [csl] = useState(initialCsl)
  const [techniques, setTechniques] = useState((suggestedTechniques ?? []).join(', '))
  const [severity, setSeverity] = useState('medium')
  const [fpNotes, setFpNotes] = useState('')
  const [copied, setCopied] = useState(false)

  const techList = techniques.split(',').map((t) => t.trim().toUpperCase()).filter(Boolean)

  const preview = useMutation({
    mutationFn: () =>
      detectionApi.sigmaPreview({ title: title || 'Untitled', csl, techniques: techList, severity, fp_notes: fpNotes }),
  })
  // Re-preview when the inputs change.
  useEffect(() => {
    const t = setTimeout(() => preview.mutate(), 250)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [title, techniques, severity, fpNotes])

  const save = useMutation({
    mutationFn: () =>
      detectionApi.save({
        title, csl, campaign_slug: campaignSlug, hunt_id: huntId,
        techniques: techList, severity, fp_notes: fpNotes,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['detections'] })
      toast({ kind: 'success', title: 'Detection saved',
              description: 'Validate it against the clean twin on the Detections page.' })
      onClose()
    },
    onError: (e: Error) =>
      toast({ kind: 'error', title: "Couldn't save detection", description: e.message }),
  })

  const sigma = preview.data

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6">
      <div className="flex max-h-[85vh] w-full max-w-4xl overflow-hidden rounded-xl border
                      border-line2 bg-surface shadow-2xl">
        {/* Left: form */}
        <div className="flex w-1/2 flex-col overflow-auto border-r border-line p-5">
          <div className="mb-4 flex items-center justify-between">
            <h3 className="text-sm font-semibold">Save detection</h3>
            <button onClick={onClose} className="text-txt-3 hover:text-txt">
              <X size={16} />
            </button>
          </div>
          <div className="space-y-3 text-sm">
            <Labeled label="Title">
              <input
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="What this detection catches"
                autoFocus
                className="w-full rounded border border-line bg-surface2 px-2 py-1.5 outline-none
                           focus:border-accent"
              />
            </Labeled>
            <Labeled label="ATT&CK techniques">
              <input
                value={techniques}
                onChange={(e) => setTechniques(e.target.value)}
                placeholder="T1558.003, T1021.006"
                className="w-full rounded border border-line bg-surface2 px-2 py-1.5 font-mono text-xs
                           outline-none focus:border-accent"
              />
            </Labeled>
            <Labeled label="Severity">
              <div className="flex gap-1">
                {SEVERITIES.map((s) => (
                  <button
                    key={s}
                    onClick={() => setSeverity(s)}
                    className={`rounded px-2 py-1 text-[11px] capitalize transition ${
                      severity === s ? 'bg-surface3 text-txt' : 'bg-surface2 text-txt-2'
                    }`}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </Labeled>
            <Labeled label="False-positive notes">
              <textarea
                value={fpNotes}
                onChange={(e) => setFpNotes(e.target.value)}
                rows={2}
                placeholder="What benign activity might trip this, and how to tune it out"
                className="w-full rounded border border-line bg-surface2 px-2 py-1.5 text-xs
                           outline-none focus:border-accent"
              />
            </Labeled>
            <Labeled label="Query">
              <pre className="max-h-32 overflow-auto rounded border border-line bg-surface2 p-2
                              font-mono text-[11px] text-txt-2">{csl}</pre>
            </Labeled>
          </div>
          <button
            onClick={() => save.mutate()}
            disabled={!title || save.isPending}
            className="mt-4 flex items-center justify-center gap-2 rounded-md bg-accent px-4 py-2
                       text-sm font-medium text-black hover:bg-accent-light disabled:opacity-40"
          >
            {save.isPending ? <Loader2 size={15} className="animate-spin" /> : <Check size={15} />}
            Save detection
          </button>
        </div>

        {/* Right: Sigma preview */}
        <div className="flex w-1/2 flex-col overflow-hidden">
          <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
            <span className="text-sm font-medium">Sigma preview</span>
            {sigma && (
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
            )}
          </div>
          {sigma && !sigma.complete && (
            <div className="flex items-start gap-2 border-b border-line bg-decoy/5 px-4 py-2
                            text-[11px] text-decoy">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" />
              <div>
                <div className="font-medium">Partial translation — finish by hand.</div>
                {sigma.warnings.slice(0, 3).map((w, i) => (
                  <div key={i} className="mt-0.5 text-decoy/80">{w}</div>
                ))}
              </div>
            </div>
          )}
          <pre className="flex-1 overflow-auto bg-surface2 p-4 font-mono text-[11px] text-txt-2">
            {preview.isPending ? 'Rendering…' : sigma?.yaml ?? ''}
          </pre>
        </div>
      </div>
    </div>
  )
}

function Labeled({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-[11px] uppercase tracking-wide text-txt-3">{label}</span>
      {children}
    </label>
  )
}
