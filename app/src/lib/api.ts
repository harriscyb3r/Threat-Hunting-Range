// Typed client for the range backend.
//
// One deliberate shape: a rejected KQL query is NOT an error here. The backend
// returns 200 with {ok:false, error} for a bad query, because in a query editor
// the engine's own diagnostic is the thing the analyst learns from. So
// runQuery never throws on a semantic error — it returns a QueryResult with
// ok:false, and the Query Lab renders the message inline.

const BASE = '/api'

async function jsonOrThrow<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = body.detail ?? body.message ?? detail
    } catch {
      /* keep statusText */
    }
    throw new Error(`${res.status} ${detail}`)
  }
  return res.json() as Promise<T>
}

// ── Types ──────────────────────────────────────────────────────────────

export interface EngineStatus {
  engine: { url: string; up: boolean; databases: string[] }
  campaigns: CampaignRow[]
  drafter: string
}

export interface CampaignRow {
  slug: string
  display_name: string
  db_name: string
  kind: 'campaign' | 'clean_twin'
  twin_of: string | null
  status: 'empty' | 'building' | 'ready' | 'missing' | 'failed'
  attached: boolean
  created_at: number
}

export interface QueryResult {
  ok: boolean
  columns: string[]
  column_types: string[]
  rows: unknown[][]
  row_count: number
  elapsed_ms: number
  error?: { message: string; code: string | null }
}

export interface Candidate {
  id: string
  name: string
  tactic: string
  summary: string
  tables: string[]
  url: string
  score: number
  confidence: 'high' | 'medium' | 'low'
  reason: string
}

export interface ResolveResult {
  text: string
  ambiguous: boolean
  candidates: Candidate[]
}

export interface Variant {
  key: string
  label: string
  tells: string
  defeats: string
}

export interface Technique {
  id: string
  name: string
  tactic: string
  summary: string
  tables: string[]
  url: string
  has_emitter: boolean
  variants: Variant[]
}

export interface ScenarioStep {
  technique_id: string
  variant: string
  loudness: number
  day_offset: number
  params: Record<string, unknown>
  note: string
}

export interface ScenarioSpec {
  name: string
  hypothesis: string
  steps: ScenarioStep[]
  context_depth: 'isolated' | 'contextual' | 'full-chain'
  actor: string
  source: string
  seed_offset: number
  window_days: number
  target_events: number | null
  decoys: boolean
}

export interface AnswerKey {
  slug: string
  spec: ScenarioSpec
  steps: {
    technique_id: string
    technique_name: string
    variant: string
    variant_label: string
    loudness: number
    start: string
    rows: number
    labelled: number
    host: string
  }[]
  ground_truth: Record<string, number>
}

// ── Calls ──────────────────────────────────────────────────────────────

export interface TechniqueHit {
  id: string
  name: string
  tactic: string
  confidence: 'high' | 'medium' | 'low'
  reason: string
  has_emitter: boolean
}

export interface Draft {
  spec: ScenarioSpec
  actor: string
  techniques: TechniqueHit[]
  playable: string[]
  unresolved: string[]
  ioc_counts: { ips: number; domains: number; hashes: number }
  text_chars: number
}

export const api = {
  status: () => fetch(`${BASE}/range/status`).then(jsonOrThrow<EngineStatus>),

  // Total telemetry events per ready campaign db, keyed by db_name (null if a
  // db could not be counted). Shown next to each campaign in the Query Lab.
  campaignCounts: () =>
    fetch(`${BASE}/range/campaigns/counts`)
      .then(jsonOrThrow<{ counts: Record<string, number | null> }>),

  runQuery: (db: string, csl: string) =>
    fetch(`${BASE}/range/query`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ db, csl }),
    }).then(jsonOrThrow<QueryResult>),

  deleteCampaign: (slug: string) =>
    fetch(`${BASE}/range/campaigns/${slug}`, { method: 'DELETE' }).then(jsonOrThrow),

  resetCampaign: (slug: string) =>
    fetch(`${BASE}/range/campaigns/${slug}/reset`, { method: 'POST' }).then(jsonOrThrow),

  resolve: (text: string) =>
    fetch(`${BASE}/scenarios/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    }).then(jsonOrThrow<ResolveResult>),

  makeSpec: (technique_ids: string[], opts: Partial<{
    name: string; context_depth: string; loudness: number; window_days: number
  }> = {}) =>
    fetch(`${BASE}/scenarios/spec`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ technique_ids, ...opts }),
    }).then(jsonOrThrow<{ spec: ScenarioSpec; unresolved: string[] }>),

  draft: (text: string, opts: Partial<{ name: string; loudness: number; window_days: number }> = {}) =>
    fetch(`${BASE}/scenarios/draft`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, ...opts }),
    }).then(jsonOrThrow<Draft>),

  build: (body: {
    slug: string; spec: ScenarioSpec; seed?: number; preset?: string
    target_events?: number; with_twin?: boolean; reset?: boolean
  }) =>
    fetch(`${BASE}/scenarios/build`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }).then(jsonOrThrow<{ slug: string; status: string }>),

  techniques: () =>
    fetch(`${BASE}/scenarios/techniques`).then(
      jsonOrThrow<{ techniques: Technique[]; count: number; implemented: number }>,
    ),

  answerKey: (slug: string) =>
    fetch(`${BASE}/scenarios/campaigns/${slug}/answer-key`).then(jsonOrThrow<AnswerKey>),
}


export interface Hunt {
  id: string
  campaign_slug: string
  title: string
  hunt_type: string
  phase: 'prepare' | 'execute' | 'act' | 'closed'
  actor: string
  behavior: string
  location: string
  evidence_expected: string
  scope: string
  data_sources: string[]
  success_criteria: string
  techniques: string[]
  writeup: string
  outcome: string
  started_at: number | null
  created_at: number
  updated_at: number
}

export interface Search {
  id: string
  csl: string
  db_name: string
  row_count: number
  elapsed_ms: number
  ok: number
  ran_at: number
}

export interface Evidence {
  id: string
  hunt_id: string
  item_id: string
  table_name: string
  row: Record<string, unknown>
  note: string
  pinned_at: number
}

export interface Finding {
  id: string
  title: string
  technique: string
  confidence: string
  description: string
  evidence_ids: string[]
  created_at: number
}

export interface HuntDetail {
  hunt: Hunt
  searches: Search[]
  evidence: Evidence[]
  findings: Finding[]
}

export interface Detection {
  id: string
  hunt_id: string | null
  campaign_slug: string
  title: string
  csl: string
  techniques: string[]
  description: string
  fp_notes: string
  severity: string
  fp_count: number | null
  tp_count: number | null
  validated_at: number | null
  created_at: number
  updated_at: number
}

export interface SigmaResult {
  yaml: string
  complete: boolean
  warnings: string[]
  table: string
}

export interface ValidationResult {
  tp_count: number
  tp_item_ids: string[]
  fp_count: number
  twin_total_rows: number
  campaign_rows: number
  can_grade_tp: boolean
  error: string
  total_attack_events: number
  recall: number | null
}


export interface Score {
  hunt_id: string
  campaign_slug: string
  planted_techniques: string[]
  identified_techniques: string[]
  missed_techniques: string[]
  technique_recall: number
  evidence_total: number
  evidence_attack: number
  evidence_decoy: number
  evidence_noise: number
  evidence_benign: number
  precision: number
  attack_events_total: number
  attack_events_found: number
  event_recall: number
  started_at: number | null
  time_to_detection_s: number | null
  searches_total: number
  searches_to_first_tp: number | null
  rigor_checks: Record<string, boolean>
  rigor_score: number
  overall: number
  grade: string
  answer_key: {
    hypothesis: string
    steps: {
      technique_id: string
      technique_name: string
      variant: string
      variant_label: string
      host: string
      events: number
      identified: boolean
    }[]
    technique_events: Record<string, number>
    counts: Record<string, number>
  }
  decoys_fooled_by: { pattern: string; mimics: string | null; count: number }[]
}

export interface AttackEvent {
  time: string
  table: string
  account: string
  host: string
  detail: string
  item_id: string
  found: boolean
}

export interface AttackEvents {
  events: AttackEvent[]
  total: number
  found: number
  missed: number
}

export interface Scoreboard {
  hunts: {
    hunt_id: string; title: string; campaign_slug: string; phase: string
    outcome: string; overall: number; grade: string
    technique_recall: number; precision: number
    identified: string[]; missed: string[]; created_at: number
  }[]
  totals: {
    hunts: number; avg_score: number
    techniques_identified: string[]; techniques_with_detection: string[]
    detections: number
  }
}

export const huntApi = {
  list: (campaign?: string) =>
    fetch(`${BASE}/hunts${campaign ? `?campaign=${campaign}` : ''}`).then(
      jsonOrThrow<{ hunts: Hunt[] }>,
    ),
  create: (campaign_slug: string, title: string, hunt_type = 'hypothesis') =>
    fetch(`${BASE}/hunts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ campaign_slug, title, hunt_type }),
    }).then(jsonOrThrow<Hunt>),
  get: (id: string) => fetch(`${BASE}/hunts/${id}`).then(jsonOrThrow<HuntDetail>),
  patch: (id: string, fields: Partial<Hunt>) =>
    fetch(`${BASE}/hunts/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(fields),
    }).then(jsonOrThrow<Hunt>),
  del: (id: string) => fetch(`${BASE}/hunts/${id}`, { method: 'DELETE' }).then(jsonOrThrow),
  search: (id: string, db: string, csl: string) =>
    fetch(`${BASE}/hunts/${id}/search`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ db, csl }),
    }).then(jsonOrThrow<QueryResult & { search_id: string }>),
  pin: (id: string, row: Record<string, unknown>, search_id = '', note = '') =>
    fetch(`${BASE}/hunts/${id}/evidence`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ row, search_id, note }),
    }).then(jsonOrThrow<Evidence>),
  unpin: (evidenceId: string) =>
    fetch(`${BASE}/hunts/evidence/${evidenceId}`, { method: 'DELETE' }).then(jsonOrThrow),
  addFinding: (id: string, f: Partial<Finding>) =>
    fetch(`${BASE}/hunts/${id}/findings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(f),
    }).then(jsonOrThrow<Finding>),
  delFinding: (fid: string) =>
    fetch(`${BASE}/hunts/findings/${fid}`, { method: 'DELETE' }).then(jsonOrThrow),
  score: (id: string) => fetch(`${BASE}/hunts/${id}/score`).then(jsonOrThrow<Score>),
  scoreboard: () =>
    fetch(`${BASE}/hunts/scoreboard/summary`).then(jsonOrThrow<Scoreboard>),
  attackEvents: (id: string) =>
    fetch(`${BASE}/hunts/${id}/attack-events`).then(jsonOrThrow<AttackEvents>),
}

export const detectionApi = {
  list: (campaign?: string) =>
    fetch(`${BASE}/detections${campaign ? `?campaign=${campaign}` : ''}`).then(
      jsonOrThrow<{ detections: Detection[] }>,
    ),
  save: (body: Partial<Detection> & { title: string; csl: string }) =>
    fetch(`${BASE}/detections`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }).then(jsonOrThrow<Detection>),
  del: (id: string) => fetch(`${BASE}/detections/${id}`, { method: 'DELETE' }).then(jsonOrThrow),
  sigma: (id: string) =>
    fetch(`${BASE}/detections/${id}/sigma`).then(jsonOrThrow<SigmaResult>),
  sigmaPreview: (body: { title: string; csl: string; techniques?: string[]; severity?: string; fp_notes?: string }) =>
    fetch(`${BASE}/detections/sigma-preview`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }).then(jsonOrThrow<SigmaResult>),
  validate: (id: string) =>
    fetch(`${BASE}/detections/${id}/validate`, { method: 'POST' }).then(
      jsonOrThrow<ValidationResult>,
    ),
}

export interface LibraryCampaign {
  slug: string
  name: string
  actor: string
  difficulty: 'starter' | 'intermediate' | 'operator'
  tactic_summary: string
  description: string
  source: string
  techniques: string[]
  events: number
  built: boolean
}

export interface Lesson {
  id: string
  title: string
  objective: string
  concept: string
  starter: string
  task: string
  solution: string
  campaign: string
  tables: string[]
  completed: boolean
}

export interface CurriculumModule {
  id: string
  title: string
  sc200_area: string
  summary: string
  lessons: Lesson[]
}

export interface Curriculum {
  modules: CurriculumModule[]
  total_lessons: number
  completed: number
}

export const learnApi = {
  library: () => fetch(`${BASE}/library`).then(jsonOrThrow<{ campaigns: LibraryCampaign[] }>),
  librarySpec: (slug: string) =>
    fetch(`${BASE}/library/${slug}/spec`).then(
      jsonOrThrow<{ spec: ScenarioSpec; meta: LibraryCampaign }>),
  curriculum: () => fetch(`${BASE}/curriculum`).then(jsonOrThrow<Curriculum>),
  setProgress: (lessonId: string, completed: boolean) =>
    fetch(`${BASE}/curriculum/lessons/${lessonId}/progress`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ completed }),
    }).then(jsonOrThrow),
}

export const TACTIC_LABEL: Record<string, string> = {
  'initial-access': 'Initial Access',
  execution: 'Execution',
  persistence: 'Persistence',
  'privilege-escalation': 'Privilege Escalation',
  'defense-evasion': 'Defense Evasion',
  'credential-access': 'Credential Access',
  discovery: 'Discovery',
  'lateral-movement': 'Lateral Movement',
  'command-and-control': 'Command & Control',
  exfiltration: 'Exfiltration',
  impact: 'Impact',
}
