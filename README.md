# Kusto Threat Hunting Range

A local, CTI-driven threat hunting range running a **real Kusto engine**, with schema-faithful
Microsoft telemetry (native + ASIM), PEAK-aligned hunt campaigns mapped to MITRE ATT&CK, and
objective hunt scoring.

Describe a behaviour — *"kerberoasting"*, *"pass the hash then WMI lateral movement then
ransomware"* — or paste a CTI report, and the range builds a campaign: a seeded organisation with
a plausible baseline, ambient noise, technique-specific decoys, and the attack chain hidden
inside it. Then you hunt it in KQL, blind, and get graded against ground truth.

Runs entirely offline. No cloud account, no Azure subscription, no API key, **no paid API calls**.

[![License: MIT](https://img.shields.io/badge/License-MIT-informational.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB.svg?logo=python&logoColor=white)
![Node 18+](https://img.shields.io/badge/Node-18%2B-339933.svg?logo=nodedotjs&logoColor=white)
![Docker Compose v2](https://img.shields.io/badge/Docker-Compose%20v2-2496ED.svg?logo=docker&logoColor=white)
![ATT&CK coverage](https://img.shields.io/badge/ATT%26CK-44%20techniques%20%C2%B7%20131%20variants-C22E2E.svg)
![Runtime cost](https://img.shields.io/badge/runtime%20cost-%240.00-success.svg)

**Contents** — [Prerequisites](#prerequisites) · [Quick start](#quick-start) ·
[Verify](#verify) · [What the range contains](#what-the-range-contains) ·
[Hunt something](#hunt-something) · [The app](#the-app) · [Attacks](#attacks) ·
[Gotchas](#three-things-that-will-bite-you-if-you-forget-them) · [API](#api) ·
[Layout](#layout) · [Troubleshooting](#troubleshooting) · [License](#license)

Build plan and design rationale: [PLAN.md](PLAN.md). UI design notes: [UI-POLISH.md](UI-POLISH.md).

---

## Prerequisites

The range runs three things locally — the Kusto engine in Docker, a Python API, and a
Vite/React UI — so you need:

| Tool | Version | Why |
|---|---|---|
| **Docker** with **Compose v2** | any current release | Runs the real Kusto engine (`kustainer-linux`). The `docker compose` command must work — it ships with Docker Desktop and modern Docker Engine. |
| **Python** | 3.11+ (3.13 verified) | The FastAPI backend. Includes `pip` and `venv`. |
| **Node.js** | 18+ (20 LTS or newer recommended) | The Vite 6 / React 18 frontend. Includes `npm`. |
| **Git** | any | To clone the repo. |

That's the whole list — **no cloud account, Azure subscription, API key, or paid service is
required.** Everything runs on your machine, offline.

A few things worth knowing before the first run:

- **Give Docker a few GB of memory.** The Kusto engine is the heavy component; Docker Desktop's
  default is usually fine, but under ~4 GB the engine can fail to start. The first
  `docker compose up` pulls the image (a few hundred MB), so it takes a minute.
- **The engine image is `linux/amd64` only.** Windows, Linux x86-64, and Intel Macs run it
  natively. On Apple Silicon (M-series) Macs it runs under emulation — install Rosetta and turn on
  *Use Rosetta for x86/amd64 emulation* in Docker Desktop → Settings → General.
- **These ports must be free:** `8080` (engine), `8780` (API), `5175` (UI). If `5175` is taken,
  Vite automatically picks the next free port and prints it.

---

## Quick start

```bash
git clone https://github.com/<your-username>/hunting-range.git
cd hunting-range

docker compose up -d                      # 1. start the Kusto engine

cd backend                                # 2. start the API
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt
.venv/Scripts/python -m uvicorn main:app --port 8780 --reload

cd ../app                                 # 3. start the UI
npm install
npm run dev
```

Then open the app at <http://localhost:5175> (API docs at <http://127.0.0.1:8780/docs>).

> **Windows vs. macOS/Linux paths.** The commands above use the Windows virtualenv layout
> (`.venv/Scripts/python`). On macOS/Linux the interpreter is at `.venv/bin/python` — either use
> that path, or run `source .venv/bin/activate` once and then plain `python`/`uvicorn`.

Configuration is optional: every setting has a working default. To change one, copy
[`backend/.env.example`](backend/.env.example) to `backend/.env`, or set the equivalent
`RANGE_`-prefixed environment variable.

To run the backend in a container too — no host Python needed:

```bash
docker compose --profile app up -d        # Kusto + backend; the UI still runs on the host
```

## Verify

```bash
cd backend
.venv/Scripts/python test_phase0.py       # full check, incl. container restart (~18s)
.venv/Scripts/python test_phase0.py --skip-restart
.venv/Scripts/python test_phase1.py       # schemas, generators, ASIM (~90s)
.venv/Scripts/python test_phase1.py --events 40000
.venv/Scripts/python probe.py             # 25 KQL capability checks
```

`test_phase2.py`, `test_phase4.py`, `test_phase6.py` and `test_coverage_emitters.py` cover the
attack emitters, the PEAK workspace, scoring, and emitter coverage respectively.

Run `probe.py` after any `docker pull` of the engine image. It is pinned to `:latest`, and the
curriculum depends on features — `autocluster`, `basket`, `diffpatterns` — that PEAK Baseline and
Model-Assisted hunts cannot work without.

---

## Status — all 7 phases complete

| | |
|---|---|
| ✅ **0** | Scaffold, compose, Kusto client, campaign registry, **startup reconciler** |
| ✅ **1** | 20 table schemas, 13 ASIM parsers, org model, benign generators + noise, batched ingest |
| ✅ **2** | 44 attack emitters (131 variants), decoys, resolver, campaign build/reset, clean twin |
| ✅ **3** | Query Lab, behaviour-first Scenarios, technique catalogue, campaigns + Study mode |
| ✅ **4** | PEAK workspace, evidence & findings, detections, Sigma export, twin validation |
| ✅ **5** | Actor-first CTI paste → local drafter (actor + kill chain + IOCs) |
| ✅ **6** | Hunt scoring, answer-key debrief, scoreboard + ATT&CK coverage |
| ✅ **7** | 8 library campaigns + 16-lesson SC-200-aligned KQL curriculum |

---

## What the range contains

**20 Microsoft tables** with real column names and types — Entra/M365 (6), Defender XDR (8),
Windows Security + Sysmon (2), DNS/firewall/IIS/NSG (4). 746 columns, each schema carrying a docs
URL so the subset can be re-checked against upstream.

**13 ASIM parsers**, built the way Sentinel does it: per-source `vim*` functions with defaulted
filtering parameters, unioned by `_Im_Authentication`, `_Im_ProcessCreate`, `_Im_Dns` and
`_Im_NetworkSession`. Each is verified to reconcile exactly against its native sources, so the
same data can be hunted both ways and the ASIM habits transfer to a real tenant. Three small
deviations are forced by the emulator and documented at the top of each `.kql` file.

**A seeded organisation** — people across departments and timezones, their devices, service
accounts, domain controllers and business rhythm. Three presets ship: `smb` (46 users), `midsize`
(206, the default) and `enterprise` (1006). `(preset, seed)` fully determines it, so a campaign
rebuilds identically and a detection can be re-tested against the same ground.

**A baseline that is hard to hunt.** Events cluster in each user's *local* working hours; ~12% of
sign-ins fail for entirely benign reasons; ~28% of 4688 events carry no command line because
audit policy was never configured; RC4 Kerberos tickets exist but are a minority. On top of that
sit six deliberate benign anomalies:

| Pattern | The query it defeats |
|---|---|
| Developer running `-EncodedCommand` daily | `ProcessCommandLine has "-enc"` |
| IT using PsExec and WMI at 2am on patch nights | admin tooling outside business hours |
| Sunday vulnerability scan authenticating to every host | one account touching many hosts |
| Backup agent bulk-reading a file share overnight | mass file access by one account |
| Executive genuinely working from Singapore | impossible travel |
| Inventory tool enumerating SPNs and Domain Admins | SPN enumeration / AD recon |

Each is labelled in ground truth, so a hunt that trips over one is told *which* pattern fooled it
rather than just being marked wrong.

## Hunt something

Behaviour-first — describe what you want to practise:

```bash
cd backend
# One technique
python -m generators.campaign_cli kerberoast-drill "kerberoasting" --twin

# Ambiguous - the resolver makes you choose
python -m generators.campaign_cli wmi-hunt "WMI abuse"          # lists the 3 readings
python -m generators.campaign_cli wmi-hunt "WMI abuse" --pick T1047

# A whole chain, ordered along the kill chain automatically
python -m generators.campaign_cli intrusion \
    "pass the hash then wmi lateral movement then ransomware" --twin

# Just a benign baseline, no attack
python -m generators.cli demo --events 300000
```

Or drive it over HTTP the way the UI does: `POST /api/scenarios/resolve` → `/spec` → `/build`,
then `POST /api/range/query` to hunt and `/api/scenarios/campaigns/{slug}/answer-key` for Study
mode.

## The app

Nine pages, all driving the API below.

**Home** — the front door. Engine and campaign status, hunts in flight, recent scores and
coverage at a glance, and the shortest path back to whatever you were doing.

**Hunt** — the Query Lab. A schema browser (20 tables by family, ASIM parsers, click-to-insert,
Microsoft-docs links), a custom KQL editor with syntax highlighting and schema-aware completion, a
virtualized results grid, query history, and a **native↔ASIM toggle** that rewrites the leading
table to its `_Im_*` parser and back. A rejected query renders the engine's own diagnostic inline,
because that message is the thing you learn from. The editor is hand-rolled rather than Monaco: a
transparent textarea over a highlighted layer plus our own tokenizer over the table registry —
~200 lines instead of a megabyte of AMD bundle that fights Vite.

**Scenarios** — two ways to build a campaign. **Behaviour-first**: type "WMI abuse", get ranked
candidates, and when it's ambiguous you must choose (three different hunts). **Actor-first**: paste
a CTI report or actor profile and it extracts the ATT&CK techniques it names, the actor, and IOC
counts, then drafts a full kill-chain campaign — all locally, no data leaves the machine. Either
way you review and edit the spec before generating, and the clean twin builds alongside.

**Techniques** — the catalogue. Every emitter grouped by tactic, expandable to its variants,
each variant showing its telemetry tells and — the point — **what naive query it defeats**.

**Campaigns** — what's built, live build status, **Study mode** (a hunt is blind by default —
the toggle reveals the answer key: planted steps, variants, and attack/decoy/noise counts), and
the list of PEAK hunts against each campaign.

**The PEAK workspace** (one hunt, at `/hunt/:id`) — **Prepare** an ABLE hypothesis (Actor,
Behavior, Location, Evidence; the phase gate won't let you start querying until all four are
filled), **Execute** with the same KQL editor — every query auto-logged as a search, result rows
pinned as evidence, evidence promoted to technique-tagged findings — then **Act**: write it up and
save the query that found something as a detection.

**Detections** — saved detections, each with a **Sigma export** (SigmaHQ YAML, honestly marked
DRAFT and warned when the query uses constructs Sigma can't express) and **validation**: run it
against the campaign for true positives and the clean twin for false positives. A detection that
fires on the twin is a 3am page — the scorecard makes that visible before you'd ever ship it.

**Score & debrief** (in a hunt's Act phase) — grade the hunt against ground truth: technique
recall, precision (were you fooled by a decoy?), time to first true find, searches to find it,
and a rigor checklist for following the method. Then it reveals the **answer key** — what was
actually planted, which variant, on which host, and for each planted technique whether you
caught it or missed it. Kept behind a button, because seeing the answer key ends the blind hunt.

**Scoreboard** — your hunt history with grades, average score, and an **ATT&CK coverage map**:
which techniques you've identified in a scored hunt (green) and which you have a saved detection
for (accent) — the portfolio view of what you can actually hunt.

**Learn** — 8 library campaigns from starter to operator, plus a 16-lesson KQL curriculum in 6
modules aligned to the KQL-heavy objectives of Microsoft **SC-200**. Every lesson query runs
against a real campaign in the range rather than being read off a page, and progress is tracked.

## Attacks

Every campaign layers four things onto the same org and time window:

```
benign baseline  +  ambient noise  +  technique decoys  +  the attack chain
```

**44 technique emitters, 131 variants.** Each technique ships several ways of performing itself,
and the builder picks one you are not told. The variants are where the training lives — several
exist specifically to break the obvious query:

| Technique | A variant that breaks the naive query |
|---|---|
| Kerberoasting (T1558.003) | `targeted` — one 4769, defeats `count() > threshold`; `aes_only` — no RC4, defeats `TicketEncryptionType == "0x17"` |
| LSASS dump (T1003.001) | `taskmgr` — GUI dump, no command line to match at all |
| Pass-the-hash (T1550.002) | `overpass` — converts the hash to a Kerberos TGT, defeats `AuthenticationPackageName == "NTLM"` |
| WMI execution (T1047) | `powershell_cim` — CIM cmdlets, no `wmic.exe` |
| HTTP C2 (T1071.001) | `jittered_beacon` — interval varies ±30%, defeats exact-interval detection |

Re-roll the same hunt and the variants change, so a detection only scores well if it generalises.

**Decoys** are benign activity that resembles *the specific technique being hunted*. Hunt
kerberoasting and the SCCM and backup service accounts' legitimate bulk RC4 tickets are planted
too; a naive `4769 | where TicketEncryptionType == "0x17"` returns them alongside the attacker.
Each decoy is labelled in ground truth, so scoring can name which lookalike fooled you.

**"WMI abuse" is three hunts.** The resolver returns ranked candidates rather than one answer, and
makes you choose — T1047 (execution), T1021.006 (lateral movement) or T1546.003 (persistence).
The choice is the point.

**The clean twin** is the same benign baseline and decoys with the attack removed. A saved
detection's false-positive rate against the twin is its FP rate against this org's real behaviour —
run it from the Detections page and see the true-positive and false-positive counts side by side.

## Three things that will bite you if you forget them

**1. The volume must stay a named volume.** `docker-compose.yml` uses `hr_kusto:/kustodata`, not a
host path. On Windows, Git Bash rewrites `-v /c/…/kusto:/kustodata` into a mount at
`\Program Files\Git\kustodata`; the engine then writes to the wrong place and every campaign
disappears on the next `docker compose down`, with no error anywhere.

**2. Persisted databases are not auto-attached.** Recreate the container and `.show databases`
lists only `NetDefaultDB` — every campaign is still on the volume, intact and invisible. Each one
has to be re-attached explicitly:

```
.attach database <name> from @"/kustodata/dbs/<name>/gen1/md"
```

The backend does this at startup (`main.py` lifespan → `kusto.admin.reconcile`), driven by the
SQLite campaign registry rather than a disk scan — the backend may be running on the host with no
access to the volume at all. A dropped campaign therefore stays dropped: orphaned files are never
resurrected because nothing references them.

`test_phase0.py` asserts the *absence* of auto-attach. If that assertion ever fails, the emulator
gained the behaviour and the reconciler stopped being load-bearing.

**3. `.drop database` does not delete anything — it detaches.** The files stay on the volume and
`.attach` brings the rows straight back. Creating a database over an occupied path fails
outright, which is why persist paths carry a generation (`.../gen3/md`) and a reset moves to
the next one. Deleting a campaign reports what it actually did: detached, and whether the
files could be purged. To reclaim disk properly, `docker compose down -v`.

---

## API

Interactive docs at <http://127.0.0.1:8780/docs> once the backend is up.

**Range**

| | |
|---|---|
| `GET /api/health` | Liveness + engine reachability |
| `GET /api/range/status` | Engine state, databases, campaigns, drafter mode |
| `GET /api/range/schema` | The 20 table schemas + ASIM parsers, for the schema browser |
| `GET /api/range/campaigns/counts` | Row counts per campaign |
| `POST /api/range/reconcile` | Re-attach registered databases on demand |
| `POST /api/range/campaigns` | Create a campaign database (+ clean twin) |
| `POST /api/range/campaigns/{slug}/reset` | Empty a campaign to a fresh persist generation |
| `DELETE /api/range/campaigns/{slug}` | Drop a campaign and its twin |
| `POST /api/range/query` | Run KQL. Seed of the Query Lab |

**Scenarios**

| | |
|---|---|
| `POST /api/scenarios/resolve` | Free text → ranked ATT&CK candidates |
| `POST /api/scenarios/draft` | CTI text → actor, kill chain, IOCs (local drafter) |
| `POST /api/scenarios/spec` | Technique ids → an editable ScenarioSpec |
| `POST /api/scenarios/build` | Build a campaign from a spec (background) |
| `GET /api/scenarios/techniques` | The technique catalogue + variants |
| `GET /api/scenarios/campaigns/{slug}/answer-key` | Study-mode reveal |

**Hunts (PEAK)**

| | |
|---|---|
| `GET` · `POST` `/api/hunts` | List / create hunts |
| `GET` · `PATCH` · `DELETE` `/api/hunts/{id}` | Read, update phase & hypothesis, delete |
| `POST /api/hunts/{id}/search` | Run KQL inside a hunt — auto-logged as a search |
| `POST /api/hunts/{id}/evidence` · `DELETE /api/hunts/evidence/{id}` | Pin / unpin result rows |
| `POST /api/hunts/{id}/findings` · `DELETE /api/hunts/findings/{id}` | Technique-tagged findings |
| `GET /api/hunts/{id}/score` | Grade against ground truth |
| `GET /api/hunts/{id}/attack-events` | Answer key: what was actually planted |
| `GET /api/hunts/scoreboard/summary` | History, averages, ATT&CK coverage |

**Detections**

| | |
|---|---|
| `GET` · `POST` `/api/detections` | List / save detections |
| `GET` · `DELETE` `/api/detections/{id}` | Read / delete one |
| `GET /api/detections/{id}/sigma` | SigmaHQ YAML export (marked DRAFT) |
| `POST /api/detections/sigma-preview` | Sigma for an unsaved query |
| `POST /api/detections/{id}/validate` | TP on the campaign, FP on the clean twin |

**Library & curriculum**

| | |
|---|---|
| `GET /api/library` · `GET /api/library/{slug}/spec` | The 8 shipped campaigns |
| `GET /api/curriculum` | 6 modules, 16 lessons, with progress |
| `POST /api/curriculum/lessons/{id}/progress` | Mark a lesson done |

`POST /api/range/query` returns **HTTP 200 with `ok: false`** for a rejected query, carrying
Kusto's own diagnostic:

```json
{"ok": false, "error": {"message": "Semantic error: SEM0100: 'where' operator: Failed to resolve
column or scalar expression named 'Nonexistent'", "code": "General_BadRequest"}}
```

A bad query is a normal event in a query editor, not a transport failure — and that message is
the thing an analyst learns from, so it is passed through untouched.

---

## Layout

```
docker-compose.yml       Kusto engine; backend under the `app` profile
data/                    SQLite registry (gitignored). Telemetry lives in the Docker volume
backend/
  .env.example           Every RANGE_ setting, documented
  Dockerfile             Backend image for `docker compose --profile app`
  config.py              RANGE_-prefixed settings
  deps.py                Shared KustoClient + Registry
  main.py                App, lifespan, startup reconciler
  kusto/client.py        /v1/rest/{query,mgmt}, result parsing, error extraction
  kusto/admin.py         Create/attach/detach/reset/reconcile, generation paths
  kusto/schemas/         20 Microsoft table definitions, by family
  kusto/asim/            13 ASIM parsers as .kql, plus the deployer
  kusto/ingest.py        KQL value serialisation, byte-sized batching
  org/                   Seeded organisation model and reference catalogue
  generators/            Benign emitters, noise, decoys, campaign builder, CLIs
  generators/attack/     44 technique emitters, 131 variants
  scenarios/             ATT&CK catalogue, resolver, ScenarioSpec, CTI drafter, library
  curriculum/lessons.py  6 modules, 16 SC-200-aligned lessons
  store/registry.py      Campaign registry — the reconciler's source of truth
  store/hunts.py         PEAK workspace: hunts, searches, evidence, findings, detections
  detections/sigma.py    KQL → Sigma (best-effort, honestly warned)
  detections/validate.py TP on the campaign, FP on the clean twin
  hunts/scoring.py       Grade a hunt vs ground truth; scoreboard aggregate
  hunts/reveal.py        Answer-key assembly
  routers/               range · scenarios · hunts · detections · curriculum
  probe.py               KQL capability regression test (25 checks)
  test_phase{0,1,2,4,6}.py, test_coverage_emitters.py
```

## App layout

```
app/
  src/lib/api.ts         Typed backend client
  src/lib/kql.ts         KQL tokenizer + keyword/function tables
  src/lib/useSchema.ts   Schema lookup for editor completion
  src/components/
    KqlEditor.tsx        Overlay-textarea editor with completion
    ResultsGrid.tsx      Virtualized results, sortable, pinnable
    SchemaBrowser.tsx    Tables by family, click-to-insert
    HuntDebrief.tsx      Score + answer key, shown in a hunt's Act phase
    SaveDetectionDialog.tsx
    ui.tsx  toast.tsx    Shared primitives
  src/pages/
    Dashboard.tsx        Home
    QueryLab.tsx         Hunt — the Query Lab
    Scenarios.tsx        Behaviour-first + actor-first builder
    Techniques.tsx       Catalogue
    Campaigns.tsx        List + Study mode + PEAK hunts
    Hunt.tsx             PEAK workspace (Prepare/Execute/Act)
    Detections.tsx       Saved detections + Sigma + twin validation
    Scoreboard.tsx       Hunt history, grades, ATT&CK coverage map
    Learn.tsx            Library campaigns + SC-200 curriculum
```

## Ports

| Port | Service |
|---|---|
| 8080 | Kusto engine |
| 8780 | Backend API |
| 5175 | Vite dev server |

---

## Troubleshooting

**`engine down` in the header, or the backend logs `kusto not reachable`.**
The backend starts anyway by design — a backend that refuses to boot because Docker is slow is
worse than one that reports the problem. Check `docker compose ps` and `docker compose logs kusto`.
A cold engine can take 30–60s to answer its first query.

**Every campaign vanished after `docker compose down`.**
Almost certainly the named-volume issue — see gotcha 1 above. Confirm with
`docker volume ls | grep hr_kusto`. If the volume is intact, the databases are detached rather
than gone: `POST /api/range/reconcile`, or just restart the backend.

**`.show databases` lists only `NetDefaultDB`.**
Expected after a container recreate. The startup reconciler re-attaches everything in the SQLite
registry — see gotcha 2 above.

**`probe.py` fails a check after a `docker pull`.**
The image is pinned to `:latest`, so an upstream change can remove a KQL feature the curriculum
depends on. Pin the image to a known-good digest in `docker-compose.yml` rather than working
around the gap.

**Port already in use.**
`8080` and `8780` are fixed; change them in `docker-compose.yml` and `RANGE_PORT` (plus `BE` in
[`app/vite.config.ts`](app/vite.config.ts)) if something else owns them. `5175` needs nothing —
Vite picks the next free port and prints it.

**Apple Silicon: the engine is slow or won't start.**
The image is `linux/amd64` only. Enable *Use Rosetta for x86/amd64 emulation* in Docker Desktop →
Settings → General, and give Docker more memory.

---

## Security & scope

This is a **single-user local practice tool**. The backend binds to `127.0.0.1` and has **no
authentication** — which is only defensible while it stays unreachable off the machine. Don't set
`RANGE_HOST=0.0.0.0` on a network you don't control, and don't put it on the internet.

Everything the range generates is **synthetic log rows**. There is no malware, no exploit code and
no offensive capability here — the "attack emitters" write plausible `DeviceProcessEvents` and
`SecurityEvent` records into a local database so you can practise finding them. Nothing is
executed on your machine, and nothing leaves it.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). A table schema, a technique emitter (with variants that
defeat the naive query), or an ASIM parser are the highest-value contributions.

## License

[MIT](LICENSE).

MITRE ATT&CK® is a registered trademark of The MITRE Corporation; technique names and IDs are used
here for reference under MITRE's terms of use. The Kusto emulator image
(`mcr.microsoft.com/azuredataexplorer/kustainer-linux`) is Microsoft's and carries its own EULA,
which `docker-compose.yml` accepts via `ACCEPT_EULA=Y`. Table schemas are modelled on Microsoft's
public documentation; this project is not affiliated with or endorsed by Microsoft.
