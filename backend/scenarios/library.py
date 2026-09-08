"""Shipped campaign library — ready-made hunts modelled on real threat activity.

Each entry is a curated ScenarioSpec with **pinned variants**, so a library
campaign builds the same way every time (unlike a re-rollable behaviour-first
one). That reproducibility is what lets the guided curriculum reference a
specific campaign and know exactly what the analyst will face.

These are *modelled on* real actors and intrusion patterns, not reproductions of
any specific victim's data — the org, hosts and IOCs are all synthetic. The
actor names orient the hunt ("this is an APT29-style chain") and match how the
techniques actually chain together in the wild.

Difficulty is honest: `starter` is one technique with light noise; `operator`
is a full kill chain buried in a large haystack with decoys that bite.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import ScenarioSpec, ScenarioStep


@dataclass(frozen=True, slots=True)
class LibraryEntry:
    slug: str
    name: str
    actor: str
    difficulty: str                 # starter | intermediate | operator
    tactic_summary: str             # short kill-chain description
    description: str
    steps: list[tuple[str, str]]    # (technique_id, variant) — variant "" = auto
    events: int = 200_000
    loudness: int = 3
    context_depth: str = "full-chain"
    source: str = ""

    def to_spec(self) -> ScenarioSpec:
        steps = [
            ScenarioStep(technique_id=tid, variant=variant, loudness=self.loudness,
                         day_offset=round(14 * 0.66 * i / max(1, len(self.steps) - 1), 2))
            for i, (tid, variant) in enumerate(self.steps)
        ]
        hyp = (f"{self.actor}: {self.tactic_summary}. "
               "Hunt the chain end to end and identify each technique.")
        return ScenarioSpec(
            name=self.name, hypothesis=hyp, steps=steps,
            context_depth=self.context_depth, actor=self.actor,
            source="library", window_days=14, target_events=self.events)

    def meta(self) -> dict:
        return {
            "slug": self.slug, "name": self.name, "actor": self.actor,
            "difficulty": self.difficulty, "tactic_summary": self.tactic_summary,
            "description": self.description, "source": self.source,
            "techniques": [tid for tid, _ in self.steps],
            "events": self.events,
        }


LIBRARY: list[LibraryEntry] = [
    LibraryEntry(
        slug="kerberoast-starter",
        name="Kerberoasting drill",
        actor="Commodity credential theft",
        difficulty="starter",
        tactic_summary="a single kerberoasting burst against service accounts",
        description="One technique, one host, moderate noise. The place to start: "
                    "learn to separate an attacker's bulk 4769 requests from the "
                    "service accounts that legitimately do the same thing.",
        steps=[("T1558.003", "rubeus")],
        events=150_000, loudness=3, context_depth="contextual",
        source="MITRE ATT&CK T1558.003",
    ),
    LibraryEntry(
        slug="encoded-powershell-starter",
        name="Encoded PowerShell delivery",
        actor="Commodity loader",
        difficulty="starter",
        tactic_summary="an encoded PowerShell download cradle",
        description="A classic: base64 PowerShell pulling a second stage. The catch "
                    "is a developer who runs encoded PowerShell every day — your "
                    "query has to tell them apart.",
        steps=[("T1059.001", "encoded")],
        events=150_000, loudness=3, context_depth="contextual",
        source="MITRE ATT&CK T1059.001",
    ),
    LibraryEntry(
        slug="pth-lateral-intermediate",
        name="Pass-the-hash lateral movement",
        actor="Hands-on-keyboard intruder",
        difficulty="intermediate",
        tactic_summary="LSASS dump, then pass-the-hash across servers",
        description="Dump credentials from LSASS, then reuse the hash to move "
                    "laterally over SMB. Watch for NTLM where Kerberos is expected, "
                    "and one account authenticating to hosts it never touches.",
        steps=[("T1003.001", "comsvcs"), ("T1550.002", "sekurlsa_pth"),
               ("T1021.002", "psexec")],
        events=200_000, loudness=3, context_depth="full-chain",
        source="MITRE ATT&CK T1003.001 / T1550.002",
    ),
    LibraryEntry(
        slug="wmi-abuse-intermediate",
        name="WMI abuse — execution to persistence",
        actor="Living-off-the-land operator",
        difficulty="intermediate",
        tactic_summary="WMI for execution, lateral movement and persistence",
        description="All three faces of WMI in one intrusion: local execution, "
                    "remote WMI to another host, and a permanent event-subscription "
                    "backdoor. The monitoring platform's nightly WMI sweep is the "
                    "decoy you must not flag.",
        steps=[("T1047", "wmic_process_call"), ("T1021.006", "wmic_node"),
               ("T1546.003", "powershell_binding")],
        events=200_000, loudness=3, context_depth="full-chain",
        source="MITRE ATT&CK T1047 / T1021.006 / T1546.003",
    ),
    LibraryEntry(
        slug="apt29-operator",
        name="APT29 — full kill chain",
        actor="APT29 (Cozy Bear)",
        difficulty="operator",
        tactic_summary="spearphish → PowerShell → LSASS → kerberoast → "
                       "pass-the-hash → WMI lateral → cloud exfil",
        description="A patient, quiet intrusion end to end. Low loudness, a big "
                    "haystack, and decoys at every stage. This is the interview "
                    "piece: reconstruct the whole chain and tag each technique.",
        steps=[("T1566.001", "macro_child"), ("T1059.001", "obfuscated"),
               ("T1003.001", "comsvcs"), ("T1558.003", "targeted"),
               ("T1550.002", "overpass"), ("T1021.006", "invoke_command"),
               ("T1567.002", "chunked")],
        events=300_000, loudness=2, context_depth="full-chain",
        source="Modelled on MITRE ATT&CK APT29 / G0016",
    ),
    LibraryEntry(
        slug="ransomware-operator",
        name="Ransomware operator",
        actor="Big-game ransomware crew",
        difficulty="operator",
        tactic_summary="access → defence evasion → discovery → mass encryption "
                       "with recovery inhibition",
        description="The last hours of a ransomware intrusion: disable Defender, "
                    "stop backup and database services, delete shadow copies, then "
                    "encrypt en masse. The recovery-inhibit steps are your early "
                    "warning — catch them before the encryption starts.",
        steps=[("T1059.001", "encoded"), ("T1562.001", "set_mppreference"),
               ("T1489", "net_stop"), ("T1490", "vssadmin"),
               ("T1486", "shadow_delete_first")],
        events=250_000, loudness=4, context_depth="full-chain",
        source="Modelled on common ransomware TTPs",
    ),
    LibraryEntry(
        slug="cloud-account-operator",
        name="Cloud account takeover",
        actor="Scattered Spider-style intruder",
        difficulty="intermediate",
        tactic_summary="password spray → cloud sign-in → app-credential persistence",
        description="An identity-first intrusion: spray for a foothold, sign in from "
                    "an unusual source, then add credentials to a service principal "
                    "for durable, MFA-free access. Native SigninLogs and the ASIM "
                    "authentication parser both come into play.",
        steps=[("T1110.003", "low_and_slow"), ("T1078.004", "residential_proxy"),
               ("T1098.001", "consent_then_use")],
        events=200_000, loudness=3, context_depth="full-chain",
        source="Modelled on MITRE ATT&CK Scattered Spider / G1015",
    ),
    LibraryEntry(
        slug="dns-c2-intermediate",
        name="DNS tunnelling C2",
        actor="Stealth C2 operator",
        difficulty="intermediate",
        tactic_summary="HTTP beacon plus DNS-tunnel C2 and exfil",
        description="Command-and-control hidden in DNS. Long, high-entropy subdomains "
                    "carrying data out, alongside a jittered HTTPS beacon. The CDN "
                    "hostnames in the baseline look just as random — entropy alone "
                    "won't cut it.",
        steps=[("T1071.001", "jittered_beacon"), ("T1071.004", "subdomain_exfil")],
        events=200_000, loudness=3, context_depth="full-chain",
        source="MITRE ATT&CK T1071.004",
    ),
]

BY_SLUG = {e.slug: e for e in LIBRARY}


def get(slug: str) -> LibraryEntry | None:
    return BY_SLUG.get(slug)


def list_entries() -> list[dict]:
    order = {"starter": 0, "intermediate": 1, "operator": 2}
    return [e.meta() for e in sorted(LIBRARY, key=lambda x: (order.get(x.difficulty, 9), x.name))]
