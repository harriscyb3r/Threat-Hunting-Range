"""The simulated organisation.

Everything the range generates is derived from an `OrgProfile`, and the profile
is a pure function of `(preset, seed)`. That is what makes a campaign
reproducible: re-roll with the same seed and you get the same people, the same
hostnames and the same IP addresses, so a hunt can be replayed and a detection
re-tested against identical ground.

The org carries the things attacks need to be *coherent*: who is an admin, which
device belongs to whom, which hosts are domain controllers, which accounts are
service accounts that legitimately behave oddly. An attack emitter that picks a
random hostname produces telemetry that falls apart the moment an analyst pivots
on it.
"""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

from . import catalog


def _weighted(rng: random.Random, options: list[tuple]) -> tuple:
    """Pick from [(value..., weight)] where weight is the last element."""
    weights = [o[-1] for o in options]
    return rng.choices(options, weights=weights, k=1)[0]


def _guid(rng: random.Random) -> str:
    return str(__import__("uuid").UUID(int=rng.getrandbits(128), version=4))


def _sid(rng: random.Random, domain_sid: str) -> str:
    return f"{domain_sid}-{rng.randint(1103, 9999)}"


@dataclass(slots=True)
class Location:
    city: str
    country: str
    country_code: str
    utc_offset_h: int


@dataclass(slots=True)
class User:
    upn: str
    sam: str                     # pre-Windows-2000 account name
    display_name: str
    department: str
    title: str
    object_id: str
    sid: str
    location: Location
    manager_upn: str | None = None
    work_start_h: int = 9        # local hour
    work_end_h: int = 17
    home_ip: str = ""
    user_agent: str = ""
    is_admin: bool = False
    is_service: bool = False
    is_executive: bool = False
    travels: bool = False
    device_names: list[str] = field(default_factory=list)

    @property
    def domain(self) -> str:
        return self.upn.split("@", 1)[1]


@dataclass(slots=True)
class Device:
    name: str
    device_id: str
    os: str
    os_version: str
    role: str                    # workstation | dc | file | sql | web | app | bkp | jump
    ip: str
    primary_user: str | None = None

    @property
    def is_server(self) -> bool:
        return self.role != "workstation"


@dataclass(slots=True)
class ServicePrincipal:
    display_name: str
    app_id: str
    object_id: str


@dataclass(slots=True)
class Network:
    workstation_subnet: str      # e.g. "10.20."
    server_subnet: str
    vpn_subnet: str
    egress_ips: list[str]
    firewall_name: str
    firewall_vendor: str
    firewall_product: str
    dns_server: str
    proxy_ip: str


@dataclass(slots=True)
class OrgProfile:
    name: str
    domain: str
    tenant_id: str
    domain_sid: str
    seed: int
    preset: str
    users: list[User]
    devices: list[Device]
    service_principals: list[ServicePrincipal]
    network: Network
    window_start: datetime
    window_end: datetime

    # ── Lookups ──────────────────────────────────────────────────────────

    def user(self, upn: str) -> User:
        return self._user_index[upn]

    def device(self, name: str) -> Device:
        return self._device_index[name]

    @property
    def _user_index(self) -> dict[str, User]:
        return {u.upn: u for u in self.users}

    @property
    def _device_index(self) -> dict[str, Device]:
        return {d.name: d for d in self.devices}

    @property
    def workstations(self) -> list[Device]:
        return [d for d in self.devices if d.role == "workstation"]

    @property
    def servers(self) -> list[Device]:
        return [d for d in self.devices if d.is_server]

    def devices_by_role(self, role: str) -> list[Device]:
        return [d for d in self.devices if d.role == role]

    @property
    def domain_controllers(self) -> list[Device]:
        return self.devices_by_role("dc")

    @property
    def admins(self) -> list[User]:
        return [u for u in self.users if u.is_admin]

    @property
    def humans(self) -> list[User]:
        return [u for u in self.users if not u.is_service]

    @property
    def service_accounts(self) -> list[User]:
        return [u for u in self.users if u.is_service]

    @property
    def netbios(self) -> str:
        return self.domain.split(".")[0].upper()

    def is_working_day(self, when: datetime) -> bool:
        if when.weekday() >= 5:
            return False
        return (when.month, when.day) not in catalog.PUBLIC_HOLIDAYS

    def summary(self) -> str:
        days = (self.window_end - self.window_start).days
        return (
            f"{self.name} ({self.preset}, seed {self.seed}) — "
            f"{len(self.humans)} people, {len(self.service_accounts)} service accounts, "
            f"{len(self.workstations)} workstations, {len(self.servers)} servers, "
            f"{days}-day window from {self.window_start:%Y-%m-%d}"
        )


# ── Presets ──────────────────────────────────────────────────────────────

PRESETS: dict[str, dict] = {
    "smb": {
        "name": "Kingsley Freight", "domain": "kingsleyfreight.com.au",
        "users": 40, "servers": 4,
        "description": "Small business. Flat network, one DC, minimal segmentation.",
    },
    "midsize": {
        "name": "Harbourline Group", "domain": "harbourline.com.au",
        "users": 200, "servers": 12,
        "description": "Mid-size Australian enterprise. Hybrid Entra, on-prem AD, "
                       "segmented server VLAN. The default.",
    },
    "enterprise": {
        "name": "Meridian Holdings", "domain": "meridianholdings.com.au",
        "users": 1000, "servers": 40,
        "description": "Large enterprise. Multiple sites, heavy non-interactive volume.",
    },
}
DEFAULT_PRESET = "midsize"


def build_org(
    preset: str = DEFAULT_PRESET,
    seed: int = 1337,
    *,
    window_days: int = 14,
    window_end: datetime | None = None,
) -> OrgProfile:
    """Deterministically build an organisation.

    `window_end` defaults to a fixed date rather than `now()` — a campaign built
    today and rebuilt next week must produce identical timestamps, or a saved
    detection cannot be re-tested against the same ground.
    """
    if preset not in PRESETS:
        raise ValueError(f"unknown preset {preset!r}; have {sorted(PRESETS)}")
    cfg = PRESETS[preset]
    rng = random.Random(seed)

    domain: str = cfg["domain"]
    tenant_id = _guid(rng)
    # A plausible domain SID, derived from the seed so it is stable.
    h = hashlib.sha256(f"{domain}:{seed}".encode()).hexdigest()
    domain_sid = (f"S-1-5-21-{int(h[0:8], 16) % 4000000000}"
                  f"-{int(h[8:16], 16) % 4000000000}-{int(h[16:24], 16) % 4000000000}")

    end = window_end or datetime(2026, 8, 24, 0, 0, tzinfo=timezone.utc)
    start = end - timedelta(days=window_days)

    net = Network(
        workstation_subnet="10.20.",
        server_subnet="10.30.",
        vpn_subnet="10.99.",
        egress_ips=[f"203.0.113.{rng.randint(10, 60)}" for _ in range(2)],
        firewall_name="fw-edge-01",
        firewall_vendor="Palo Alto Networks",
        firewall_product="PAN-OS",
        dns_server="10.30.0.10",
        proxy_ip="10.30.0.20",
    )

    users = _build_users(rng, cfg, domain, domain_sid)
    devices = _build_devices(rng, cfg, users, net)
    _assign_devices(users, devices)
    sps = [ServicePrincipal(n, aid, _guid(rng)) for n, aid in catalog.SERVICE_PRINCIPALS]

    return OrgProfile(
        name=cfg["name"], domain=domain, tenant_id=tenant_id, domain_sid=domain_sid,
        seed=seed, preset=preset, users=users, devices=devices,
        service_principals=sps, network=net,
        window_start=start, window_end=end,
    )


def _build_users(rng: random.Random, cfg: dict, domain: str, domain_sid: str) -> list[User]:
    count: int = cfg["users"]
    users: list[User] = []
    used: set[str] = set()

    # Department headcount, proportional and at least one each.
    dept_plan: list[tuple[str, str]] = []
    for dept, share, titles in catalog.DEPARTMENTS:
        n = max(1, round(count * share))
        for _ in range(n):
            dept_plan.append((dept, rng.choice(titles)))
    rng.shuffle(dept_plan)
    dept_plan = dept_plan[:count]

    for dept, title in dept_plan:
        for _ in range(50):
            given = rng.choice(catalog.GIVEN_NAMES)
            surname = rng.choice(catalog.SURNAMES)
            sam = f"{given[0].lower()}{surname.lower()}"
            if sam not in used:
                break
        else:
            sam = f"user{len(users):04d}"
        used.add(sam)

        city, country, cc, off = rng.choice(catalog.LOCATIONS)
        is_exec = dept == "Executive"
        # IT staff and executives hold privileged roles; nobody else does.
        is_admin = (dept == "IT" and rng.random() < 0.55) or (is_exec and rng.random() < 0.2)
        start_h = rng.choice([7, 8, 8, 9, 9, 9, 10])

        users.append(User(
            upn=f"{sam}@{domain}",
            sam=sam,
            display_name=f"{given} {surname}",
            department=dept,
            title=title,
            object_id=_guid(rng),
            sid=_sid(rng, domain_sid),
            location=Location(city, country, cc, off),
            work_start_h=start_h,
            work_end_h=start_h + rng.choice([8, 8, 9, 9, 10]),
            home_ip=f"1.128.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
            user_agent=_weighted(rng, catalog.USER_AGENTS)[0],
            is_admin=is_admin,
            is_executive=is_exec,
            # Sales and executives travel; this is what makes impossible-travel
            # hunts require thought rather than a one-liner.
            travels=dept in ("Sales", "Executive") and rng.random() < 0.35,
        ))

    # Managers, within department.
    by_dept: dict[str, list[User]] = {}
    for u in users:
        by_dept.setdefault(u.department, []).append(u)
    for dept, members in by_dept.items():
        lead = next((m for m in members if "Manager" in m.title or "Chief" in m.title), members[0])
        for m in members:
            if m is not lead:
                m.manager_upn = lead.upn

    # Service accounts. These legitimately authenticate at odd hours from
    # servers, which is precisely why attackers hide in them.
    for name, label in [
        ("svc-backup", "Veeam Backup Service"),
        ("svc-sqlagent", "SQL Server Agent"),
        ("svc-sccm", "Configuration Manager"),
        ("svc-scanner", "Vulnerability Scanner"),
        ("svc-monitor", "Monitoring Agent"),
        ("svc-iis", "IIS Application Pool"),
    ]:
        users.append(User(
            upn=f"{name}@{domain}", sam=name, display_name=label,
            department="IT", title="Service Account",
            object_id=_guid(rng), sid=_sid(rng, domain_sid),
            location=Location("Melbourne", "Australia", "AU", 10),
            work_start_h=0, work_end_h=24,
            home_ip="", user_agent="",
            is_admin=name in ("svc-backup", "svc-sccm"),
            is_service=True,
        ))
    return users


def _build_devices(rng: random.Random, cfg: dict, users: list[User],
                   net: Network) -> list[Device]:
    devices: list[Device] = []
    octet, host = 1, 10

    # Servers first, on the server subnet.
    server_budget: int = cfg["servers"]
    planned: list[tuple[str, str]] = []
    for role, _label, base in catalog.SERVER_ROLES:
        planned += [(role, role)] * base
    while len(planned) < server_budget:
        planned.append(("app", "app"))
    planned = planned[:server_budget]

    role_seq: dict[str, int] = {}
    for role, _ in planned:
        role_seq[role] = role_seq.get(role, 0) + 1
        devices.append(Device(
            name=f"SRV-{role.upper()}-{role_seq[role]:02d}",
            device_id=_guid(rng),
            os="WindowsServer2022", os_version="10.0.20348.2762",
            role=role,
            ip=f"{net.server_subnet}0.{host}",
        ))
        host += 1

    # Workstations for every human.
    host = 20
    for u in (x for x in users if not x.is_service):
        os_name, os_ver, _ = _weighted(rng, catalog.WORKSTATION_OS)
        devices.append(Device(
            name=f"WKS-{u.sam[:10].upper()}",
            device_id=_guid(rng),
            os=os_name, os_version=os_ver,
            role="workstation",
            ip=f"{net.workstation_subnet}{octet}.{host}",
            primary_user=u.upn,
        ))
        host += 1
        if host > 250:
            host, octet = 20, octet + 1
    return devices


def _assign_devices(users: list[User], devices: list[Device]) -> None:
    for d in devices:
        if d.primary_user:
            for u in users:
                if u.upn == d.primary_user:
                    u.device_names.append(d.name)
                    break
