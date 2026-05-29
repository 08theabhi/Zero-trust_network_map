"""Data models for the Zero-Trust Network Map."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional


class TrustLevel(Enum):
    UNTRUSTED = "untrusted"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConnectionType(Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"


@dataclass
class Service:
    port: int
    protocol: str  # tcp or udp
    name: str
    state: str  # open, closed, filtered
    version: Optional[str] = None
    risk_score: float = 0.0  # 0.0 (safe) to 1.0 (dangerous)

    def to_dict(self):
        return asdict(self)


@dataclass
class Device:
    ip: str
    mac: str
    hostname: str
    vendor: str = "Unknown"
    os: str = "Unknown"
    device_type: str = "Unknown"  # workstation, server, phone, iot, router, etc.
    services: list[Service] = field(default_factory=list)
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    first_seen: str = ""
    last_seen: str = ""
    is_gateway: bool = False
    is_dns_server: bool = False
    is_dhcp_server: bool = False
    risk_score: float = 0.0
    open_port_count: int = 0
    vulnerabilities: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.first_seen:
            self.first_seen = datetime.now().isoformat()
        if not self.last_seen:
            self.last_seen = datetime.now().isoformat()

    def to_dict(self):
        result = asdict(self)
        result["trust_level"] = self.trust_level.value
        result["services"] = [s.to_dict() for s in self.services]
        return result


@dataclass
class Connection:
    source_ip: str
    target_ip: str
    port: int
    protocol: str
    connection_type: ConnectionType = ConnectionType.UNKNOWN
    risk_score: float = 0.0
    last_active: str = ""
    bytes_transferred: int = 0

    def __post_init__(self):
        if not self.last_active:
            self.last_active = datetime.now().isoformat()

    def to_dict(self):
        result = asdict(self)
        result["connection_type"] = self.connection_type.value
        return result


@dataclass
class BlastRadius:
    """Represents what would happen if a device is compromised."""
    device_ip: str
    directly_exposed_ips: list[str] = field(default_factory=list)
    indirectly_exposed_ips: list[str] = field(default_factory=list)
    exposed_services: list[dict] = field(default_factory=list)
    critical_data_risk: bool = False
    total_exposed_devices: int = 0
    severity: str = "low"

    def to_dict(self):
        return asdict(self)


@dataclass
class ScanResult:
    """Container for a full scan result."""
    scan_id: str
    network: str
    timestamp: str = ""
    devices: list[Device] = field(default_factory=list)
    connections: list[Connection] = field(default_factory=list)
    blast_radius_analyses: list[BlastRadius] = field(default_factory=list)
    overall_risk_score: float = 0.0
    total_devices: int = 0
    total_open_ports: int = 0
    total_high_risk_devices: int = 0
    scan_duration_seconds: float = 0.0
    scan_status: str = "pending"  # pending, running, completed, failed

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        result = asdict(self)
        result["devices"] = [d.to_dict() for d in self.devices]
        result["connections"] = [c.to_dict() for c in self.connections]
        result["blast_radius_analyses"] = [b.to_dict() for b in self.blast_radius_analyses]
        return result
