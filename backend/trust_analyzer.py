"""Zero-Trust Analysis Engine.

Evaluates the network's security posture against zero-trust principles:
- Never trust, always verify
- Assume breach
- Least privilege access
- Micro-segmentation
- Continuous monitoring
"""
from __future__ import annotations

from typing import Optional

from models import Device, Connection, ScanResult, TrustLevel, BlastRadius


class ZeroTrustAnalyzer:
    """Analyzes a network scan result against zero-trust principles."""

    def __init__(self, scan_result: ScanResult):
        self.scan = scan_result
        self.findings: list[dict] = []
        self.recommendations: list[dict] = []

    def analyze(self) -> dict:
        """Run all analyses and return a comprehensive zero-trust report."""
        self._analyze_device_trust()
        self._analyze_network_segmentation()
        self._analyze_exposed_services()
        self._analyze_blast_radius_risks()
        self._analyze_least_privilege()
        self._analyze_monitoring_gaps()

        overall_compliance = self._calculate_compliance_score()

        return {
            "overall_compliance_score": overall_compliance,
            "trust_level_distribution": self._get_trust_distribution(),
            "findings": self.findings,
            "recommendations": self.recommendations,
            "summary": self._generate_summary(overall_compliance),
        }

    def _analyze_device_trust(self):
        """Evaluate trust levels of all devices."""
        for device in self.scan.devices:
            # Flag untrusted devices
            if device.trust_level in (TrustLevel.UNTRUSTED, TrustLevel.LOW):
                self.findings.append({
                    "type": "untrusted_device",
                    "severity": "high" if device.trust_level == TrustLevel.UNTRUSTED else "medium",
                    "device_ip": device.ip,
                    "device_hostname": device.hostname,
                    "message": f"Device {device.hostname} ({device.ip}) has low trust level ({device.trust_level.value}). "
                              f"Risk score: {device.risk_score:.2f}",
                    "open_ports": device.open_port_count,
                })
                self.recommendations.append({
                    "priority": "high",
                    "category": "device_hardening",
                    "device_ip": device.ip,
                    "message": f"Harden device {device.hostname}: close unnecessary ports, update firmware/OS, "
                              f"implement host-based firewall, and enable logging.",
                })

            # Flag devices with high-risk services
            high_risk_services = [s for s in device.services if s.risk_score >= 0.7]
            if high_risk_services:
                service_names = [s.name for s in high_risk_services]
                self.findings.append({
                    "type": "high_risk_services",
                    "severity": "high",
                    "device_ip": device.ip,
                    "message": f"{device.hostname} exposes high-risk services: {', '.join(service_names)}",
                })
                self.recommendations.append({
                    "priority": "critical",
                    "category": "service_hardening",
                    "device_ip": device.ip,
                    "message": f"On {device.hostname}: disable or replace {', '.join(service_names)} with secure alternatives "
                              f"(e.g., SFTP instead of FTP, SSH instead of Telnet).",
                })

    def _analyze_network_segmentation(self):
        """Evaluate network segmentation (micro-segmentation compliance)."""
        # Group devices by type
        device_types = {}
        for d in self.scan.devices:
            device_types.setdefault(d.device_type, []).append(d)

        # Check for cross-type connections that shouldn't exist
        suspicious_cross_connects = []
        for conn in self.scan.connections:
            source = self._find_device(conn.source_ip)
            target = self._find_device(conn.target_ip)
            if source and target and source.device_type != target.device_type:
                # IoT to Server connections are suspicious
                if source.device_type == "IoT/Embedded" and target.device_type in ("Server", "Database"):
                    suspicious_cross_connects.append(conn)

        if suspicious_cross_connects:
            self.findings.append({
                "type": "poor_segmentation",
                "severity": "high",
                "message": f"Found {len(suspicious_cross_connects)} cross-segment connections that violate "
                          f"micro-segmentation principles (e.g., IoT devices accessing servers).",
            })
            self.recommendations.append({
                "priority": "high",
                "category": "micro_segmentation",
                "message": "Implement network micro-segmentation: create separate VLANs for IoT, workstations, "
                          "servers, and critical systems. Use firewall rules to restrict inter-VLAN traffic.",
            })

        # Check if all devices are on the same flat network
        if len(self.scan.devices) > 5:
            has_segmentation = any(
                d.device_type in ("Router/Firewall", "Network Device")
                for d in self.scan.devices
            )
            if not has_segmentation:
                self.findings.append({
                    "type": "flat_network",
                    "severity": "medium",
                    "message": f"Network appears to be flat with {len(self.scan.devices)} devices on the same subnet. "
                              f"No router/firewall/gateway detected.",
                })

    def _analyze_exposed_services(self):
        """Analyze which services are unnecessarily exposed to the network."""
        for device in self.scan.devices:
            unnecessary_services = []
            for service in device.services:
                # Services that are commonly unnecessary for general consumption
                if service.name in ("Telnet", "FTP", "NetBIOS", "NFS"):
                    unnecessary_services.append(service.name)

            if unnecessary_services:
                self.findings.append({
                    "type": "unnecessary_exposure",
                    "severity": "medium",
                    "device_ip": device.ip,
                    "message": f"{device.hostname} exposes unnecessary services: {', '.join(unnecessary_services)}",
                })
                self.recommendations.append({
                    "priority": "medium",
                    "category": "reduce_attack_surface",
                    "device_ip": device.ip,
                    "message": f"Disable unnecessary services on {device.hostname}: {', '.join(unnecessary_services)}",
                })

            # Check for database exposure
            db_services = [s for s in device.services if s.name in ("MySQL", "PostgreSQL", "MongoDB", "MSSQL", "OracleDB", "Redis")]
            if db_services:
                db_names = [s.name for s in db_services]
                self.findings.append({
                    "type": "database_exposure",
                    "severity": "critical",
                    "device_ip": device.ip,
                    "message": f"Database service(s) {', '.join(db_names)} exposed on {device.hostname}. "
                              f"Databases should never be directly accessible from the network.",
                })
                self.recommendations.append({
                    "priority": "critical",
                    "category": "database_hardening",
                    "device_ip": device.ip,
                    "message": f"Move {', '.join(db_names)} to an isolated backend network. "
                              f"Implement authentication, encryption in transit (TLS), and IP whitelisting.",
                })

    def _analyze_blast_radius_risks(self):
        """Analyze blast radius analyses and flag critical risks."""
        for analysis in self.scan.blast_radius_analyses:
            device = self._find_device(analysis.device_ip)
            hostname = device.hostname if device else analysis.device_ip

            if analysis.severity in ("critical", "high"):
                self.findings.append({
                    "type": "blast_radius",
                    "severity": analysis.severity,
                    "device_ip": analysis.device_ip,
                    "message": f"Compromise of {hostname} would expose {analysis.total_exposed_devices} devices "
                              f"({len(analysis.directly_exposed_ips)} direct, {len(analysis.indirectly_exposed_ips)} indirect). "
                              f"{'CRITICAL DATA AT RISK!' if analysis.critical_data_risk else ''}",
                })

                # Only 2 recommendations per device to avoid spam
                self.recommendations.append({
                    "priority": "critical" if analysis.severity == "critical" else "high",
                    "category": "blast_radius_reduction",
                    "device_ip": analysis.device_ip,
                    "message": f"Reduce blast radius for {hostname}: implement network segmentation, "
                              f"application whitelisting, and host-based firewalls. "
                              f"Apply the principle of least privilege to all connections.",
                })

    def _analyze_least_privilege(self):
        """Check for violations of least privilege principle."""
        for conn in self.scan.connections:
            if conn.connection_type.name == "SUSPICIOUS":
                source = self._find_device(conn.source_ip)
                target = self._find_device(conn.target_ip)
                source_name = source.hostname if source else conn.source_ip
                target_name = target.hostname if target else conn.target_ip

                self.findings.append({
                    "type": "least_privilege_violation",
                    "severity": "medium",
                    "message": f"Suspicious connection: {source_name} -> {target_name}:{conn.port}. "
                              f"This may violate least-privilege principles.",
                })

    def _analyze_monitoring_gaps(self):
        """Identify gaps in monitoring and visibility."""
        high_risk_count = sum(1 for d in self.scan.devices if d.risk_score >= 0.6)
        if high_risk_count > 0:
            self.recommendations.append({
                "priority": "high",
                "category": "monitoring",
                "message": f"Deploy continuous monitoring for {high_risk_count} high-risk devices. "
                          f"Implement SIEM integration, network flow analysis, and anomaly detection.",
            })

        # Check for devices with no services detected (potential stealth)
        stealth_devices = [d for d in self.scan.devices if d.open_port_count == 0]
        if stealth_devices:
            self.findings.append({
                "type": "stealth_devices",
                "severity": "low",
                "message": f"{len(stealth_devices)} devices showed no open ports. These may be using host-based firewalls "
                          f"or stealth techniques. Verify they are authorized.",
            })

    def _calculate_compliance_score(self) -> float:
        """Calculate overall zero-trust compliance score (0-100)."""
        score = 100.0

        if not self.scan.devices:
            return 0.0

        # Deductions for untrusted devices
        untrusted = sum(1 for d in self.scan.devices if d.trust_level in (TrustLevel.UNTRUSTED, TrustLevel.LOW))
        score -= untrusted * 10

        # Deductions for high-risk devices
        high_risk = self.scan.total_high_risk_devices
        score -= high_risk * 8

        # Deductions for critical findings
        critical_findings = sum(1 for f in self.findings if f.get("severity") == "critical")
        score -= critical_findings * 15

        high_findings = sum(1 for f in self.findings if f.get("severity") == "high")
        score -= high_findings * 5

        # Deduction for large blast radius
        critical_blast = sum(1 for b in self.scan.blast_radius_analyses if b.severity == "critical")
        score -= critical_blast * 10

        # Deduction for database exposure
        db_findings = sum(1 for f in self.findings if f.get("type") == "database_exposure")
        score -= db_findings * 20

        # Bonus for segmentation
        router_count = sum(1 for d in self.scan.devices if d.device_type == "Router/Firewall")
        score += min(router_count * 5, 15)

        return max(0.0, min(100.0, score))

    def _get_trust_distribution(self) -> dict:
        """Get the distribution of trust levels across devices."""
        distribution = {t.value: 0 for t in TrustLevel}
        for d in self.scan.devices:
            distribution[d.trust_level.value] = distribution.get(d.trust_level.value, 0) + 1
        return distribution

    def _generate_summary(self, compliance_score: float) -> str:
        """Generate a human-readable summary of the zero-trust analysis."""
        total = len(self.scan.devices)
        high_risk = self.scan.total_high_risk_devices
        untrusted = sum(1 for d in self.scan.devices if d.trust_level in (TrustLevel.UNTRUSTED, TrustLevel.LOW))
        critical_findings = sum(1 for f in self.findings if f.get("severity") == "critical")

        if compliance_score >= 80:
            rating = "Good"
            emoji = "🟢"
        elif compliance_score >= 60:
            rating = "Fair"
            emoji = "🟡"
        elif compliance_score >= 40:
            rating = "Poor"
            emoji = "🟠"
        else:
            rating = "Critical"
            emoji = "🔴"

        lines = [
            f"{emoji} Zero-Trust Compliance Score: {compliance_score:.1f}/100 ({rating})",
            f"",
            f"Network: {self.scan.network}",
            f"Devices discovered: {total}",
            f"Open ports: {self.scan.total_open_ports}",
            f"High-risk devices: {high_risk}",
            f"Untrusted/low-trust devices: {untrusted}",
            f"Critical findings: {critical_findings}",
            f"Recommendations: {len(self.recommendations)}",
        ]
        return "\n".join(lines)

    def _find_device(self, ip: str) -> Optional[Device]:
        """Find a device by IP address."""
        for d in self.scan.devices:
            if d.ip == ip:
                return d
        return None
