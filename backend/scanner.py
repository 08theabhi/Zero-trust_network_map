"""Network scanner for Zero-Trust Network Map.

Performs:
- ARP-based device discovery on the local network
- TCP connect port scanning on discovered devices
- Service fingerprinting via banner grabbing
- OS detection via TTL analysis
"""
from __future__ import annotations

import ipaddress
import socket
import subprocess
import re
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional

from models import Device, Service, TrustLevel, ScanResult

# Common ports to scan
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985,
    5986, 6379, 8080, 8443, 9000, 9090, 27017
]

PORT_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "OracleDB", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9000: "SonarQube", 9090: "Prometheus", 27017: "MongoDB"
}

# Risk scores for common services (0.0 = safe, 1.0 = dangerous)
SERVICE_RISK_MAP = {
    "FTP": 0.7, "Telnet": 0.9, "SMB": 0.8, "RDP": 0.6,
    "VNC": 0.8, "MSSQL": 0.5, "MySQL": 0.4, "Redis": 0.6,
    "SSH": 0.3, "HTTP": 0.4, "HTTPS": 0.2, "DNS": 0.2,
    "SMTP": 0.5, "NetBIOS": 0.7, "MSRPC": 0.6, "NFS": 0.8,
}


def get_local_network() -> str:
    """Detect the local network CIDR notation."""
    try:
        if is_windows():
            result = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                line = line.strip()
                if "IPv4" in line or "IP Address" in line:
                    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if ip_match:
                        ip = ip_match.group(1)
                        if ip.startswith("127."):
                            continue
                        # Get subnet mask
                        mask_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                        # Approximate: assume /24
                        network = f"{'.'.join(ip.split('.')[:3])}.0/24"
                        return network
        else:
            result = subprocess.run(
                ["ip", "-4", "addr", "show"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "inet " in line and "127.0.0.1" not in line:
                    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", line)
                    if match:
                        return match.group(1)
    except Exception:
        pass
    return "192.168.1.0/24"


def is_windows() -> bool:
    """Check if running on Windows."""
    try:
        import platform
        return platform.system().lower() == "windows"
    except Exception:
        return False


def arp_scan(network: str) -> list[dict]:
    """Discover devices on the local network using ARP (via arp -a or ping sweep)."""
    devices = {}

    # Method 1: Parse arp cache
    try:
        if is_windows():
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split("\n"):
                match = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17,})", line
                )
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace("-", ":")
                    if ip not in devices and not ip.startswith("224.") and not ip.startswith("239."):
                        devices[ip] = {"ip": ip, "mac": mac.upper()}
        else:
            result = subprocess.run(
                ["arp", "-n"], capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split("\n"):
                match = re.search(
                    r"(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:]{17})", line
                )
                if match:
                    ip = match.group(1)
                    mac = match.group(2).upper()
                    if ip not in devices:
                        devices[ip] = {"ip": ip, "mac": mac}
    except Exception:
        pass

    # Method 2: Ping sweep to discover additional devices
    try:
        net = ipaddress.IPv4Network(network, strict=False)
        # Guard against scanning very large networks
        if net.prefixlen < 20:
            # For large networks, only scan the first /24 subnet
            net = ipaddress.IPv4Network(f'{net.network_address}/24', strict=False)
        hosts = list(net.hosts())[:50]  # Limit to first 50 hosts for speed

        def ping_host(ip):
            try:
                if is_windows():
                    cmd = ["ping", "-n", "1", "-w", "500", str(ip)]
                else:
                    cmd = ["ping", "-c", "1", "-W", "1", str(ip)]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=3
                )
                if result.returncode == 0:
                    return str(ip)
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(ping_host, h): h for h in hosts}
            for future in as_completed(futures, timeout=20):
                ip = future.result()
                if ip and ip not in devices:
                    devices[ip] = {"ip": ip, "mac": "00:00:00:00:00:00"}
    except Exception:
        pass

    return list(devices.values())


def get_hostname(ip: str) -> str:
    """Resolve hostname for an IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return ip


def get_mac_vendor(mac: str) -> str:
    """Identify the vendor from MAC address prefix."""
    if not mac or mac == "00:00:00:00:00:00":
        return "Unknown"
    try:
        # Common MAC prefixes
        vendors = {
            "00:00:0C": "Cisco",
            "00:01:42": "Cisco",
            "00:05:5D": "Cisco",
            "00:14:5E": "Cisco",
            "00:1A:A1": "Cisco",
            "00:1E:13": "Cisco",
            "00:1E:E5": "Cisco",
            "00:21:55": "Hewlett-Packard",
            "00:23:7D": "Hewlett-Packard",
            "00:25:B3": "Hewlett-Packard",
            "00:0C:29": "VMware",
            "00:50:56": "VMware",
            "00:05:69": "VMware",
            "08:00:27": "Oracle/VirtualBox",
            "00:15:5D": "Microsoft Hyper-V",
            "00:03:FF": "Microsoft",
            "00:0D:65": "Microsoft",
            "00:50:F2": "Microsoft",
            "00:1B:21": "Dell",
            "00:21:9B": "Dell",
            "00:14:22": "Dell",
            "00:12:17": "Apple",
            "00:1B:63": "Apple",
            "00:1E:C2": "Apple",
            "00:1F:F3": "Apple",
            "00:24:36": "Apple",
            "CC:46:D6": "Apple",
            "3C:22:FB": "Apple",
            "F0:18:98": "Apple",
            "B0:34:95": "Samsung",
            "00:23:D4": "Samsung",
            "00:1A:11": "Google",
            "00:1A:3F": "Google",
            "8C:DE:F9": "Google",
            "00:25:90": "TP-Link",
            "50:C7:BF": "TP-Link",
            "14:CF:92": "TP-Link",
            "A4:2B:B0": "TP-Link",
            "AC:84:C6": "TP-Link",
            "00:16:3E": "Xen",
            "00:1B:4A": "Ubiquiti",
            "24:A4:3C": "Ubiquiti",
            "68:72:51": "Raspberry Pi",
            "B8:27:EB": "Raspberry Pi",
            "DC:A6:32": "Raspberry Pi",
        }
        prefix = mac.upper()[:8]
        if prefix in vendors:
            return vendors[prefix]
        prefix_short = mac.upper()[:8]
        if prefix_short in vendors:
            return vendors[prefix_short]
        return "Unknown"
    except Exception:
        return "Unknown"


def guess_device_type(hostname: str, services: list, mac: str, vendor: str) -> str:
    """Guess the device type based on hostname, services, and vendor."""
    hostname_lower = hostname.lower()
    vendor_lower = vendor.lower()

    if any(x in hostname_lower for x in ["router", "gateway", "fw", "firewall"]):
        return "Router/Firewall"
    if any(x in hostname_lower for x in ["switch", "ap", "access-point"]):
        return "Network Device"
    if "printer" in hostname_lower:
        return "Printer"
    if any(x in hostname_lower for x in ["server", "nas", "exchange", "sql", "db"]):
        return "Server"
    if any(x in vendor_lower for x in ["apple", "iphone", "ipad"]):
        return "Mobile Device"
    if any(x in hostname_lower for x in ["phone", "iphone", "android", "mobile"]):
        return "Mobile Device"
    if any(x in vendor_lower for x in ["raspberry"]):
        return "IoT/Embedded"
    if any(x in hostname_lower for x in ["iot", "camera", "sensor", "thermostat"]):
        return "IoT/Embedded"
    if 443 in [s.port for s in services] and 80 in [s.port for s in services]:
        return "Web Server"
    if 22 in [s.port for s in services]:
        return "Linux/Unix Workstation"
    if 3389 in [s.port for s in services]:
        return "Windows Workstation"

    return "Workstation"


def guess_os(ip: str, services: list) -> str:
    """Try to guess the OS based on open ports and TTL."""
    # Check for TTL
    try:
        if is_windows():
            result = subprocess.run(
                ["ping", "-n", "1", ip], capture_output=True, text=True, timeout=5
            )
        else:
            result = subprocess.run(
                ["ping", "-c", "1", ip], capture_output=True, text=True, timeout=5
            )
        ttl_match = re.search(r"TTL=(\d+)", result.stdout, re.IGNORECASE)
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl <= 32:
                return "iOS/Embedded"
            elif ttl <= 64:
                return "Linux/Unix/MacOS"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Solaris/AIX"
    except Exception:
        pass

    # Guess from services
    service_ports = {s.port for s in services}
    if 3389 in service_ports:
        return "Windows (RDP detected)"
    if 5357 in service_ports or 5985 in service_ports:
        return "Windows"
    if 22 in service_ports and 111 in service_ports:
        return "Linux/Unix"
    if 62078 in service_ports:
        return "iPhone/iOS"

    return "Unknown"


def scan_port(ip: str, port: int, timeout: float = 1.0) -> Optional[Service]:
    """TCP connect scan on a single port. Returns Service if open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            service_name = PORT_SERVICE_MAP.get(port, "Unknown")
            # Try banner grab
            banner = ""
            try:
                sock.settimeout(1.5)
                sock.send(b"\r\n")
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()[:100]
            except Exception:
                pass
            risk = SERVICE_RISK_MAP.get(service_name, 0.5)
            sock.close()
            return Service(
                port=port,
                protocol="tcp",
                name=service_name,
                state="open",
                version=banner if banner else None,
                risk_score=risk,
            )
        sock.close()
    except Exception:
        pass
    return None


def scan_device_ports(
    ip: str,
    ports: list[int] = None,
    max_workers: int = 50,
    timeout: float = 1.0,
) -> list[Service]:
    """Scan common ports on a single device using threaded TCP connects."""
    if ports is None:
        ports = COMMON_PORTS
    services = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures, timeout=60):
            service = future.result()
            if service:
                services.append(service)
    services.sort(key=lambda s: s.port)
    return services


def scan_network(
    network: str = None,
    scan_ports: bool = True,
    progress_callback=None,
) -> ScanResult:
    """Perform a full network scan.

    Args:
        network: CIDR notation (e.g., "192.168.1.0/24"). Auto-detected if None.
        scan_ports: Whether to scan for open ports on discovered devices.
        progress_callback: Optional callback(status, percent, message).

    Returns:
        ScanResult with discovered devices, connections, and analysis.
    """
    if network is None:
        network = get_local_network()

    scan_id = f"scan_{int(time.time())}"
    result = ScanResult(
        scan_id=scan_id,
        network=network,
        scan_status="running",
    )

    start_time = time.time()

    try:
        # Step 1: ARP discovery
        if progress_callback:
            progress_callback("scanning", 10, "Discovering devices via ARP...")

        discovered = arp_scan(network)
        if not discovered:
            # Fallback: use the gateway and ourselves
            discovered = [
                {"ip": str(ipaddress.IPv4Network(network, strict=False).network_address + 1), "mac": "00:00:00:00:00:00"},
            ]

        total_devices = len(discovered)
        if progress_callback:
            progress_callback("scanning", 25, f"Found {total_devices} devices. Resolving details...")

        # Step 2: Resolve device details
        devices = []
        for i, d in enumerate(discovered):
            ip = d["ip"]
            mac = d["mac"]
            hostname = get_hostname(ip)
            vendor = get_mac_vendor(mac)

            # Quick connectivity check
            services = []
            if scan_ports:
                if progress_callback:
                    pct = 25 + int((i / total_devices) * 55)
                    progress_callback("scanning", min(pct, 80), f"Scanning {ip} ({hostname})...")
                services = scan_device_ports(ip)

            vendor = get_mac_vendor(mac)
            device_type = guess_device_type(hostname, services, mac, vendor)
            os_name = guess_os(ip, services)

            # Calculate risk score
            risk_score = calculate_device_risk(services, device_type)

            # Set trust level based on risk
            if risk_score < 0.2:
                trust_level = TrustLevel.CRITICAL if device_type in ("Router/Firewall", "Server") else TrustLevel.HIGH
            elif risk_score < 0.4:
                trust_level = TrustLevel.HIGH
            elif risk_score < 0.6:
                trust_level = TrustLevel.MEDIUM
            elif risk_score < 0.8:
                trust_level = TrustLevel.LOW
            else:
                trust_level = TrustLevel.UNTRUSTED

            device = Device(
                ip=ip,
                mac=mac,
                hostname=hostname,
                vendor=vendor,
                os=os_name,
                device_type=device_type,
                services=services,
                trust_level=trust_level,
                is_gateway="router" in device_type.lower() or ip.endswith(".1") or ip.endswith(".254"),
                is_dns_server=53 in [s.port for s in services],
                is_dhcp_server="dhcp" in hostname.lower() or 67 in [s.port for s in services],
                risk_score=risk_score,
                open_port_count=len(services),
            )
            devices.append(device)

        result.devices = devices
        result.total_devices = len(devices)
        result.total_open_ports = sum(d.open_port_count for d in devices)
        result.total_high_risk_devices = sum(1 for d in devices if d.risk_score >= 0.6)

        # Step 3: Map connections between devices
        if progress_callback:
            progress_callback("analyzing", 85, "Mapping connections and trust relationships...")

        connections = map_connections(devices)
        result.connections = connections

        # Step 4: Analyze blast radius
        blast_analyses = []
        for device in devices:
            analysis = analyze_blast_radius(device, devices, connections)
            blast_analyses.append(analysis)
        result.blast_radius_analyses = blast_analyses

        # Step 5: Overall risk score
        if devices:
            result.overall_risk_score = sum(d.risk_score for d in devices) / len(devices)
        result.scan_status = "completed"

    except Exception as e:
        result.scan_status = "failed"
        if progress_callback:
            progress_callback("failed", 0, f"Scan failed: {str(e)}")

    result.scan_duration_seconds = time.time() - start_time

    if progress_callback:
        progress_callback("completed", 100, "Scan complete!")

    return result


def calculate_device_risk(services: list[Service], device_type: str) -> float:
    """Calculate risk score for a device based on its services and type."""
    if not services:
        return 0.1

    # Base risk from services
    service_risks = [s.risk_score for s in services]
    avg_service_risk = sum(service_risks) / len(service_risks) if service_risks else 0

    # Port count factor (more ports = more attack surface)
    port_count = len(services)
    port_factor = min(port_count / 10, 1.0) * 0.3

    # Device type factor
    type_risk_map = {
        "IoT/Embedded": 0.8,
        "Printer": 0.6,
        "Mobile Device": 0.5,
        "Workstation": 0.4,
        "Windows Workstation": 0.5,
        "Linux/Unix Workstation": 0.3,
        "Web Server": 0.6,
        "Server": 0.5,
        "Router/Firewall": 0.3,
        "Network Device": 0.4,
    }
    type_risk = type_risk_map.get(device_type, 0.5)

    # High-risk services bonus
    has_high_risk = any(
        s.name in ("Telnet", "FTP", "SMB", "VNC", "NetBIOS", "NFS")
        for s in services
    )
    high_risk_bonus = 0.2 if has_high_risk else 0

    risk = (avg_service_risk * 0.4) + (port_factor * 0.2) + (type_risk * 0.3) + (high_risk_bonus * 0.1)
    return min(risk, 1.0)


def map_connections(devices: list[Device]) -> list:
    """Map connections between devices based on service access patterns."""
    connections = []
    from models import Connection, ConnectionType

    for i, source in enumerate(devices):
        for target in devices:
            if source.ip == target.ip:
                continue

            # If source has a service and target is also on the network, they can potentially connect
            for service in source.services:
                # Check if the service could be accessed from other devices
                conn_type = ConnectionType.ALLOWED
                # Services that should NOT be accessible from other devices
                if service.name in ("MySQL", "PostgreSQL", "MongoDB", "Redis", "WinRM-HTTP", "WinRM-HTTPS"):
                    # These should ideally be isolated
                    if not target.is_gateway and not target.is_dns_server:
                        conn_type = ConnectionType.SUSPICIOUS

                # Determine risk of this connection
                conn_risk = service.risk_score * 0.7
                if conn_type == ConnectionType.SUSPICIOUS:
                    conn_risk = min(conn_risk + 0.3, 1.0)

                connections.append(Connection(
                    source_ip=source.ip,
                    target_ip=target.ip,
                    port=service.port,
                    protocol=service.protocol,
                    connection_type=conn_type,
                    risk_score=conn_risk,
                ))

    return connections


def analyze_blast_radius(device: Device, all_devices: list[Device], connections: list) -> dict:
    """Analyze what would happen if this device were compromised."""
    from models import BlastRadius

    directly_exposed = []
    indirectly_exposed = []
    exposed_services = []

    for conn in connections:
        if conn.source_ip == device.ip:
            directly_exposed.append(conn.target_ip)
            exposed_services.append({
                "port": conn.port,
                "protocol": conn.protocol,
                "risk_score": conn.risk_score,
            })

    # Deduplicate
    directly_exposed = list(set(directly_exposed))

    # Indirect exposure: devices reachable through directly exposed devices
    for exposed_ip in directly_exposed:
        for conn in connections:
            if conn.source_ip == exposed_ip and conn.target_ip != device.ip:
                if conn.target_ip not in directly_exposed and conn.target_ip != device.ip:
                    indirectly_exposed.append(conn.target_ip)

    indirectly_exposed = list(set(indirectly_exposed))

    # Check if any critical data services are exposed
    critical_ports = {3306, 5432, 27017, 1433, 3389, 22, 445}
    has_critical = any(
        s.get("port") in critical_ports for s in exposed_services
    )

    total_exposed = len(directly_exposed) + len(indirectly_exposed)

    if total_exposed >= 10:
        severity = "critical"
    elif total_exposed >= 5:
        severity = "high"
    elif total_exposed >= 2:
        severity = "medium"
    else:
        severity = "low"

    return BlastRadius(
        device_ip=device.ip,
        directly_exposed_ips=directly_exposed,
        indirectly_exposed_ips=indirectly_exposed,
        exposed_services=exposed_services,
        critical_data_risk=has_critical,
        total_exposed_devices=total_exposed,
        severity=severity,
    )
