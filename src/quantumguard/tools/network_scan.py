"""
Network Scan Tool
=================

Active network probing capabilities for agents.

Supports:
- Host discovery (ARP/ping sweep)
- Port scanning (TCP SYN, UDP, connect)
- Basic service/version detection (banner grabbing stub)
- Custom packet crafting (via scapy)

Configuration keys (from tools.network_scan):
- enabled: bool (default: True)
- privileged: bool (requires root for raw sockets; default: False)
- timeout_seconds: float (default: 2.0)
- rate_limit_pps: int (packets per second; default: 100)
- dry_run: bool (simulate scan without sending packets; default: True)

Usage:
    scan_results = network_scan_tool.scan_ports(target="192.168.1.100", ports=[22, 80, 443])
"""

from __future__ import annotations

import os
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

from scapy.all import ARP, Ether, ICMP, IP, TCP, UDP, RandShort, sr1, srp, conf

from quantumguard.utils.logging import get_logger

logger = get_logger(__name__)

class NetworkScanTool:
    """
    Tool for network scanning and host/port probing.

    Requires scapy (pip install scapy).
    Many operations need root privileges for raw sockets.
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.enabled: bool = config.get("enabled", True)
        self.privileged: bool = config.get("privileged", False)
        self.timeout: float = config.get("timeout_seconds", 2.0)
        self.rate_limit: int = config.get("rate_limit_pps", 100)
        self.dry_run: bool = config.get("dry_run", True)

        if self.dry_run:
            logger.warning("NetworkScanTool running in DRY-RUN mode – no packets sent")

        if not self.privileged and not self.dry_run:
            logger.warning("Non-privileged mode – limited to connect() scans (no raw packets)")

        # Scapy config tweaks
        conf.verb = 0  # Suppress scapy verbose output

        self._check_privileges()

    def _check_privileges(self) -> None:
        """Verify if we can send raw packets."""
        if self.dry_run:
            return

        try:
            socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except OSError:
            logger.error("Raw socket access denied – run as root or enable privileged mode")
            self.privileged = False

    def scan_hosts(
        self,
        subnet: str = "192.168.1.0/24",
        method: str = "arp",
    ) -> List[Dict[str, Any]]:
        """
        Discover live hosts in a subnet.

        Methods:
        - arp (fast, local network only)
        - icmp (ping sweep)

        Returns:
            List of {"ip": str, "mac": str or None, "alive": bool}
        """
        if not self.enabled:
            return []

        if self.dry_run:
            logger.info("[DRY RUN] Host scan simulated", subnet=subnet, method=method)
            return [{"ip": f"192.168.1.{i}", "mac": None, "alive": True} for i in range(1, 255)]

        results = []

        if method == "arp":
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                timeout=self.timeout,
                verbose=0,
            )
            for sent, recv in ans:
                ip = recv.psrc
                mac = recv.hwsrc
                results.append({"ip": ip, "mac": mac, "alive": True})

        elif method == "icmp":
            for ip in self._generate_ips(subnet):
                pkt = IP(dst=ip) / ICMP()
                resp = sr1(pkt, timeout=self.timeout, verbose=0)
                if resp:
                    results.append({"ip": ip, "mac": None, "alive": True})

        logger.info("Host scan completed", live_hosts=len(results), subnet=subnet)
        return results

    def scan_ports(
        self,
        target: str,
        ports: List[int] = [22, 80, 443, 445, 3389],
        scan_type: str = "syn",
    ) -> Dict[str, Any]:
        """
        Scan target for open ports.

        Scan types:
        - syn (half-open, stealthy – requires root)
        - connect (full TCP handshake – no root needed)

        Returns:
            {
                "target": str,
                "open_ports": list[int],
                "closed_ports": list[int],
                "filtered_ports": list[int],
                "duration_sec": float
            }
        """
        if not self.enabled:
            return {"target": target, "open_ports": [], "status": "disabled"}

        start_time = time.time()

        open_ports = []
        closed_ports = []
        filtered_ports = []

        if self.dry_run:
            logger.info("[DRY RUN] Port scan simulated", target=target, ports=ports)
            return {
                "target": target,
                "open_ports": ports[:2],
                "closed_ports": ports[2:],
                "filtered_ports": [],
                "duration_sec": round(time.time() - start_time, 2),
                "dry_run": True,
            }

        if scan_type == "syn" and not self.privileged:
            logger.warning("SYN scan requires privileges – falling back to connect scan")
            scan_type = "connect"

        for port in ports:
            if scan_type == "syn":
                pkt = IP(dst=target) / TCP(dport=port, flags="S")
                resp = sr1(pkt, timeout=self.timeout, verbose=0)

                if resp is None:
                    filtered_ports.append(port)
                elif resp.haslayer(TCP):
                    if resp[TCP].flags == 0x12:  # SYN-ACK
                        open_ports.append(port)
                        # Send RST to close
                        rst = IP(dst=target) / TCP(dport=port, flags="R")
                        sr1(rst, timeout=0.1, verbose=0)
                    elif resp[TCP].flags == 0x14:  # RST-ACK
                        closed_ports.append(port)
                    else:
                        filtered_ports.append(port)
                else:
                    filtered_ports.append(port)

            elif scan_type == "connect":
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(self.timeout)
                    result = s.connect_ex((target, port))
                    s.close()
                    if result == 0:
                        open_ports.append(port)
                    else:
                        closed_ports.append(port)
                except Exception as e:
                    logger.debug(f"Connect scan error on {target}:{port}", error=str(e))
                    filtered_ports.append(port)

        duration = time.time() - start_time

        result = {
            "target": target,
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "filtered_ports": filtered_ports,
            "duration_sec": round(duration, 2),
            "scan_type": scan_type,
        }

        logger.info("Port scan completed", **result)
        return result

    def _generate_ips(self, subnet: str) -> List[str]:
        """Helper: Generate list of IPs in CIDR subnet (simple, for small ranges)."""
        # MVP: only /24 support
        if "/24" not in subnet:
            raise ValueError("Only /24 subnets supported in MVP")

        base = subnet.split("/24")[0]
        return [f"{base}.{i}" for i in range(1, 255)]

    def banner_grab(
        self,
        target: str,
        port: int,
        timeout: float = 2.0
    ) -> Optional[str]:
        """Attempt to grab service banner/version (connect-based)."""
        if self.dry_run:
            return "[DRY RUN] banner would be grabbed"

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            s.send(b"\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            s.close()
            return banner if banner else None
        except Exception as e:
            logger.debug("Banner grab failed", target=target, port=port, error=str(e))
            return None
