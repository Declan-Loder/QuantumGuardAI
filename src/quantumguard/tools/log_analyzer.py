"""
Log Analyzer Tool
=================

Parses and normalizes security/network logs into structured events.

Supported formats (extensible):
- Zeek conn.log (tab-separated)
- Suricata EVE JSON
- Generic CSV/JSON logs with IP fields
- Windows Event Logs / Sysmon (JSON/XML stub)

Extracted fields per event:
- timestamp
- src_ip, dst_ip
- src_port, dst_port
- protocol
- bytes_in, bytes_out
- duration
- flags / status
- anomaly_score / suspicious (heuristic or from log)
- raw_line (fallback)

Output: List[Dict] — each dict is one normalized event

Configuration keys (from tools.log_analyzer):
- parsers: list of enabled parsers ["zeek", "suricata", "generic"]
- anomaly_keywords: list of strings that flag suspicious logs
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from quantumguard.utils.logging import get_logger

logger = get_logger(__name__)

class LogAnalyzer:
    """
    Tool for parsing logs and extracting structured security events.
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.parsers: List[str] = config.get("parsers", ["zeek", "suricata", "generic"])
        self.anomaly_keywords: List[str] = config.get(
            "anomaly_keywords",
            ["alert", "suspicious", "malware", "attack", "c2", "exploit", "scan"]
        )
        self.default_timestamp_format = "%Y-%m-%dT%H:%M:%S.%f%z"  # ISO with micros & tz

        logger.info(
            "LogAnalyzer initialized",
            enabled_parsers=self.parsers,
            anomaly_keywords_count=len(self.anomaly_keywords)
        )

    def parse_log_file(
        self,
        path: Union[str, Path],
        format_hint: Optional[str] = None,
        max_lines: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Parse an entire log file and return list of normalized events.

        Tries parsers in order until one succeeds without fatal errors.
        """
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f"Log file not found: {path}")

        content = path.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()

        if max_lines:
            lines = lines[:max_lines]

        # Try format-specific parsers first
        for parser_name in self.parsers:
            try:
                if parser_name == "zeek":
                    return self._parse_zeek_conn(lines)
                elif parser_name == "suricata":
                    return self._parse_suricata_eve(lines)
                elif parser_name == "generic":
                    return self._parse_generic_csv_or_json(lines)
            except Exception as e:
                logger.debug(f"Parser {parser_name} failed on {path}", error=str(e))

        logger.warning(f"All parsers failed on {path} – using raw fallback")
        return [{"raw_line": line, "parse_error": "no_matching_parser"} for line in lines]

    def _parse_zeek_conn(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse Zeek conn.log (tab-separated, #header)."""
        events = []

        # Skip header/comments
        reader = csv.reader(
            (line for line in lines if line.strip() and not line.startswith("#")),
            delimiter="\t"
        )

        for row in reader:
            if len(row) < 8:
                continue

            try:
                ts = float(row[0])
                timestamp = datetime.fromtimestamp(ts).isoformat()

                event = {
                    "timestamp": timestamp,
                    "src_ip": row[2],
                    "dst_ip": row[4],
                    "src_port": int(row[3]) if row[3] != "-" else None,
                    "dst_port": int(row[5]) if row[5] != "-" else None,
                    "protocol": row[6],
                    "duration": float(row[8]) if row[8] != "-" else 0.0,
                    "bytes_in": int(row[10]) if row[10] != "-" else 0,
                    "bytes_out": int(row[9]) if row[9] != "-" else 0,
                    "conn_state": row[11],
                    "anomaly": any(kw.lower() in " ".join(row).lower() for kw in self.anomaly_keywords),
                }
                events.append(event)
            except (ValueError, IndexError) as e:
                logger.debug("Zeek line parse error", error=str(e), line=row)

        return events

    def _parse_suricata_eve(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse Suricata EVE JSON (one event per line)."""
        events = []

        for line in lines:
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                if "event_type" not in data:
                    continue

                event = {
                    "timestamp": data.get("timestamp"),
                    "src_ip": data.get("src_ip"),
                    "dst_ip": data.get("dest_ip"),
                    "src_port": data.get("src_port"),
                    "dst_port": data.get("dest_port"),
                    "protocol": data.get("proto", "unknown"),
                    "bytes_in": data.get("flow", {}).get("bytes_toserver", 0),
                    "bytes_out": data.get("flow", {}).get("bytes_toclient", 0),
                    "anomaly": data.get("event_type") == "alert" or any(
                        kw in json.dumps(data).lower() for kw in self.anomaly_keywords
                    ),
                    "alert_signature": data.get("alert", {}).get("signature", None),
                }
                events.append(event)
            except json.JSONDecodeError:
                logger.debug("Suricata JSON decode error", line=line[:100])

        return events

    def _parse_generic_csv_or_json(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Fallback parser for generic CSV/JSON logs."""
        events = []

        # Try JSON first (one object per line)
        for line in lines:
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                events.append(self._normalize_event(data))
            except json.JSONDecodeError:
                # Try CSV
                try:
                    reader = csv.DictReader(StringIO("\n".join(lines)))
                    for row in reader:
                        events.append(self._normalize_event(row))
                    break  # If CSV works, stop per-line JSON attempts
                except Exception:
                    pass

        return events

    def _normalize_event(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Standardize field names from any log format."""
        normalized = {
            "timestamp": raw.get("timestamp") or raw.get("ts") or datetime.utcnow().isoformat(),
            "src_ip": raw.get("src_ip") or raw.get("source_ip") or raw.get("src"),
            "dst_ip": raw.get("dst_ip") or raw.get("dest_ip") or raw.get("dest"),
            "src_port": raw.get("src_port") or raw.get("sport"),
            "dst_port": raw.get("dst_port") or raw.get("dport"),
            "protocol": raw.get("proto") or raw.get("protocol") or "unknown",
            "bytes_in": raw.get("bytes_in") or raw.get("rx_bytes") or 0,
            "bytes_out": raw.get("bytes_out") or raw.get("tx_bytes") or 0,
            "duration": raw.get("duration") or 0.0,
            "anomaly": any(kw in json.dumps(raw).lower() for kw in self.anomaly_keywords),
            "raw": raw,
        }
        return normalized

    def extract_graph_features(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Post-process parsed events into graph-ready features.

        Returns list of edge-like dicts for graph builder.
        """
        edges = []

        for event in events:
            if not event.get("src_ip") or not event.get("dst_ip"):
                continue

            edge = {
                "src_ip": event["src_ip"],
                "dst_ip": event["dst_ip"],
                "protocol": event.get("protocol"),
                "bytes": event.get("bytes_in", 0) + event.get("bytes_out", 0),
                "duration": event.get("duration", 0.0),
                "count": 1,
                "anomaly": event.get("anomaly", False),
            }
            edges.append(edge)

        logger.debug("Extracted graph features", edge_count=len(edges))
        return edges
