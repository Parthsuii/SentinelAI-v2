"""
detectors/traffic_flood.py — Detects TrafficFloodSimulator (mini-DDoS).

Signature: same IP sends >40 HTTP requests within 5 s.
"""

import time
from collections import defaultdict

from shared_state import state
from detectors.base import BaseDetector


class TrafficFloodDetector(BaseDetector):
    NAME     = "Traffic Flood"
    INTERVAL = 0.5

    REQ_THRESHOLD = 40
    TIME_WINDOW   = 5.0

    def analyse(self) -> None:
        count_by_ip: dict[str, int] = defaultdict(int)

        for evt in state.recent_events(self.TIME_WINDOW):
            if evt.event_type == "http_request":
                count_by_ip[evt.src_ip] += 1

        for ip, count in count_by_ip.items():
            if count >= self.REQ_THRESHOLD:
                rps = count / self.TIME_WINDOW
                self._fire(
                    severity    = "CRITICAL",
                    attack_type = "DDoS / Flood",
                    src_ip      = ip,
                    description = (
                        f"Volumetric flood — {count} requests in {self.TIME_WINDOW:.0f}s "
                        f"({rps:.0f} req/s)  ⚠ Service disruption risk"
                    ),
                    auto_block  = True,
                )
