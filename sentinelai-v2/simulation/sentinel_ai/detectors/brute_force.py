"""
detectors/brute_force.py — Detects BruteForceSimulator traffic.

Signature: same IP sends 5+ POST requests within 12 s that look like
auth attempts — matches /login path, BruteForce user-agent, or repeated
POST calls returning auth-failure codes (401, 403, 404).
"""

import time
from collections import defaultdict

from shared_state import state
from detectors.base import BaseDetector


class BruteForceDetector(BaseDetector):
    NAME     = "Brute Force"
    INTERVAL = 1.0

    ATTEMPT_THRESHOLD = 5
    TIME_WINDOW       = 12.0

    def analyse(self) -> None:
        attempts_by_ip: dict[str, int] = defaultdict(int)

        for evt in state.recent_events(self.TIME_WINDOW):
            if evt.event_type != "http_request" or evt.method != "POST":
                continue
            path = evt.path or ""
            ua   = evt.user_agent or ""
            # Detect by: login path, brute-force user-agent, or auth-fail status
            is_login_path = any(p in path for p in ("/login", "/auth", "/signin", "/wp-login"))
            is_bf_agent   = "BruteForce" in ua or "brute" in ua.lower()
            is_auth_fail  = evt.status_code in (401, 403, 404)

            if is_login_path or is_bf_agent or is_auth_fail:
                attempts_by_ip[evt.src_ip] += 1

        for ip, count in attempts_by_ip.items():
            if count >= self.ATTEMPT_THRESHOLD:
                rate = count / self.TIME_WINDOW
                self._fire(
                    severity    = "HIGH",
                    attack_type = "Brute Force",
                    src_ip      = ip,
                    description = (
                        f"Credential stuffing — {count} auth POST attempts "
                        f"in {self.TIME_WINDOW:.0f}s ({rate:.1f} req/s)"
                    ),
                    auto_block  = True,
                )
