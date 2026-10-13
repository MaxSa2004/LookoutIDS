# behaviour-based port scan detection logic

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PortScanDetector:
    # detects sources contacting many unique dest. ports
    threshold: int = 20 # 20 ports in last 10seconds = flagged
    window_seconds: float = 10.0

    # each key identifies a src-target pair
    # each value stores (timestamp, dest. port) observations
    observations: dict[tuple[str, str], deque[tuple[float, int]]] = field(
        default_factory=lambda: defaultdict(deque)
    )

    def process_event(
        self, event: dict[str, Any], timestamp: float
    ) -> dict[str, Any] | None:
        # process flow event and return alert when detected
        if event.get("event_type") != "flow":
            return None

        src_ip = event.get("src_ip")
        dest_ip = event.get("dest_ip")
        dest_port = event.get("dest_port")

        if not src_ip or not dest_ip or dest_port is None:
            return None

        try:
            dest_port = int(dest_port)
        except (TypeError, ValueError):
            return None

        if not 1 <= dest_port <= 65535:
            return None

        key = (src_ip, dest_ip)
        observations = self.observations[key]

        # remove observations outside the rolling time window.
        cutoff = timestamp - self.window_seconds

        while observations and observations[0][0] < cutoff:
            observations.popleft()

        # record the current observation.
        observations.append((timestamp, dest_port))

        unique_ports = {port for _, port in observations}

        if len(unique_ports) >= self.threshold:
            return {
                "detection": "possible_port_scan",
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "unique_destination_ports": len(unique_ports),
                "window_seconds": self.window_seconds,
                "severity": "medium",
                "description": (
                    f"{src_ip} contacted {len(unique_ports)} unique "
                    f"destination ports on {dest_ip} within "
                    f"{self.window_seconds} seconds."
                ),
            }

        return None
