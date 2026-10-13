import unittest

from src.lookoutids.detectors.port_scan import PortScanDetector


class TestPortScanDetector(unittest.TestCase):
    def test_detects_many_unique_ports(self):
        detector = PortScanDetector(
            threshold=3,
            window_seconds=10,
        )

        self.assertIsNone(
            detector.process_event(
                {
                    "event_type": "flow",
                    "src_ip": "192.168.1.50",
                    "dest_ip": "192.168.1.70",
                    "dest_port": 22,
                },
                timestamp=1.0,
            )
        )

        detector.process_event(
            {
                "event_type": "flow",
                "src_ip": "192.168.1.50",
                "dest_ip": "192.168.1.70",
                "dest_port": 80,
            },
            timestamp=2.0,
        )

        alert = detector.process_event(
            {
                "event_type": "flow",
                "src_ip": "192.168.1.50",
                "dest_ip": "192.168.1.70",
                "dest_port": 443,
            },
            timestamp=3.0,
        )

        self.assertIsNotNone(alert)
        self.assertEqual(alert["detection"], "possible_port_scan")
        self.assertEqual(alert["unique_destination_ports"], 3)

    def test_repeated_port_does_not_increase_unique_count(self):
        detector = PortScanDetector(
            threshold=3,
            window_seconds=10,
        )

        for timestamp in (1.0, 2.0, 3.0):
            alert = detector.process_event(
                {
                    "event_type": "flow",
                    "src_ip": "192.168.1.50",
                    "dest_ip": "192.168.1.70",
                    "dest_port": 80,
                },
                timestamp=timestamp,
            )

        self.assertIsNone(alert)

    def test_old_observations_expire(self):
        detector = PortScanDetector(
            threshold=3,
            window_seconds=5,
        )

        for timestamp, port in (
            (1.0, 22),
            (2.0, 80),
            (3.0, 443),
        ):
            detector.process_event(
                {
                    "event_type": "flow",
                    "src_ip": "192.168.1.50",
                    "dest_ip": "192.168.1.70",
                    "dest_port": port,
                },
                timestamp=timestamp,
            )

        # The earlier observations are now outside the window.
        alert = detector.process_event(
            {
                "event_type": "flow",
                "src_ip": "192.168.1.50",
                "dest_ip": "192.168.1.70",
                "dest_port": 8080,
            },
            timestamp=10.0,
        )

        self.assertIsNone(alert)


if __name__ == "__main__":
    unittest.main()
