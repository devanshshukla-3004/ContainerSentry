import tempfile
import unittest
from pathlib import Path
from containersentry import analyze_dockerfile, analyze_compose

class DockerfileTests(unittest.TestCase):
    def test_root_and_latest_are_flagged(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "Dockerfile"
            path.write_text("FROM python:latest\nRUN echo hello\n", encoding="utf-8")
            ids = {item["rule_id"] for item in analyze_dockerfile(path)}
            self.assertIn("CTR001", ids)
            self.assertIn("CTR003", ids)

    def test_non_root_user_suppresses_root_finding(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "Dockerfile"
            path.write_text("FROM python:3.12\nUSER 10001\n", encoding="utf-8")
            ids = {item["rule_id"] for item in analyze_dockerfile(path)}
            self.assertNotIn("CTR001", ids)

class ComposeTests(unittest.TestCase):
    def test_privileged_and_host_network_are_flagged(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML is not installed")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "compose.yaml"
            path.write_text("services:\n  app:\n    privileged: true\n    network_mode: host\n", encoding="utf-8")
            ids = {item["rule_id"] for item in analyze_compose(path)}
            self.assertIn("CMP001", ids)
            self.assertIn("CMP004", ids)

if __name__ == "__main__":
    unittest.main()
