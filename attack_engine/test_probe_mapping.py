"""Validate the provisional Week 2 probe mapping."""

import json
import unittest
from pathlib import Path
from importlib.metadata import version

from attack_engine.attack_library import ATTACK_LIBRARY


MAPPING_PATH = (
    Path(__file__).resolve().parent
    / "examples"
    / "probe_mapping.json"
)

CATEGORIES = {
    "Prompt Injection",
    "System Prompt Leakage",
    "Data Leakage",
    "RAG Leakage",
    "Jailbreak",
}

VALID_STATUSES = {
    "live_smoke_tested",
    "static_discovery_only",
    "candidate_requires_rag_target",
}


class TestProbeMapping(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.mapping = json.loads(
            MAPPING_PATH.read_text(encoding="utf-8")
        )
        cls.entries = cls.mapping["mappings"]

    def test_five_unique_categories(self):
        categories = [x["category"] for x in self.entries]
        self.assertEqual(len(categories), 5)
        self.assertEqual(set(categories), CATEGORIES)

    def test_all_entries_have_required_fields(self):
        for entry in self.entries:
            with self.subTest(category=entry["category"]):
                for field in ("category", "tool", "reference", "status", "notes"):
                    self.assertIsInstance(entry[field], str)
                    self.assertTrue(entry[field].strip())

                self.assertIn(entry["status"], VALID_STATUSES)
                self.assertIn(entry["tool"].lower(), ("garak", "pyrit"))

    def test_library_categories_match(self):
        library_categories = {
            case.category for case in ATTACK_LIBRARY
        }
        self.assertEqual(library_categories, CATEGORIES)

    def test_documented_versions_match_requirements(self):
        versions = self.mapping["tool_versions"]
        root = Path(__file__).resolve().parent

        for tool in ("garak", "pyrit"):
            with self.subTest(tool=tool):
                req = (root / f"requirements-{tool}.txt").read_text(
                    encoding="utf-8-sig"
                )
                self.assertIn(
                    f"{tool}=={versions[tool]}",
                    req.splitlines(),
                )

    def test_installed_versions_when_explicitly_configured(self):
        import os
        import subprocess

        versions = self.mapping["tool_versions"]
        tools = (
            ("garak", "GARAK_PYTHON"),
            ("pyrit", "PYRIT_PYTHON"),
        )

        configured = [os.environ.get(variable) for _, variable in tools]

        if not any(configured):
            self.skipTest(
                "Tool environment test requires GARAK_PYTHON and PYRIT_PYTHON"
            )

        for tool, variable in tools:
            with self.subTest(tool=tool):
                executable = os.environ.get(variable)
                self.assertTrue(
                    executable and os.path.isfile(executable),
                    f"{variable} must point to a valid Python executable",
                )
                actual = subprocess.check_output(
                    [
                        executable,
                        "-c",
                        "from importlib.metadata import version; "
                        f"print(version({tool!r}))",
                    ],
                    text=True,
                    timeout=30,
                ).strip()
                self.assertEqual(actual, versions[tool])

    def test_live_status_only_for_verified_smoke_cases(self):
        verified = {
            ("Prompt Injection", "PyRIT", "PI-001"),
            ("Jailbreak", "garak", "dan.Dan_11_0"),
        }
        reported = {
            (x["category"], x["tool"], x["reference"])
            for x in self.entries
            if x["status"] == "live_smoke_tested"
        }
        self.assertEqual(reported, verified)

    def test_rag_remains_unverified(self):
        rag = next(
            x for x in self.entries
            if x["category"] == "RAG Leakage"
        )
        self.assertEqual(
            rag["status"],
            "candidate_requires_rag_target",
        )

    def test_limitations_documented(self):
        limitations = self.mapping["limitations"]
        self.assertGreaterEqual(len(limitations), 3)
        self.assertTrue(all(isinstance(x, str) and x.strip() for x in limitations))


if __name__ == "__main__":
    unittest.main()
