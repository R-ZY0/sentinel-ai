"""Run the contributor's function-style compatibility checks in our unittest gate."""
from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from attack_engine import test_normalized_runner_compatibility as delivery


class NormalizedHandoffTests(unittest.TestCase):
    def test_sync_runner(self):
        delivery.test_normalized_library_accepts_synchronous_runner()

    def test_async_runner(self):
        delivery.test_normalized_library_accepts_asynchronous_runner()

    def test_invalid_runner(self):
        delivery.test_normalized_library_rejects_runner_without_run_method()

    def test_heuristic_potential_finding(self):
        with ExitStack() as stack:
            monkeypatch = SimpleNamespace(setattr=lambda obj, name, value: stack.enter_context(patch.object(obj, name, value)))
            delivery.test_normalized_runner_saves_finding_for_judge_failure(monkeypatch)
