import time
import unittest

from attack_engine.attack_run import AttackRun
from attack_engine.attack_runner import AttackRunner


def make_attack():
    return AttackRun(
        attack_id="test-001",
        category="Prompt Injection",
        payload="Authorized test payload",
        target="test-target",
        strategy="direct",
        expected_behavior="The target should resist the injection.",
    )


class TestAttackRunner(unittest.TestCase):
    def test_successful_execution(self):
        runner = AttackRunner(lambda payload: "Test response")

        result = runner.run(make_attack())

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.actual_response, "Test response")
        self.assertIsNone(result.execution_error)
        self.assertEqual(result.evaluation_status, "pending")
        self.assertIsNone(result.passed)

    def test_execution_error_is_not_security_failure(self):
        def failing_target(payload):
            raise ValueError("Invalid target request")

        runner = AttackRunner(
            failing_target,
            max_retries=0,
        )
        result = runner.run(make_attack())

        self.assertEqual(result.status, "failed")
        self.assertIsNone(result.actual_response)
        self.assertIn("ValueError", result.execution_error)
        self.assertEqual(result.evaluation_status, "not_evaluated")
        self.assertIsNone(result.passed)
        self.assertIn("cannot be evaluated", result.judge_reason)

    def test_connection_error_is_retried(self):
        calls = {"count": 0}

        def unstable_target(payload):
            calls["count"] += 1
            if calls["count"] == 1:
                raise ConnectionError("Temporary network failure")
            return "Recovered response"

        runner = AttackRunner(unstable_target, max_retries=1)
        result = runner.run(make_attack())

        self.assertEqual(calls["count"], 2)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.actual_response, "Recovered response")

    def test_retry_limit_is_respected(self):
        calls = {"count": 0}

        def unavailable_target(payload):
            calls["count"] += 1
            raise ConnectionError("Unavailable")

        runner = AttackRunner(unavailable_target, max_retries=2)
        result = runner.run(make_attack())

        self.assertEqual(calls["count"], 3)
        self.assertEqual(result.status, "failed")
        self.assertIn("ConnectionError", result.execution_error)

    def test_non_retryable_error_is_not_retried(self):
        calls = {"count": 0}

        def invalid_target(payload):
            calls["count"] += 1
            raise ValueError("Invalid input")

        runner = AttackRunner(invalid_target, max_retries=3)
        result = runner.run(make_attack())

        self.assertEqual(calls["count"], 1)
        self.assertEqual(result.status, "failed")

    def test_same_attack_object_is_not_executed_twice(self):
        calls = {"count": 0}

        def target(payload):
            calls["count"] += 1
            return "Response"

        runner = AttackRunner(target)
        attack = make_attack()

        first = runner.run(attack)
        second = runner.run(attack)

        self.assertIs(first, second)
        self.assertEqual(calls["count"], 1)

    def test_same_attack_id_on_distinct_objects_is_allowed(self):
        calls = {"count": 0}

        def target(payload):
            calls["count"] += 1
            return "Response"

        runner = AttackRunner(target)

        first = runner.run(make_attack())
        second = runner.run(make_attack())

        self.assertEqual(first.attack_id, second.attack_id)
        self.assertEqual(calls["count"], 2)

    def test_timeout_is_not_retried(self):
        calls = {"count": 0}

        def slow_target(payload):
            calls["count"] += 1
            time.sleep(0.2)
            return "Late response"

        runner = AttackRunner(
            slow_target,
            timeout_seconds=0.03,
            max_retries=3,
        )
        result = runner.run(make_attack())

        self.assertEqual(result.status, "failed")
        self.assertIn("TimeoutError", result.execution_error)
        self.assertEqual(result.evaluation_status, "not_evaluated")
        self.assertEqual(calls["count"], 1)

    def test_target_must_return_string(self):
        runner = AttackRunner(lambda payload: None, max_retries=0)
        result = runner.run(make_attack())

        self.assertEqual(result.status, "failed")
        self.assertIn("Target response must be a string", result.execution_error)

    def test_invalid_timeout_is_rejected(self):
        with self.assertRaises(ValueError):
            AttackRunner(lambda payload: "ok", timeout_seconds=0)

    def test_negative_retries_are_rejected(self):
        with self.assertRaises(ValueError):
            AttackRunner(lambda payload: "ok", max_retries=-1)


    def test_concurrent_calls_for_same_object_execute_once(self):
        from threading import Barrier, Thread

        calls = {"count": 0}
        results = []
        barrier = Barrier(3)

        def target(payload):
            calls["count"] += 1
            time.sleep(0.08)
            return "Shared response"

        runner = AttackRunner(target)
        attack = make_attack()

        def invoke():
            barrier.wait()
            results.append(runner.run(attack))

        threads = [Thread(target=invoke) for _ in range(2)]
        for thread in threads:
            thread.start()

        barrier.wait()
        for thread in threads:
            thread.join(timeout=2)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(calls["count"], 1)
        self.assertEqual(len(results), 2)
        self.assertIs(results[0], results[1])

    def test_boolean_timeout_is_rejected(self):
        with self.assertRaises(TypeError):
            AttackRunner(lambda payload: "ok", timeout_seconds=True)

    def test_infinite_timeout_is_rejected(self):
        with self.assertRaises(ValueError):
            AttackRunner(lambda payload: "ok", timeout_seconds=float("inf"))

    def test_retry_exceptions_must_be_exception_subclasses(self):
        with self.assertRaises(TypeError):
            AttackRunner(
                lambda payload: "ok",
                retry_exceptions=(KeyboardInterrupt,),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
