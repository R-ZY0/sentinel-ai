import asyncio

from attack_engine.attack_run import AttackRun
from attack_engine.normalized_attack_runner import run_normalized_attack_library


class SyncRunner:
    def __init__(self):
        self.calls = 0

    def run(self, attack):
        self.calls += 1
        attack.actual_response = "A normal test response."
        attack.status = "completed"
        return attack


class AsyncRunner:
    def __init__(self):
        self.calls = 0

    async def run(self, attack):
        self.calls += 1
        attack.actual_response = "A normal test response."
        attack.status = "completed"
        return attack


def test_normalized_library_accepts_synchronous_runner():
    runner = SyncRunner()
    results = asyncio.run(
        run_normalized_attack_library(runner, "test-target")
    )

    assert len(results) == 15
    assert runner.calls == 15
    assert all(isinstance(item, AttackRun) for item in results)
    assert all(item.status == "completed" for item in results)


def test_normalized_library_accepts_asynchronous_runner():
    runner = AsyncRunner()
    results = asyncio.run(
        run_normalized_attack_library(runner, "test-target")
    )

    assert len(results) == 15
    assert runner.calls == 15
    assert all(isinstance(item, AttackRun) for item in results)
    assert all(item.status == "completed" for item in results)


def test_normalized_library_rejects_runner_without_run_method():
    class InvalidRunner:
        pass

    try:
        asyncio.run(
            run_normalized_attack_library(InvalidRunner(), "test-target")
        )
    except TypeError as exc:
        assert "run(attack)" in str(exc)
    else:
        raise AssertionError("Expected TypeError for invalid runner.")


def test_normalized_runner_saves_finding_for_judge_failure(monkeypatch):
    import attack_engine.normalized_attack_runner as normalized_runner
    from attack_engine.finding import Finding

    definition = next(
        item
        for item in normalized_runner.NORMALIZED_ATTACK_LIBRARY
        if item.category == "System Prompt Leakage"
    )
    monkeypatch.setattr(
        normalized_runner,
        "NORMALIZED_ATTACK_LIBRARY",
        [definition],
    )

    class LeakageRunner:
        def run(self, attack):
            attack.status = "completed"
            attack.actual_response = "System prompt: confidential test instruction."
            return attack

    class InMemoryFindingRepository:
        def __init__(self):
            self.items = []

        def save(self, finding):
            self.items.append(finding)

    repository = InMemoryFindingRepository()

    results = asyncio.run(
        normalized_runner.run_normalized_attack_library(
            LeakageRunner(),
            "test-target",
            finding_repository=repository,
        )
    )

    assert len(results) == 1
    assert results[0].evaluation_status == "fail"
    assert results[0].passed is False

    assert len(repository.items) == 1
    finding = repository.items[0]

    assert isinstance(finding, Finding)
    assert finding.attack_id == definition.attack_id
    assert finding.category == "System Prompt Leakage"
    assert finding.severity == "Medium"
    assert finding.evidence == results[0].actual_response
    assert finding.finding_id.startswith("finding-")
