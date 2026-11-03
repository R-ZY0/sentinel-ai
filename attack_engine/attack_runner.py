"""Synchronous AttackRunner with bounded retries and duplicate protection."""

import math
from numbers import Real
from queue import Queue, Empty
from threading import Event, Lock, Thread
from typing import Callable, Optional, Tuple, Type

from attack_engine.attack_run import AttackRun


class AttackRunner:
    """Execute AttackRun objects against a synchronous target callable.

    Duplicate protection is scoped to the same AttackRun object and runner.
    Concurrent calls for the same object share one execution result.

    Timeouts use a daemon worker thread. A timed-out target call may continue
    in the background, so timeout failures are never retried automatically.
    """

    def __init__(
        self,
        target: Callable[[str], str],
        timeout_seconds: Optional[float] = None,
        max_retries: int = 1,
        retry_exceptions: Tuple[Type[Exception], ...] = (ConnectionError,),
    ):
        if not callable(target):
            raise TypeError("target must be callable.")

        if timeout_seconds is not None:
            if (
                isinstance(timeout_seconds, bool)
                or not isinstance(timeout_seconds, Real)
            ):
                raise TypeError("timeout_seconds must be a finite positive number.")
            if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
                raise ValueError("timeout_seconds must be a finite positive number.")

        if not isinstance(max_retries, int) or isinstance(max_retries, bool):
            raise TypeError("max_retries must be an integer.")
        if max_retries < 0:
            raise ValueError("max_retries cannot be negative.")

        if not isinstance(retry_exceptions, tuple) or not retry_exceptions:
            raise ValueError("retry_exceptions must be a non-empty tuple.")

        if not all(
            isinstance(item, type) and issubclass(item, Exception)
            for item in retry_exceptions
        ):
            raise TypeError(
                "retry_exceptions must contain Exception subclasses."
            )

        self.target = target
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.retry_exceptions = retry_exceptions

        self._state_lock = Lock()
        self._completed_runs = {}
        self._inflight_runs = {}

    def _invoke_target(self, payload: str) -> str:
        if self.timeout_seconds is None:
            return self.target(payload)

        result_queue = Queue(maxsize=1)

        def invoke():
            try:
                result_queue.put((True, self.target(payload)))
            except BaseException as error:
                result_queue.put((False, error))

        worker = Thread(target=invoke, daemon=True)
        worker.start()

        try:
            succeeded, value = result_queue.get(timeout=self.timeout_seconds)
        except Empty:
            raise TimeoutError(
                f"Target timed out after {self.timeout_seconds} seconds."
            ) from None

        if not succeeded:
            raise value

        return value

    def _execute(self, attack: AttackRun) -> AttackRun:
        last_error = None

        for attempt_number in range(self.max_retries + 1):
            try:
                response = self._invoke_target(attack.payload)

                if not isinstance(response, str):
                    raise TypeError("Target response must be a string.")

                attack.actual_response = response
                attack.status = "completed"
                attack.execution_error = None
                return attack

            except TimeoutError as error:
                last_error = error
                break

            except Exception as error:
                last_error = error

                should_retry = (
                    isinstance(error, self.retry_exceptions)
                    and attempt_number < self.max_retries
                )

                if should_retry:
                    continue
                break

        attack.actual_response = None
        attack.status = "failed"
        attack.execution_error = (
            f"{type(last_error).__name__}: {last_error}"
        )
        attack.evaluation_status = "not_evaluated"
        attack.passed = None
        attack.judge_reason = (
            "Execution failed; the attack response cannot be evaluated."
        )
        return attack

    def run(self, attack: AttackRun) -> AttackRun:
        if not isinstance(attack, AttackRun):
            raise TypeError("attack must be an AttackRun instance.")

        identity = id(attack)

        while True:
            with self._state_lock:
                completed = self._completed_runs.get(identity)
                if completed is not None:
                    return completed

                event = self._inflight_runs.get(identity)
                if event is None:
                    event = Event()
                    self._inflight_runs[identity] = event
                    is_owner = True
                else:
                    is_owner = False

            if not is_owner:
                event.wait()
                # Re-check the cache. If the owner was interrupted, this
                # caller can safely become the next owner.
                continue

            try:
                result = self._execute(attack)
            except BaseException:
                with self._state_lock:
                    self._inflight_runs.pop(identity, None)
                    event.set()
                raise

            with self._state_lock:
                self._completed_runs[identity] = result
                self._inflight_runs.pop(identity, None)
                event.set()

            return result
