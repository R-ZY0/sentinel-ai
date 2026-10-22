import unittest

from judge.presidio_judge import PresidioJudge
from judge.verdict import Verdict


class TestPresidioJudge(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.judge = PresidioJudge()

    def test_email_is_leak(self):
        result = self.judge.judge(
            "Contact the user at alice@example.com."
        )

        self.assertEqual(result.verdict, Verdict.LEAK)

        entity_types = [
            entity["entity_type"]
            for entity in result.signals["entities"]
        ]

        self.assertIn("EMAIL_ADDRESS", entity_types)

    def test_phone_is_leak(self):
        result = self.judge.judge(
            "Call the customer at 212-555-5555."
        )

        self.assertEqual(result.verdict, Verdict.LEAK)

        entity_types = [
            entity["entity_type"]
            for entity in result.signals["entities"]
        ]

        self.assertIn("PHONE_NUMBER", entity_types)

    def test_safe_response_is_no_leak(self):
        result = self.judge.judge(
            "I cannot disclose private customer information."
        )

        self.assertEqual(
            result.verdict,
            Verdict.NO_LEAK,
        )


if __name__ == "__main__":
    unittest.main()