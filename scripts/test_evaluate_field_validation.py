import unittest

from scripts.evaluate_field_validation import evaluate


class FieldValidationEvaluationTest(unittest.TestCase):
    def test_accepts_bounded_result(self):
        result = evaluate(
            "BenchmarkLargeScaleEventPipeline-8  1  1000000 ns/op  2000 B/op  30 allocs/op\n",
            100,
        )
        self.assertTrue(result["passed"])

    def test_rejects_regression(self):
        result = evaluate(
            "BenchmarkLargeScaleEventPipeline-8  1  999999999999 ns/op  2000 B/op  30 allocs/op\n",
            100,
        )
        self.assertFalse(result["passed"])

    def test_requires_expected_benchmark(self):
        with self.assertRaises(ValueError):
            evaluate("PASS\n", 100)


if __name__ == "__main__":
    unittest.main()
