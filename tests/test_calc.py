import unittest
from calc import (
    calculate_cpp,
    calculate_ei,
    calculate_federal_tax,
    calculate_ontario_tax,
    calculate_payroll,
)


class CalcTests(unittest.TestCase):
    def test_cpp(self):
        # Bi-weekly default (P=26) with basic exemption proration
        p = 26
        exemption = 3500 / p
        period_ympe = 74600 / p
        pensionable = max(0.0, min(1000.0, period_ympe) - exemption)
        expected = round(pensionable * 0.0595, 2)
        self.assertEqual(calculate_cpp(1000, pay_periods_per_year=p), expected)

    def test_ei(self):
        p = 26
        period_mie = 68900 / p
        insurable = min(1000.0, period_mie)
        emp, employer, meta = calculate_ei(1000, pay_periods_per_year=p)
        self.assertEqual(emp, round(insurable * 0.0163, 2))
        self.assertEqual(employer, round(insurable * 0.02282, 2))
        self.assertIn('ei_max_employee', meta)

    def test_taxes_nonnegative(self):
        # Taxes are computed via CRA annualization and may be 0 at lower incomes,
        # but must never be negative.
        fed = calculate_federal_tax(1500, pay_periods_per_year=26)
        ont = calculate_ontario_tax(1500, pay_periods_per_year=26)
        self.assertIsInstance(fed, float)
        self.assertIsInstance(ont, float)
        self.assertGreaterEqual(fed, 0)
        self.assertGreaterEqual(ont, 0)

    def test_payroll_consistency(self):
        res = calculate_payroll(2000, pay_periods_per_year=26)
        expected_total = round(
            res['cpp_employee'] + res['ei_employee'] + res['federal_tax'] + res['ontario_tax'], 2
        )
        self.assertEqual(res['total_employee_deductions'], expected_total)
        self.assertEqual(res['net_pay'], round(res['gross'] - res['total_employee_deductions'], 2))
        # Remittance should include withheld amounts + employer portions.
        self.assertEqual(
            res['total_remittance'],
            round(
                res['federal_tax']
                + res['ontario_tax']
                + res['cpp_employee']
                + res['ei_employee']
                + res['cpp_employer']
                + res['ei_employer'],
                2,
            ),
        )


if __name__ == '__main__':
    unittest.main()
