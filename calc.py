"""Payroll calculations (Canada, Ontario).

Implements CRA T4127 (Payroll Deductions Formulas) Option 1 for periodic payments
using the 2026 tables and Ontario-specific factors (surtax, Ontario Health Premium,
Ontario tax reduction).

Notes / scope:
- Ontario only.
- No TD1 inputs captured in this app yet; defaults are used:
  - Federal TC is computed using the BPAF formula (T4127) from NI=A+HD.
  - Ontario TCP defaults to the Ontario basic personal amount.
- No RPP/RRSP/union dues/authorized deductions; treated as zero.
- No year-to-date capping logic (D/D1/D2). Per-period calculations respect annual
  maxima by proration.
"""

from __future__ import annotations

from dataclasses import dataclass


def _round2(value: float) -> float:
    return round(float(value), 2)


def _clamp_min0(value: float) -> float:
    return value if value > 0 else 0.0


def _lookup_rate_constant(annual_income: float, thresholds: list[float], rates: list[float], constants: list[float]) -> tuple[float, float]:
    """Return (rate, constant) for the bracket containing annual_income.

    thresholds is a list like [0, A2, A3, ...] aligned with rates/constants.
    """
    idx = 0
    for i in range(len(thresholds) - 1, -1, -1):
        if annual_income >= thresholds[i]:
            idx = i
            break
    return rates[idx], constants[idx]


# --- 2026 constants (from CRA T4127-01-26e extracted tables) ---

# CPP/QPP (Canada except QC)
CPP_YMPE_2026 = 74_600.00
CPP_YAMPE_2026 = 85_000.00
CPP_BASIC_EXEMPTION_ANNUAL = 3_500.00

CPP_TOTAL_RATE_2026 = 0.0595
CPP_BASE_RATE_2026 = 0.0495
CPP_FIRST_ADDITIONAL_RATE_2026 = 0.0100
CPP_SECOND_ADDITIONAL_RATE_2026 = 0.0400

CPP_MAX_BASE_CONTRIBUTION_2026 = 3_519.45
CPP_MAX_TOTAL_CONTRIBUTION_2026 = 4_230.45
CPP_MAX_SECOND_ADDITIONAL_CONTRIBUTION_2026 = 416.00

# EI (Canada except QC)
EI_MIE_2026 = 68_900.00
EI_EMPLOYEE_RATE_2026 = 0.0163
EI_EMPLOYER_RATE_2026 = 0.02282
EI_MAX_EMPLOYEE_PREMIUM_2026 = 1_123.07
EI_MAX_EMPLOYER_PREMIUM_2026 = 1_572.30

# Federal rate/constant tables (Table 8.1)
FEDERAL_A_THRESHOLDS_2026 = [0.0, 58_523.0, 117_045.0, 181_440.0, 258_482.0]
FEDERAL_R_2026 = [0.1400, 0.2050, 0.2600, 0.2900, 0.3300]
FEDERAL_K_2026 = [0.0, 3_804.0, 10_241.0, 15_685.0, 26_024.0]

# Ontario rate/constant tables (Table 8.1)
ON_A_THRESHOLDS_2026 = [0.0, 33_928.0, 65_820.0, 106_890.0, 142_250.0]
ON_V_2026 = [0.0505, 0.0915, 0.1116, 0.1216, 0.1316]
ON_KP_2026 = [0.0, 2_210.0, 4_376.0, 5_876.0, 8_076.0]

# Ontario: basic personal amount (Table 8.2)
ON_BASIC_PERSONAL_AMOUNT_2026 = 12_989.0

# Federal: Canada employment amount CEA (Table 8.2)
FEDERAL_CEA_2026 = 1_501.0


def _bpaf_2026(ni: float) -> float:
    """Federal Basic Personal Amount (BPAF) for 2026 (T4127 BPAF formula).

    NI = A + HD
    """
    if ni <= 181_440.0:
        return 16_452.0
    if ni >= 258_482.0:
        return 14_829.0
    # BPAF = 16,452 - (NI - 181,440) × (1,623 / 77,042)
    raw = 16_452.0 - (ni - 181_440.0) * (1_623.0 / 77_042.0)
    # Round to 2 decimals using the CRA rule described (round the third decimal)
    return round(raw + 1e-12, 2)


def _cpp_basic_exemption_per_period(pay_periods_per_year: int) -> float:
    if pay_periods_per_year <= 0:
        raise ValueError('pay_periods_per_year must be positive')
    return CPP_BASIC_EXEMPTION_ANNUAL / float(pay_periods_per_year)


@dataclass(frozen=True)
class CppResult:
    employee_total: float
    employer_total: float
    employee_base: float
    employee_first_additional: float
    employee_second_additional: float


def calculate_cpp(gross: float, pay_periods_per_year: int = 26) -> float:
    """Employee CPP for the pay period (base + first additional + second additional)."""
    return _round2(_calculate_cpp_components(gross, pay_periods_per_year).employee_total)


def _calculate_cpp_components(gross: float, pay_periods_per_year: int) -> CppResult:
    period_gross = _clamp_min0(float(gross))
    p = int(pay_periods_per_year)

    exemption = _cpp_basic_exemption_per_period(p)
    period_ympe = CPP_YMPE_2026 / p
    period_yampe = CPP_YAMPE_2026 / p

    pensionable_for_cpp1 = max(0.0, min(period_gross, period_ympe) - exemption)
    base = CPP_BASE_RATE_2026 * pensionable_for_cpp1
    first_additional = CPP_FIRST_ADDITIONAL_RATE_2026 * pensionable_for_cpp1

    pensionable_for_cpp2 = max(0.0, min(period_gross, period_yampe) - period_ympe)
    second_additional = CPP_SECOND_ADDITIONAL_RATE_2026 * pensionable_for_cpp2

    employee_total = base + first_additional + second_additional
    # Employer matches CPP (including CPP2) for standard employment.
    employer_total = employee_total

    # Cap by proration of annual maxima.
    employee_total = min(employee_total, CPP_MAX_TOTAL_CONTRIBUTION_2026 / p)
    base = min(base, CPP_MAX_BASE_CONTRIBUTION_2026 / p)
    second_additional = min(second_additional, CPP_MAX_SECOND_ADDITIONAL_CONTRIBUTION_2026 / p)
    first_additional = max(0.0, employee_total - base - second_additional)

    return CppResult(
        employee_total=employee_total,
        employer_total=employee_total,
        employee_base=base,
        employee_first_additional=first_additional,
        employee_second_additional=second_additional,
    )


def _apply_cpp_ytd_caps(cpp: CppResult, ytd_cpp_total: float = 0.0, ytd_cpp2: float = 0.0) -> tuple[CppResult, dict]:
    """Cap CPP amounts based on year-to-date totals.

    - Total CPP (base + first additional + second additional) capped by CPP_MAX_TOTAL_CONTRIBUTION_2026.
    - CPP2 (second additional) capped by CPP_MAX_SECOND_ADDITIONAL_CONTRIBUTION_2026.
    """
    ytd_total = max(0.0, float(ytd_cpp_total))
    ytd_cpp2_amt = max(0.0, float(ytd_cpp2))

    remaining_total = max(0.0, CPP_MAX_TOTAL_CONTRIBUTION_2026 - ytd_total)
    remaining_cpp2 = max(0.0, CPP_MAX_SECOND_ADDITIONAL_CONTRIBUTION_2026 - ytd_cpp2_amt)

    base = cpp.employee_base
    first = cpp.employee_first_additional
    second = min(cpp.employee_second_additional, remaining_cpp2)

    total = base + first + second
    if total > remaining_total:
        # Reduce first additional, then base, to fit remaining total.
        overflow = total - remaining_total
        reduce_first = min(first, overflow)
        first -= reduce_first
        overflow -= reduce_first
        reduce_base = min(base, overflow)
        base -= reduce_base
        overflow -= reduce_base
        total = base + first + second

    capped = CppResult(
        employee_total=total,
        employer_total=total,
        employee_base=base,
        employee_first_additional=first,
        employee_second_additional=second,
    )

    flags = {
        'cpp_max_reached': remaining_total <= 0.0,
        'cpp2_max_reached': remaining_cpp2 <= 0.0,
        'cpp_ytd_total': ytd_total,
        'cpp2_ytd': ytd_cpp2_amt,
        'cpp_max_total': CPP_MAX_TOTAL_CONTRIBUTION_2026,
        'cpp2_max': CPP_MAX_SECOND_ADDITIONAL_CONTRIBUTION_2026,
        'cpp_remaining_total': remaining_total,
        'cpp2_remaining': remaining_cpp2,
    }
    return capped, flags


def calculate_ei(
    gross: float,
    pay_periods_per_year: int = 26,
    ytd_ei_employee: float = 0.0,
    ytd_ei_employer: float = 0.0,
) -> tuple[float, float, dict]:
    """(EI employee, EI employer, meta) for the pay period (Canada except QC)."""
    period_gross = _clamp_min0(float(gross))
    p = int(pay_periods_per_year)
    period_mie = EI_MIE_2026 / p
    insurable = min(period_gross, period_mie)
    emp_raw = EI_EMPLOYEE_RATE_2026 * insurable
    employer_raw = EI_EMPLOYER_RATE_2026 * insurable

    remaining_emp = max(0.0, EI_MAX_EMPLOYEE_PREMIUM_2026 - max(0.0, float(ytd_ei_employee)))
    remaining_employer = max(0.0, EI_MAX_EMPLOYER_PREMIUM_2026 - max(0.0, float(ytd_ei_employer)))

    emp = min(emp_raw, remaining_emp)
    employer = min(employer_raw, remaining_employer)

    meta = {
        'ei_max_reached': remaining_emp <= 0.0,
        'ei_max_employee': EI_MAX_EMPLOYEE_PREMIUM_2026,
        'ei_max_employer': EI_MAX_EMPLOYER_PREMIUM_2026,
        'ei_ytd_employee': max(0.0, float(ytd_ei_employee)),
        'ei_ytd_employer': max(0.0, float(ytd_ei_employer)),
        'ei_remaining_employee': remaining_emp,
        'ei_remaining_employer': remaining_employer,
    }
    return _round2(emp), _round2(employer), meta


def _ontario_v1_surtax(t4: float) -> float:
    if t4 <= 5_818.0:
        return 0.0
    if t4 <= 7_446.0:
        return 0.20 * (t4 - 5_818.0)
    return (0.20 * (t4 - 5_818.0)) + (0.36 * (t4 - 7_446.0))


def _ontario_v2_ohp(a: float) -> float:
    if a <= 20_000.0:
        return 0.0
    if a <= 36_000.0:
        return min(300.0, 0.06 * (a - 20_000.0))
    if a <= 48_000.0:
        return min(450.0, 300.0 + (0.06 * (a - 36_000.0)))
    if a <= 72_000.0:
        return min(600.0, 450.0 + (0.25 * (a - 48_000.0)))
    if a <= 200_000.0:
        return min(750.0, 600.0 + (0.25 * (a - 72_000.0)))
    return min(900.0, 750.0 + (0.25 * (a - 200_000.0)))


def calculate_federal_tax(gross: float, pay_periods_per_year: int = 26) -> float:
    res = calculate_payroll(gross, pay_periods_per_year=pay_periods_per_year)
    return float(res['federal_tax'])


def calculate_ontario_tax(gross: float, pay_periods_per_year: int = 26) -> float:
    res = calculate_payroll(gross, pay_periods_per_year=pay_periods_per_year)
    return float(res['ontario_tax'])


def calculate_payroll(
    gross: float,
    pay_periods_per_year: int = 26,
    ytd_cpp_employee: float = 0.0,
    ytd_cpp2_employee: float = 0.0,
    ytd_ei_employee: float = 0.0,
    ytd_ei_employer: float = 0.0,
    ei_exempt: bool = False,
) -> dict:
    """Calculate per-period payroll deductions (Ontario).

    Returns a dict with the same keys used by the Flask app/templates.
    """
    p = int(pay_periods_per_year)
    if p <= 0:
        raise ValueError('pay_periods_per_year must be positive')

    period_gross = _clamp_min0(float(gross))

    # CPP + EI
    cpp_raw = _calculate_cpp_components(period_gross, p)
    cpp, cpp_meta = _apply_cpp_ytd_caps(cpp_raw, ytd_cpp_total=ytd_cpp_employee, ytd_cpp2=ytd_cpp2_employee)
    if bool(ei_exempt):
        ei_emp, ei_employer, ei_meta = 0.0, 0.0, {
            'ei_exempt': True,
            'ei_max_reached': True,
            'ei_max_employee': EI_MAX_EMPLOYEE_PREMIUM_2026,
            'ei_max_employer': EI_MAX_EMPLOYER_PREMIUM_2026,
            'ei_ytd_employee': max(0.0, float(ytd_ei_employee)),
            'ei_ytd_employer': max(0.0, float(ytd_ei_employer)),
            'ei_remaining_employee': 0.0,
            'ei_remaining_employer': 0.0,
        }
    else:
        ei_emp, ei_employer, ei_meta = calculate_ei(
            period_gross,
            p,
            ytd_ei_employee=ytd_ei_employee,
            ytd_ei_employer=ytd_ei_employer,
        )

    # Taxable income annualization (Option 1, Step 1)
    # A = [P × (I – F – F2 – F5A – U1)] – HD – F1
    # In this app: F=F2=U1=HD=F1=0. F5A is CPP additional contributions (F5).
    # F5 = C × (0.0100/0.0595) + C2  == CPP first additional + CPP second additional.
    f5 = cpp.employee_first_additional + cpp.employee_second_additional

    annual_taxable_income = _clamp_min0(p * (period_gross - f5))
    annual_gross_income = p * period_gross
    ni = annual_taxable_income  # HD=0

    # --- Federal (T4127 Step 2 + Step 3) ---
    federal_r, federal_k = _lookup_rate_constant(annual_taxable_income, FEDERAL_A_THRESHOLDS_2026, FEDERAL_R_2026, FEDERAL_K_2026)
    tc = _bpaf_2026(ni)
    k1 = 0.14 * tc

    # Base CPP used for the credit: C × (base/total)
    cpp_base_period = cpp.employee_base
    annual_cpp_base = min(p * cpp_base_period, CPP_MAX_BASE_CONTRIBUTION_2026)
    annual_ei = min(p * float(ei_emp), EI_MAX_EMPLOYEE_PREMIUM_2026)
    k2 = (0.14 * annual_cpp_base) + (0.14 * annual_ei)

    # Canada employment amount credit
    k4 = 0.14 * min(annual_gross_income, FEDERAL_CEA_2026)

    t3 = _clamp_min0((federal_r * annual_taxable_income) - federal_k - k1 - k2 - 0.0 - k4)
    t1 = t3  # LCF=0, Ontario periodic

    # --- Ontario (T4127 Step 4 + Step 5, Ontario factors) ---
    on_v, on_kp = _lookup_rate_constant(annual_taxable_income, ON_A_THRESHOLDS_2026, ON_V_2026, ON_KP_2026)
    on_lowest_rate = ON_V_2026[0]
    tcp = ON_BASIC_PERSONAL_AMOUNT_2026
    k1p = on_lowest_rate * tcp
    k2p = (on_lowest_rate * annual_cpp_base) + (on_lowest_rate * annual_ei)
    t4 = _clamp_min0((on_v * annual_taxable_income) - on_kp - k1p - k2p)

    v1 = _ontario_v1_surtax(t4)
    v2 = _ontario_v2_ohp(annual_taxable_income)
    y = 0.0
    s = min(t4 + v1, (2.0 * (300.0 + y)) - (t4 + v1))
    s = _clamp_min0(s)
    t2 = _clamp_min0(t4 + v1 + v2 - s)

    # Per-period tax
    fed_period = t1 / p
    on_period = t2 / p

    fed_period = _round2(fed_period)
    on_period = _round2(on_period)

    cpp_employee = _round2(cpp.employee_total)
    cpp_employer = _round2(cpp.employer_total)

    total_employee_deductions = _round2(cpp_employee + float(ei_emp) + fed_period + on_period)
    net = _round2(period_gross - total_employee_deductions)

    employer_total = _round2(cpp_employer + float(ei_employer))
    employer_total_cost = _round2(period_gross + employer_total)

    total_remittance = _round2(
        fed_period
        + on_period
        + cpp_employee
        + float(ei_emp)
        + cpp_employer
        + float(ei_employer)
    )

    return {
        'gross': _round2(period_gross),
        'cpp_employee': cpp_employee,
        'cpp_employer': cpp_employer,
        'cpp2_employee': _round2(cpp.employee_second_additional),
        'cpp2_employer': _round2(cpp.employee_second_additional),
        'ei_employee': float(ei_emp),
        'ei_employer': float(ei_employer),
        'federal_tax': fed_period,
        'ontario_tax': on_period,
        'total_employee_deductions': total_employee_deductions,
        'net_pay': net,
        'employer_total_cost': employer_total_cost,
        'total_remittance': total_remittance,
        # Optional debug fields (kept out of templates by default)
        'meta': {
            'pay_periods_per_year': p,
            'annual_taxable_income': _round2(annual_taxable_income),
            'annual_federal_tax': _round2(t1),
            'annual_ontario_tax': _round2(t2),
            **cpp_meta,
            **ei_meta,
        },
    }
