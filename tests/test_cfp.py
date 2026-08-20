# Tests for the bytes -> energy -> CO2 conversion model (src/cfp.py).
# These pin down the equations from the thesis (Chapter 3) so an accidental
# change to the formula, not just the constants, would fail loudly here.
import pytest

from cfp import bytes_to_cfp, DEFAULT_ENERGY_PER_BYTE_J, DEFAULT_CO2_PER_KWH


def test_zero_bytes_gives_zero_everything():
    result = bytes_to_cfp(0)
    assert result.bytes == 0
    assert result.energy_kwh == 0.0
    assert result.co2_kg == 0.0


def test_negative_bytes_is_rejected():
    with pytest.raises(ValueError):
        bytes_to_cfp(-1)


def test_matches_the_thesis_equations_with_default_constants():
    total_bytes = 1_000_000
    result = bytes_to_cfp(total_bytes)

    expected_energy_j = total_bytes * DEFAULT_ENERGY_PER_BYTE_J
    expected_energy_kwh = expected_energy_j / 3_600_000.0
    expected_co2_kg = expected_energy_kwh * DEFAULT_CO2_PER_KWH

    assert result.energy_kwh == pytest.approx(expected_energy_kwh)
    assert result.co2_kg == pytest.approx(expected_co2_kg)


def test_energy_and_co2_scale_linearly_with_bytes():
    small = bytes_to_cfp(1000)
    large = bytes_to_cfp(10_000)

    assert large.energy_kwh == pytest.approx(small.energy_kwh * 10)
    assert large.co2_kg == pytest.approx(small.co2_kg * 10)


def test_custom_constants_override_the_defaults():
    # A different grid / energy-intensity assumption should change the
    # result without needing to touch bytes_to_cfp itself.
    result = bytes_to_cfp(1_000_000, energy_per_byte_j=1.0, co2_per_kwh=1.0)
    expected_energy_kwh = 1_000_000 / 3_600_000.0
    assert result.energy_kwh == pytest.approx(expected_energy_kwh)
    assert result.co2_kg == pytest.approx(expected_energy_kwh)
