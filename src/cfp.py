from dataclasses import dataclass


@dataclass
class CFPResult:
    bytes: int
    energy_kwh: float
    co2_kg: float


# Energy model constants
# Network energy intensity (J/byte) - Sustainable Web Design Model v4 (2024),
# "networks" segment only (0.059 kWh/GB), since that is the system boundary
# this framework actually measures (network traffic via PCAP)

# https://sustainablewebdesign.org/estimating-digital-emissions/

DEFAULT_ENERGY_PER_BYTE_J = 2.124e-4

# Grid carbon intensity (kgCO2e/kWh) - Spanish electricity mix, CNMC
# 2024 generation data: 283 gCO2eq/kWh

# CNMC, Acuerdo de Etiquetado de la Electricidad

DEFAULT_CO2_PER_KWH = 0.283


def bytes_to_cfp(
    total_bytes: int,
    energy_per_byte_j: float = DEFAULT_ENERGY_PER_BYTE_J,
    co2_per_kwh: float = DEFAULT_CO2_PER_KWH,
) -> CFPResult:
    if total_bytes < 0:
        raise ValueError("total_bytes must be a non-negative number")

    energy_j = total_bytes * energy_per_byte_j
    energy_kwh = energy_j / 3_600_000.0
    co2_kg = energy_kwh * co2_per_kwh

    return CFPResult(bytes=total_bytes, energy_kwh=energy_kwh, co2_kg=co2_kg)


def pretty_print_cfp(label: str, result: CFPResult) -> None:
    print(f"\n--- CFP: {label} ---")
    print(f"Bytes           : {result.bytes}")
    print(f"Energy [kWh]    : {result.energy_kwh:.6e}")
    print(f"CO2 [kgCO2e]    : {result.co2_kg:.6e}")