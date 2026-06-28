from dataclasses import dataclass


@dataclass
class CFPResult:
    bytes: int
    energy_kwh: float
    co2_kg: float


# Constantes del modelo energético — ajustar según el modelo final elegido
# Intensidad energética de la red (J/byte) — valor de referencia bibliográfico
DEFAULT_ENERGY_PER_BYTE_J = 1e-7

# Factor de emisión eléctrico (kgCO2e/kWh) — media UE aproximada
DEFAULT_CO2_PER_KWH = 0.4


def bytes_to_cfp(
    total_bytes: int,
    energy_per_byte_j: float = DEFAULT_ENERGY_PER_BYTE_J,
    co2_per_kwh: float = DEFAULT_CO2_PER_KWH,
) -> CFPResult:
    if total_bytes < 0:
        raise ValueError("total_bytes debe ser un número no negativo")

    energy_j = total_bytes * energy_per_byte_j
    energy_kwh = energy_j / 3_600_000.0
    co2_kg = energy_kwh * co2_per_kwh

    return CFPResult(bytes=total_bytes, energy_kwh=energy_kwh, co2_kg=co2_kg)


def pretty_print_cfp(label: str, result: CFPResult) -> None:
    print(f"\n--- CFP: {label} ---")
    print(f"Bytes           : {result.bytes}")
    print(f"Energía [kWh]   : {result.energy_kwh:.6e}")
    print(f"CO₂ [kgCO₂e]    : {result.co2_kg:.6e}")
