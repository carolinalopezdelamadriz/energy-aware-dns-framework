"""
Simple energy and carbon-footprint model for network traffic.

Todas las constantes están separadas para que puedas ajustarlas
fácilmente según las fuentes que utilices en la memoria del TFG.
"""

from dataclasses import dataclass


@dataclass
class CFPResult:
    bytes: int
    energy_kwh: float
    co2_kg: float


# --- Modelo configurable ----------------------------------------------------

# Energía por byte transferido (J/byte).
# Sustituye este valor por el que justifiques en el Estado del Arte.
DEFAULT_ENERGY_PER_BYTE_J = 1e-7  # EJEMPLO: 0.1 µJ por byte

# Factor de emisión medio de la electricidad (kgCO2e/kWh).
# De nuevo, deberías ajustarlo a tu referencia (por país / mix energético).
DEFAULT_CO2_PER_KWH = 0.4  # EJEMPLO: 400 gCO2e/kWh


def bytes_to_cfp(
    total_bytes: int,
    energy_per_byte_j: float = DEFAULT_ENERGY_PER_BYTE_J,
    co2_per_kwh: float = DEFAULT_CO2_PER_KWH,
) -> CFPResult:
    """
    Convierte un volumen de datos (bytes) en energía y huella de carbono.

    Fórmulas:
      E[J]   = bytes * energy_per_byte_j
      E[kWh] = E[J] / 3.6e6
      CO2[kg] = E[kWh] * co2_per_kwh
    """
    if total_bytes < 0:
        raise ValueError("total_bytes debe ser un número no negativo")

    energy_j = total_bytes * energy_per_byte_j
    energy_kwh = energy_j / 3_600_000.0
    co2_kg = energy_kwh * co2_per_kwh

    return CFPResult(bytes=total_bytes, energy_kwh=energy_kwh, co2_kg=co2_kg)


def pretty_print_cfp(label: str, result: CFPResult) -> None:
    """
    Imprime en consola un resumen legible del resultado CFP para un experimento.
    """
    print(f"\n--- CFP for {label} ---")
    print(f"Bytes           : {result.bytes}")
    print(f"Energía [kWh]   : {result.energy_kwh:.6e}")
    print(f"CO₂ [kgCO₂e]    : {result.co2_kg:.6e}")


